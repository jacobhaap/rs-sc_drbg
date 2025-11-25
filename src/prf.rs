use aes::{
    Aes128, Aes192, Aes256,
    cipher::{KeyIvInit, StreamCipher},
};
use ctr::Ctr128BE;
use digest::{
    Digest, ExtendableOutput, HashMarker, OutputSizeUser, Update, XofReader,
    block_buffer::Eager,
    core_api::{
        BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
    },
    typenum::{IsLess, Le, NonZero, U256},
};
use hkdf::{self, Hkdf};
use hmac::{Hmac, Mac};
use sha3::Shake256;
use std::{cmp::PartialEq, marker::PhantomData, ops::Rem};

const D_1: u8 = 0x01;
const D_2: u8 = 0x02;
const D_3: u8 = 0x03;
const D_4: u8 = 0x04;
const D_5: u8 = 0x05;
const D_6: u8 = 0x06;
const D_7: u8 = 0x07;

pub trait UnsignedInt:
    Copy + From<u32> + Rem<Output = Self> + PartialEq
{
    const SIZE: usize;
    fn wrapping_add(self, other: Self) -> Self;
    fn wrapping_sub(self, other: Self) -> Self;
    fn as_usize(self) -> usize;
    fn from_usize(v: usize) -> Self;
}

impl UnsignedInt for u32 {
    const SIZE: usize = 4;
    fn wrapping_add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }
    fn wrapping_sub(self, other: Self) -> Self {
        self.wrapping_sub(other)
    }
    fn as_usize(self) -> usize {
        self as usize
    }
    fn from_usize(v: usize) -> Self {
        v as u32
    }
}

impl UnsignedInt for u64 {
    const SIZE: usize = 8;
    fn wrapping_add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }
    fn wrapping_sub(self, other: Self) -> Self {
        self.wrapping_sub(other)
    }
    fn as_usize(self) -> usize {
        self as usize
    }
    fn from_usize(v: usize) -> Self {
        v as u64
    }
}

pub struct Prf<D> {
    _digest: PhantomData<D>,
}

impl<D> Prf<D>
where
    D: Digest + CoreProxy + OutputSizeUser,
    D::Core: Sync
        + HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone
        + BlockSizeUser,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    pub fn bind<U>(
        arr: &[Vec<u8>],
        key: &[u8],
        encode: fn(U) -> Vec<u8>,
    ) -> Vec<Vec<u8>>
    where
        U: UnsignedInt,
    {
        // Initialize bound elements
        let mut bound = Vec::with_capacity(arr.len());
        // Bind each element to its position, length, and content
        for i in 0..arr.len() {
            // Initialize MAC using key
            let mut mac = Hmac::<D>::new_from_slice(&key)
                .expect("HMAC can take key of any size");
            // Absorb domain byte
            Mac::update(&mut mac, &[D_1]);
            // Absorb element position, length, and contents
            Mac::update(&mut mac, &encode(U::from_usize(i)));
            Mac::update(&mut mac, &encode(U::from_usize(arr[i].len())));
            Mac::update(&mut mac, &arr[i]);
            // Add binding to bound elements
            bound.push(mac.finalize().into_bytes().to_vec());
        }
        bound
    }
    pub fn mix<U>(
        arr: &[Vec<u8>],
        prk: &[u8],
        rounds: usize,
        encode: fn(U) -> Vec<u8>,
    ) -> Vec<Vec<u8>>
    where
        U: UnsignedInt,
    {
        // Initialize mixed elements from array
        let mut mixed = arr.to_vec();
        let output_len = <D as OutputSizeUser>::output_size();
        // Apply rounds of mixing
        for i in 0..rounds {
            // Create info from round number, expand PRK into mixing key
            let info = format!("ROUND{}", i);
            let info_bytes = info.as_bytes();
            let hk = hkdf::Hkdf::<D>::from_prk(prk)
                .expect("PRK should be large enough");
            let mut key = vec![0u8; output_len];
            hk.expand(&info_bytes, &mut key)
                .expect("okm length should match the hash digest length");
            // Create tweak from mixing key and round
            let mut tweak_hasher = D::new();
            tweak_hasher.update(&key);
            tweak_hasher.update(&encode(U::from_usize(i)));
            let tweak = tweak_hasher.finalize().to_vec();
            // Create sponge, absorb tweak
            let mut sponge = Shake256::default();
            sponge.update(&tweak);
            // Absorb all elements and positions
            for j in 0..mixed.len() {
                sponge.update(&mixed[j]);
                sponge.update(&encode(U::from_usize(j)));
            }
            // Squeeze outputs from sponge, use temporary buffer
            let mut sponge_reader = sponge.finalize_xof();
            let mut tmp = Vec::with_capacity(mixed.len());
            for j in 0..mixed.len() {
                let mut element = vec![0u8; mixed[j].len()];
                sponge_reader.read(&mut element);
                tmp.push(element);
            }
            mixed = tmp;
        }
        mixed
    }
    pub fn next<U>(
        arr: &[Vec<u8>],
        prk: &[u8],
        subset: usize,
        counter: U,
        encode: fn(U) -> Vec<u8>,
        decode: fn(&[u8]) -> U,
        dst: &mut [u8],
    ) where
        U: UnsignedInt,
    {
        // Create commitment
        let commit = Self::commitment::<U>(arr, encode);
        // Expand PRK into keys for each step
        let output_len = <D as OutputSizeUser>::output_size();
        let hk = Hkdf::<D>::from_prk(prk).expect("PRK should be large enough");
        let mut key_1 = vec![0u8; output_len];
        hk.expand(b"SUBKEYS", &mut key_1)
            .expect("okm length should match the hash digest length");
        let mut key_2 = vec![0u8; output_len];
        hk.expand(b"INDICES", &mut key_2)
            .expect("okm length should match the hash digest length");
        let mut key_3 = vec![0u8; output_len];
        hk.expand(b"PRF", &mut key_3)
            .expect("okm length should match the hash digest length");
        // Create subkeys and select indices
        let k_s = Self::subkeys::<U>(arr, &key_1, &commit, encode);
        let k_i = Self::indices::<U>(
            &key_2,
            &commit,
            U::from_usize(arr.len()),
            U::from_usize(subset),
            counter,
            encode,
            decode,
        );
        // Bind each subkey to the commitment and counter, XOR into accumulator
        let acc = Self::combine::<U>(&k_s, &k_i, &commit, counter, encode);
        // Derive PRF key and nonce
        let (prf_key, nonce) =
            Self::derive_key_nonce::<U>(&key_3, &commit, counter, &acc, encode);
        // Fill the destination buffer with zero bytes
        dst.fill(0);
        // Encrypt zero bytes using AES-CTR, change variant based on key size
        match prf_key.len() {
            16 => {
                let mut aes_key = [0u8; 16];
                aes_key.copy_from_slice(&prf_key);
                let mut cipher =
                    Ctr128BE::<Aes128>::new(&aes_key.into(), &nonce.into());
                cipher.apply_keystream(dst);
            }
            24 => {
                let mut aes_key = [0u8; 24];
                aes_key.copy_from_slice(&prf_key);
                let mut cipher =
                    Ctr128BE::<Aes192>::new(&aes_key.into(), &nonce.into());
                cipher.apply_keystream(dst);
            }
            32 => {
                let mut aes_key = [0u8; 32];
                aes_key.copy_from_slice(&prf_key);
                let mut cipher =
                    Ctr128BE::<Aes256>::new(&aes_key.into(), &nonce.into());
                cipher.apply_keystream(dst);
            }
            _ => panic!("key length {} is invalid for AES-CTR", prf_key.len()),
        }
    }
    fn commitment<U>(arr: &[Vec<u8>], encode: fn(U) -> Vec<u8>) -> Vec<u8>
    where
        U: UnsignedInt,
    {
        // Initialize hasher
        let mut hasher = D::new();
        // Absorb domain byte
        hasher.update(&[D_2]);
        // Encode and absorb element count
        hasher.update(&encode(U::from_usize(arr.len())));
        // For each element, commit to its position, length, and content
        for i in 0..arr.len() {
            // Absorb element position, length, and contents
            hasher.update(&encode(U::from_usize(i)));
            hasher.update(&encode(U::from_usize(arr[i].len())));
            hasher.update(&arr[i]);
        }
        // Return commitment
        hasher.finalize().to_vec()
    }
    fn subkeys<U>(
        arr: &[Vec<u8>],
        key: &[u8],
        commit: &[u8],
        encode: fn(U) -> Vec<u8>,
    ) -> Vec<Vec<u8>>
    where
        U: UnsignedInt,
    {
        // Allocate subkeys buffer
        let mut k_s = Vec::with_capacity(arr.len());
        // Derive a subkey for each element
        for i in 0..arr.len() {
            // Initialize MAC using key
            let mut mac = Hmac::<D>::new_from_slice(&key)
                .expect("HMAC can take key of any size");
            // Absorb domain byte, element properties, and commitment
            Mac::update(&mut mac, &[D_3]);
            Mac::update(&mut mac, &encode(U::from_usize(i)));
            Mac::update(&mut mac, &encode(U::from_usize(arr[i].len())));
            Mac::update(&mut mac, &arr[i]);
            Mac::update(&mut mac, commit);
            // Use MAC digest as the subkey for the current element
            let subkey: Vec<u8> = mac.finalize().into_bytes().to_vec();
            k_s.push(subkey);
        }
        k_s
    }
    fn indices<U>(
        key: &[u8],
        commit: &[u8],
        n: U,
        s: U,
        counter: U,
        encode: fn(U) -> Vec<u8>,
        decode: fn(&[u8]) -> U,
    ) -> Vec<U>
    where
        U: UnsignedInt,
    {
        // Initialize indices array [0..n-1]
        let n_usize = n.as_usize();
        let s_usize = s.as_usize();
        let mut k_i: Vec<U> = (0..n_usize).map(|i| U::from_usize(i)).collect();
        // Encode external counter
        let ctr_bytes_ext = encode(counter);
        // Initialize internal counter
        let mut ctr: U = U::from(0);
        // Byte source from PRF closure
        // Produces the next 32 bytes of PRF output on each call
        let mut next = || {
            // Encode internal counter
            let ctr_bytes_in = encode(ctr);
            ctr = ctr.wrapping_add(U::from(1));
            // Initialize MAC using key
            let mut mac = Hmac::<D>::new_from_slice(key)
                .expect("HMAC can take key of any size");
            // Absorb domain byte, commitment and counters
            Mac::update(&mut mac, &[D_4]);
            Mac::update(&mut mac, commit);
            Mac::update(&mut mac, &ctr_bytes_ext);
            Mac::update(&mut mac, &ctr_bytes_in);
            // Return MAC digest as PRF bytes
            let bytes: Vec<u8> = mac.finalize().into_bytes().to_vec();
            bytes
        };
        // Buffer of PRF bytes
        let mut p: Vec<u8> = Vec::new();
        // Iterate until reaching subset size
        for i in 0..s_usize {
            let i_c = U::from_usize(i);
            // Limit range to unsigned integer limit
            let range = n.wrapping_sub(i_c);
            // Calculate remainder for rejection sampling
            let rem = U::from(0).wrapping_sub(range) % range;
            // Draw v with rejection sampling
            let mut v: U;
            if rem == U::from(0) {
                // Range divides integer limit evenly, no rejection needed
                // Verify enough bytes available
                if p.len() < U::SIZE {
                    p = next();
                }
                // Read integer from p
                v = decode(&p[0..U::SIZE]);
                // Consume bytes
                p.drain(0..U::SIZE);
            } else {
                // Apply rejection sampling to avoid modulo bias
                let limit = U::from(0).wrapping_sub(rem);
                loop {
                    // Verify enough bytes available
                    if p.len() < U::SIZE {
                        p = next();
                    }
                    // Read integer from p
                    v = decode(&p[0..U::SIZE]);
                    // Consume bytes
                    p.drain(0..U::SIZE);
                    // Only accept v in range [0, limit)
                    if v.as_usize() < limit.as_usize() {
                        break;
                    }
                    // If v is out of range, draw another value
                }
            }
            // Map v into the indices array by modular reduction
            // of the remaining range size
            let j_usize = i + (v % range).as_usize();
            // Swap indices i and j
            k_i.swap(i, j_usize);
        }
        k_i[0..s_usize].to_vec()
    }
    fn combine<U>(
        subkeys: &Vec<Vec<u8>>,
        indices: &Vec<U>,
        commit: &[u8],
        counter: U,
        encode: fn(U) -> Vec<u8>,
    ) -> Vec<u8>
    where
        U: UnsignedInt,
    {
        // Set output length based on hashing algorithm
        let output_len = <D as OutputSizeUser>::output_size();
        // Encode external counter
        let ctr_bytes = encode(counter);
        // Allocate XOR accumulator
        let mut acc = vec![0u8; output_len];
        // For all selected indices
        for i in indices.iter() {
            // Initialize MAC using subkey
            let mut mac = Hmac::<D>::new_from_slice(&subkeys[i.as_usize()])
                .expect("HMAC can take key of any size");
            // Absorb commitment and counter
            Mac::update(&mut mac, &[D_5]);
            Mac::update(&mut mac, commit);
            Mac::update(&mut mac, &ctr_bytes);
            let y = mac.finalize().into_bytes().to_vec();
            // acc ^= Y
            for j in 0..output_len {
                acc[j] ^= y[j]
            }
        }
        acc
    }
    fn derive_key_nonce<U>(
        key: &[u8],
        commit: &[u8],
        counter: U,
        acc: &[u8],
        encode: fn(U) -> Vec<u8>,
    ) -> (Vec<u8>, [u8; 16])
    where
        U: UnsignedInt,
    {
        // Set PRF key length based on hashing algorithm
        let digest_len = <D as OutputSizeUser>::output_size();
        let key_len = if digest_len >= 32 {
            32 // AES-256
        } else if digest_len >= 24 {
            24 // AES-196
        } else {
            16 // AES-128
        };
        // Encode external counter
        let ctr_bytes = encode(counter);
        // Derive PRF key
        // Depends on commitment, counter, and accumulator
        let mut mac = Hmac::<D>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        Mac::update(&mut mac, &[D_6]);
        Mac::update(&mut mac, commit);
        Mac::update(&mut mac, &ctr_bytes);
        Mac::update(&mut mac, acc);
        let key_full: Vec<u8> = mac.finalize().into_bytes().to_vec();
        let mut prf_key = vec![0u8; key_len];
        if key_full.len() >= key_len {
            prf_key.copy_from_slice(&key_full[0..key_len]);
        } else {
            // If hash output is too small, expand it with HKDF
            prf_key[0..key_full.len()].copy_from_slice(&key_full);
            let hk = Hkdf::<D>::new(None, &key_full);
            hk.expand(b"AES_KEY_EXPANSION", &mut prf_key[key_full.len()..])
                .expect("HKDF expansion should succeed");
        }
        // Derive PRF nonce
        // Depends on commitment and counter
        let mut mac = Hmac::<D>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        Mac::update(&mut mac, &[D_7]);
        Mac::update(&mut mac, commit);
        Mac::update(&mut mac, &ctr_bytes);
        let nonce_full: Vec<u8> = mac.finalize().into_bytes().to_vec();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_full[0..16]);
        // Return PRF key and nonce
        (prf_key, nonce)
    }
}
