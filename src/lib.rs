//! A Rust implementation of the Subset Counter-Based Deterministic Random Bit
//! Generator (SC_DRBG).
//!
//! Provides a deterministic random bit generator that maintains an internal
//! array of seed elements (rather than a single seed), and allows generating
//! outputs from a configurable subset of those elements.
//!
//! # Features
//! - Support for 32 and 64 bit unsigned integers.
//! - Configurable endianness.
//! - Can specify the number of elements (1 to N) used to produce each output.
//! - Binding of array elements to their positions, lengths, and contents.
//! - Configurable rounds of mixing for entropy distribution across elements.
//! - Provides forward security through state evolution.
//! - Implements `RngCore` for compatibility with the Rust random ecosystem.
//! - Secure memory zeroization on drop.
//!
//! # Example
//! ```ignore
//! use rand_core::RngCore;
//! use sc_drbg::Drbg;
//! use sha2::Sha256;
//!
//! fn main() {
//!     // Define array elements and optional context string
//!     let arr = vec![
//!         b"L01X00T47".to_vec(),
//!         b"MUSTERMANN".to_vec(),
//!         b"ERIKA".to_vec(),
//!         b"12081983".to_vec(),
//!         b"DEUTSCH".to_vec(),
//!         b"BERLIN".to_vec(),
//!     ];
//!     let context = "my-app";
//!
//!     // Create DRBG
//!     let mut drbg = Drbg::<Sha256>::new_u32_le(&arr, Some(context), 1)
//!         .expect("Should create new SC_DRBG instance");
//!
//!     // Fill dst with 32 bytes from Drbg
//!     let mut dst = [0u8; 32];
//!     drbg.fill_bytes(&mut dst);
//!
//!     // Fill dst using subset of 4 elements
//!     drbg.fill_bytes_subset(4, &mut dst);
//!
//!     // Get 64 bit unsigned integer via rand_core
//!    let num = drbg.next_u64();
//! }
//! ```

mod errors;
mod prf;

use ::zeroize::Zeroize;
use digest::{
    Digest, HashMarker, OutputSizeUser,
    block_buffer::Eager,
    core_api::{
        BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
    },
    typenum::{IsLess, Le, NonZero, U256},
};
use errors::DrbgError;
use hkdf::Hkdf;
use prf::Prf;
use rand_core::RngCore;
use std::marker::PhantomData;

/// Endianness for internal counter and other integers.
///
/// Specifies how 32 and 64 bit integers are converted to/from bytes during
/// SC_DRBG operations. This choice affects deterministic output and should
/// match the endianness of other operations.
#[derive(Copy, Clone)]
pub enum CounterEndian {
    /// 32 bit counter, little-endian byte order.
    U32LE,
    /// 32 bit counter, big-endian byte order.
    U32BE,
    /// 64 bit counter, little-endian byte order.
    U64LE,
    /// 64 bit counter, big-endian byte order.
    U64BE,
}

/// A Subset Counter-Based Deterministic Random Bit Generator (SC_DRBG).
///
/// `Drbg`` generates pseudorandom bytes from an initial array of seed
/// material. The generator maintains an internal state that evolves after
/// each output, providing forward secrecy.
///
/// # Generic Parameters
/// - `D` - A hashing algorithm implementing the `Digest` trait (e.g.,
/// `Sha256`, `Sha512`).
///
/// # Security Considerations
/// The generator's security depends on the seed array containing sufficient
/// entropy. Low entropy inputs should be properly handled before use with
/// `Drbg`. The internal counter will panic if it reaches its maximum value
/// (`u32::MAX` or `u64::MAX`). Lastly, all outputs are deterministic given
/// the same seed array, context, and operations.
pub struct Drbg<D> {
    arr: Vec<Vec<u8>>,
    prk: Vec<u8>,
    context: String,
    ctr: usize,
    ctr_endian: CounterEndian,
    _digest: PhantomData<D>,
}

impl<D> Drbg<D>
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
    /// Create a new [Drbg] instance with a 32 bit little-endian counter.
    ///
    /// This constructor performs three operations. First, each element in the
    /// seed array is committed to its position, length, and content. Next,
    /// `rounds` iterations of SHAKE256 mixing is applied to distribute entropy
    /// across seed elements. Last, the [Drbg] instance is initialized.
    pub fn new_u32_le(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        rounds: usize,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        let bound = Self::bind(&arr, context, CounterEndian::U32LE);
        let mixed = Self::mix(&bound, context, rounds, CounterEndian::U32LE);
        Ok(Self::new_from(&mixed, context, CounterEndian::U32LE))
    }
    /// Create a new [Drbg] instance with a 32 bit little-endian counter.
    ///
    /// This constructor bypasses the binding and mixing operations, using the
    /// provided seed array directly in the [Drbg] state. Use this for seed
    /// material that has been processed externally, or to restore a previous
    /// state.
    pub fn new_from_u32_le(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        Ok(Self::new_from(arr, context, CounterEndian::U32LE))
    }
    /// Create a new [Drbg] instance with a 32 bit big-endian counter.
    ///
    /// This constructor performs three operations. First, each element in the
    /// seed array is committed to its position, length, and content. Next,
    /// `rounds` iterations of SHAKE256 mixing is applied to distribute entropy
    /// across seed elements. Last, the [Drbg] instance is initialized.
    pub fn new_u32_be(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        rounds: usize,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        let bound = Self::bind(&arr, context, CounterEndian::U32BE);
        let mixed = Self::mix(&bound, context, rounds, CounterEndian::U32BE);
        Ok(Self::new_from(&mixed, context, CounterEndian::U32BE))
    }
    /// Create a new [Drbg] instance with a 32 bit big-endian counter.
    ///
    /// This constructor bypasses the binding and mixing operations, using the
    /// provided seed array directly in the [Drbg] state. Use this for seed
    /// material that has been processed externally, or to restore a previous
    /// state.
    pub fn new_from_u32_be(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        Ok(Self::new_from(arr, context, CounterEndian::U32BE))
    }
    /// Create a new [Drbg] instance with a 64 bit little-endian counter.
    ///
    /// This constructor performs three operations. First, each element in the
    /// seed array is committed to its position, length, and content. Next,
    /// `rounds` iterations of SHAKE256 mixing is applied to distribute entropy
    /// across seed elements. Last, the [Drbg] instance is initialized.
    pub fn new_u64_le(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        rounds: usize,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        let bound = Self::bind(&arr, context, CounterEndian::U64LE);
        let mixed = Self::mix(&bound, context, rounds, CounterEndian::U64LE);
        Ok(Self::new_from(&mixed, context, CounterEndian::U64LE))
    }
    /// Create a new [Drbg] instance with a 64 bit little-endian counter.
    ///
    /// This constructor bypasses the binding and mixing operations, using the
    /// provided seed array directly in the [Drbg] state. Use this for seed
    /// material that has been processed externally, or to restore a previous
    /// state.
    pub fn new_from_u64_le(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        Ok(Self::new_from(arr, context, CounterEndian::U64LE))
    }
    /// Create a new [Drbg] instance with a 64 bit big-endian counter.
    ///
    /// This constructor performs three operations. First, each element in the
    /// seed array is committed to its position, length, and content. Next,
    /// `rounds` iterations of SHAKE256 mixing is applied to distribute entropy
    /// across seed elements. Last, the [Drbg] instance is initialized.
    pub fn new_u64_be(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        rounds: usize,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        let bound = Self::bind(&arr, context, CounterEndian::U64BE);
        let mixed = Self::mix(&bound, context, rounds, CounterEndian::U64BE);
        Ok(Self::new_from(&mixed, context, CounterEndian::U64BE))
    }
    /// Create a new [Drbg] instance with a 64 bit big-endian counter.
    ///
    /// This constructor bypasses the binding and mixing operations, using the
    /// provided seed array directly in the [Drbg] state. Use this for seed
    /// material that has been processed externally, or to restore a previous
    /// state.
    pub fn new_from_u64_be(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        Ok(Self::new_from(arr, context, CounterEndian::U64BE))
    }
    /// Return the next random `u32`, seeded by a subset of elements from the
    /// [Drbg] state.
    ///
    /// Generates output by finalizing a subset of seed array elements with the
    /// current counter value. Provides forward secrecy by modifying the
    /// internal state after each call. Decodes bytes to the `u32` based on
    /// endianness from the state.
    ///
    /// # Arguments
    /// - `subset` Number of array elements to use. Clamped to array length.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX`). This prevents counter overflow.
    pub fn next_u32_subset(&mut self, subset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes_subset(subset, &mut bytes);
        match self.ctr_endian {
            CounterEndian::U32LE => from_le_bytes_32(&bytes),
            CounterEndian::U32BE => from_be_bytes_32(&bytes),
            CounterEndian::U64LE => from_le_bytes_32(&bytes),
            CounterEndian::U64BE => from_be_bytes_32(&bytes),
        }
    }
    /// Return the next random `u64`, seeded by a subset of elements from the
    /// [Drbg] state.
    ///
    /// Generates output by finalizing a subset of seed array elements with the
    /// current counter value. Provides forward secrecy by modifying the
    /// internal state after each call. Decodes bytes to the `u64` based on
    /// endianness from the state.
    ///
    /// # Arguments
    /// - `subset` Number of array elements to use. Clamped to array length.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u64::MAX`). This prevents counter overflow.
    pub fn next_u64_subset(&mut self, subset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes_subset(subset, &mut bytes);
        match self.ctr_endian {
            CounterEndian::U32LE => from_le_bytes_64(&bytes),
            CounterEndian::U32BE => from_be_bytes_64(&bytes),
            CounterEndian::U64LE => from_le_bytes_64(&bytes),
            CounterEndian::U64BE => from_be_bytes_64(&bytes),
        }
    }
    /// Fills a destination buffer with random bytes, seeded by a subset of
    /// elements from the [Drbg] state.
    ///
    /// Generates output by finalizing a subset of seed array elements with
    /// the current counter value, then updates the internal state by re-mixing
    /// the array elements, deriving a new PRK from the mixed state, and
    /// incrementing the counter.
    ///
    /// As each call modifies the internal state, forward secrecy is provided.
    ///
    /// # Arguments
    /// - `subset` Number of array elements to use. Clamped to array length.
    /// - `dst` - Destination buffer to fill with random bytes.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX` depending on the [CounterEndian]
    /// configuration). This prevents counter overflow.
    pub fn fill_bytes_subset(&mut self, subset: usize, dst: &mut [u8]) {
        // Clamp subset to array length
        let subset = subset.min(self.arr.len());
        // Finalize subset of elements using PRK and counter
        match &mut self.ctr_endian {
            CounterEndian::U32LE => {
                if self.ctr == u32::MAX as usize {
                    panic!("Counter reached u32 limit")
                }
                Prf::<D>::next(
                    &self.arr,
                    &self.prk,
                    subset,
                    self.ctr as u32,
                    to_le_bytes_32,
                    from_le_bytes_32,
                    dst,
                );
                self.ctr = self.ctr.wrapping_add(1);
            }
            CounterEndian::U32BE => {
                if self.ctr == u32::MAX as usize {
                    panic!("Counter reached u32 limit")
                }
                Prf::<D>::next(
                    &self.arr,
                    &self.prk,
                    subset,
                    self.ctr as u32,
                    to_be_bytes_32,
                    from_be_bytes_32,
                    dst,
                );
                self.ctr = self.ctr.wrapping_add(1);
            }
            CounterEndian::U64LE => {
                if self.ctr == u64::MAX as usize {
                    panic!("Counter reached u64 limit")
                }
                Prf::<D>::next(
                    &self.arr,
                    &self.prk,
                    subset,
                    self.ctr as u64,
                    to_le_bytes_64,
                    from_le_bytes_64,
                    dst,
                );
                self.ctr = self.ctr.wrapping_add(1);
            }
            CounterEndian::U64BE => {
                if self.ctr == u64::MAX as usize {
                    panic!("Counter reached u64 limit")
                }
                Prf::<D>::next(
                    &self.arr,
                    &self.prk,
                    subset,
                    self.ctr as u64,
                    to_be_bytes_64,
                    from_be_bytes_64,
                    dst,
                );
                self.ctr = self.ctr.wrapping_add(1);
            }
        }
        // Prepend the context to the label
        let label = format!("{}-REMIX", &self.context);
        let label_bytes = &label.as_bytes().to_vec();
        // PRK to re-mix elements
        let mut tmp_prk = Self::derive_prk(&dst.to_vec(), &label_bytes);
        // Mix the array from the current state
        let tmp_arr = match self.ctr_endian {
            CounterEndian::U32LE => {
                Prf::<D>::mix(&self.arr, &tmp_prk, 1, to_le_bytes_32)
            }
            CounterEndian::U32BE => {
                Prf::<D>::mix(&self.arr, &tmp_prk, 1, to_be_bytes_32)
            }
            CounterEndian::U64LE => {
                Prf::<D>::mix(&self.arr, &tmp_prk, 1, to_le_bytes_64)
            }
            CounterEndian::U64BE => {
                Prf::<D>::mix(&self.arr, &tmp_prk, 1, to_be_bytes_64)
            }
        };
        // Concatenate all array elements
        let arr_concat: Vec<u8> = tmp_arr.iter().flatten().copied().collect();
        // Prepend the context to the label
        let label = format!("{}-NEXT", &self.context);
        let label_bytes = &label.as_bytes().to_vec();
        // PRK for the updated state, used in the next PRF call
        tmp_prk = Self::derive_prk(&arr_concat, &label_bytes);
        // Update instance with mixed array and new PRK
        self.arr = tmp_arr;
        self.prk = tmp_prk;
    }
    /// Create a cryptographic for each element of an array, binding each to
    /// their position, length, and content.
    ///
    /// Binding helps to prevent reordering or substitution.
    ///
    /// # Arguments
    /// - `arr` - Array of elements to bind.
    /// - `context` - Optional context string for domain separation.
    /// - `ctr_endian` - Enum for the counter integer type, and endianness.
    ///
    /// # Returns
    /// A new array where each element has been committed to its properties.
    pub fn bind(
        arr: &[Vec<u8>],
        context: Option<&str>,
        ctr_endian: CounterEndian,
    ) -> Vec<Vec<u8>> {
        // Key length based on hashing algorithm
        let key_len = <D as OutputSizeUser>::output_size();
        // Concatenate all array elements
        let arr_concat: Vec<u8> = arr.iter().flatten().copied().collect();
        // Prepend the context to the label
        let label = format!("{}-BIND", context.unwrap_or(""));
        let label_bytes = &label.as_bytes().to_vec();
        // PRK from HKDF-Extract
        let prk = Self::derive_prk(&arr_concat, &label_bytes);
        // Set info bytes from endianness
        let info: Vec<u8>;
        match ctr_endian {
            CounterEndian::U32LE | CounterEndian::U64LE => {
                info = b"little-endian".to_vec()
            }
            CounterEndian::U32BE | CounterEndian::U64BE => {
                info = b"big-endian".to_vec()
            }
        }
        // Expand PRK into key for binding
        let hk = Hkdf::<D>::from_prk(&prk).expect("PRK should be large enough");
        let mut key = vec![0u8; key_len];
        hk.expand(&info, &mut key)
            .expect("okm length should match the hash digest length");
        // Bind elements to their positions, lengths, and contents
        let bound: Vec<Vec<u8>>;
        match ctr_endian {
            CounterEndian::U32LE => {
                bound = Prf::<D>::bind(&arr, &key, to_le_bytes_32);
            }
            CounterEndian::U32BE => {
                bound = Prf::<D>::bind(&arr, &key, to_be_bytes_32);
            }
            CounterEndian::U64LE => {
                bound = Prf::<D>::bind(&arr, &key, to_le_bytes_64);
            }
            CounterEndian::U64BE => {
                bound = Prf::<D>::bind(&arr, &key, to_be_bytes_64);
            }
        }
        bound
    }
    /// Mixes an array with `rounds` of SHAKE256 to distribute entropy across
    /// all array elements. More rounds provide increased entropy distribution
    /// at the cost of an increased computational cost. One round should be
    /// suitable for most cases.
    ///
    /// Mixed elements match the lengths of the corresponding input elements.
    ///
    /// # Arguments
    /// - `arr` - Array of elements to mix.
    /// - `context` - Optional context string for domain separation.
    /// - `ctr_endian` - Enum for the counter integer type, and endianness.
    ///
    /// # Returns
    /// A new array of mixed elements.
    pub fn mix(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        rounds: usize,
        ctr_endian: CounterEndian,
    ) -> Vec<Vec<u8>> {
        // Concatenate all array elements
        let arr_concat: Vec<u8> = arr.iter().flatten().copied().collect();
        // Prepend the context to the label
        let label = format!("{}-MIX", context.unwrap_or(""));
        let label_bytes = &label.as_bytes().to_vec();
        // PRK from HKDF-Extract
        let prk = Self::derive_prk(&arr_concat, &label_bytes);
        // Mix elements with rounds of SHAKE256
        let mixed: Vec<Vec<u8>>;
        match ctr_endian {
            CounterEndian::U32LE => {
                mixed = Prf::<D>::mix(&arr, &prk, rounds, to_le_bytes_32);
            }
            CounterEndian::U32BE => {
                mixed = Prf::<D>::mix(&arr, &prk, rounds, to_be_bytes_32);
            }
            CounterEndian::U64LE => {
                mixed = Prf::<D>::mix(&arr, &prk, rounds, to_le_bytes_64);
            }
            CounterEndian::U64BE => {
                mixed = Prf::<D>::mix(&arr, &prk, rounds, to_be_bytes_64);
            }
        }
        mixed
    }
    fn validate_array(arr: &Vec<Vec<u8>>) -> Result<(), DrbgError> {
        if arr.is_empty() {
            return Err(DrbgError::EmptyArray);
        }
        let empty_elements: Vec<usize> = arr
            .iter()
            .enumerate()
            .filter_map(
                |(i, element)| if element.is_empty() { Some(i) } else { None },
            )
            .collect();
        if !empty_elements.is_empty() {
            return Err(DrbgError::EmptyElement(empty_elements));
        }
        Ok(())
    }
    fn validate_digest() -> Result<(), DrbgError> {
        let digest_len = <D as OutputSizeUser>::output_size();
        if digest_len < 16 {
            return Err(DrbgError::DigestTooSmall(digest_len));
        }
        Ok(())
    }
    fn derive_prk(ikm: &Vec<u8>, label: &Vec<u8>) -> Vec<u8> {
        // PRK length based on hashing algorithm
        let prk_len = <D as OutputSizeUser>::output_size();
        // PRK from HKDF-Extract, using the label as salt
        let (prk_arr, _) = Hkdf::<D>::extract(Some(&label), &ikm);
        let mut prk = vec![0u8; prk_len];
        prk.copy_from_slice(&prk_arr);
        prk
    }
    fn new_from(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        ctr_endian: CounterEndian,
    ) -> Self {
        // Concatenate all array elements
        let arr_concat: Vec<u8> = arr.iter().flatten().copied().collect();
        // Prepend the context to the label
        let label = format!("{}-OUTPUT", context.unwrap_or(""));
        let label_bytes = &label.as_bytes().to_vec();
        // PRK from HKDF-Extract
        let prk = Self::derive_prk(&arr_concat, &label_bytes);
        // Return Drbg instance
        Self {
            arr: arr.to_vec(),
            prk: prk,
            context: context.unwrap_or("").to_string(),
            ctr: 0,
            ctr_endian: ctr_endian,
            _digest: PhantomData,
        }
    }
}

impl<D> RngCore for Drbg<D>
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
    /// Return the next random `u32`.
    ///
    /// Generates output by finalizing all seed array elements with the current
    /// counter value. Provides forward secrecy by modifying the internal state
    /// after each call. Decodes bytes to the `u32` based on endianness from the
    /// state.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX`). This prevents counter overflow.
    fn next_u32(&mut self) -> u32 {
        return self.next_u32_subset(self.arr.len());
    }
    /// Return the next random `u64`.
    ///
    /// Generates output by finalizing all seed array elements with the current
    /// counter value. Provides forward secrecy by modifying the internal state
    /// after each call. Decodes bytes to the `u64` based on endianness from the
    /// state.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u64::MAX`). This prevents counter overflow.
    fn next_u64(&mut self) -> u64 {
        return self.next_u64_subset(self.arr.len());
    }
    /// Fills a destination buffer with random bytes.
    ///
    /// Generates output by finalizing all seed array elements with the current
    /// counter value, then updates the internal state by re-mixing the array
    /// elements, deriving a new PRK from the mixed state, and incrementing the
    /// counter.
    ///
    /// As each call modifies the internal state, forward secrecy is provided.
    ///
    /// # Arguments
    /// - `dst` - Destination buffer to fill with random bytes.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX` depending on the [CounterEndian]
    /// configuration). This prevents counter overflow.
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.fill_bytes_subset(self.arr.len(), dst);
    }
}

impl<D> Drop for Drbg<D> {
    fn drop(&mut self) {
        self.prk.zeroize();
        for element in &mut self.arr {
            element.zeroize();
        }
    }
}

fn to_le_bytes_32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn to_be_bytes_32(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn to_le_bytes_64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn to_be_bytes_64(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn from_le_bytes_32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(
        bytes
            .try_into()
            .expect("slice must be exactly 4 bytes for u32 conversion"),
    )
}

fn from_be_bytes_32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(
        bytes
            .try_into()
            .expect("slice must be exactly 4 bytes for u32 conversion"),
    )
}

fn from_le_bytes_64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(
        bytes
            .try_into()
            .expect("slice must be exactly 4 bytes for u64 conversion"),
    )
}

fn from_be_bytes_64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(
        bytes
            .try_into()
            .expect("slice must be exactly 4 bytes for u64 conversion"),
    )
}
