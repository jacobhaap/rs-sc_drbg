//! A Rust implementation of the Subset Counter-Based Deterministic Random Bit
//! Generator (SC_DRBG).
//!
//! Provides a deterministic random bit generator that maintains an array of
//! seed material in its internal state (rather than a single seed), allowing
//! each output to be generated from a configurable subset of array elements.
//!
//! # Features
//! - Support for 32 and 64 bit unsigned integers.
//! - Configurable endianness.
//! - Can specify the number of elements (1 to N) used to produce each output.
//! - Commitment of array elements to their positions, lengths, and contents.
//! - Configurable rounds of mixing for entropy diffusion across elements.
//! - Provides forward security through state evolution.
//! - Implements `RngCore` for compatibility with the Rust random ecosystem.
//! - Secure memory zeroization on drop.
//!
//! # Example
//! ```
//! use hex_literal::hex;
//! use rand_core::RngCore;
//! use sc_drbg::Drbg;
//! use sha3::Sha3_256;
//!
//! fn main() {
//!     let arr = vec![
//!         hex!("456E64204F662054686520576F726C642053756E").to_vec(),
//!         hex!("556E6D616B65207468652057696C64204C69676874").to_vec(),
//!         hex!("536166652050617373616765").to_vec(),
//!         hex!("747261636B6572706C61747A").to_vec(),
//!         hex!("3635646179736F66737461746963").to_vec(),
//!     ];
//!     let context = "some-random-application";
//!
//!     let mut drbg = Drbg::<Sha3_256, u32>::new_le(&arr, Some(context), true)
//!         .expect("Should create new SC_DRBG instance");
//!
//!     let num = drbg.next_u32();
//!     assert_eq!(num, 4076030162);
//! }
//! ```

mod errors;
mod prf;
mod traits;

use digest::{
    Digest, HashMarker, OutputSizeUser,
    block_buffer::Eager,
    core_api::{
        BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
    },
    typenum::{IsLess, Le, NonZero, U256},
};
pub use errors::DrbgError;
use hkdf::Hkdf;
use prf::Prf;
use rand_core::RngCore;
use std::marker::PhantomData;
pub use traits::UnsignedInt;
use zeroize::Zeroize;

/// Byte order for integer encoding and decoding.
///
/// Specifies how 32 and 64 bit integers are converted to and from bytes.
/// during SC_DRBG operations. This choice affects deterministic output and
/// should match the endianness of other operations.
#[derive(Copy, Clone)]
pub enum Endian {
    /// Little-endian byte order.
    LittleEndian,
    /// Big-endian byte order.
    BigEndian,
}

/// Structure representing SC_DRBG, a Subset Counter-Based Deterministic
/// Random Bit Generator.
///
/// `Drbg` generates pseudorandom bytes from an initial array of seed
/// material. The generator maintains an internal state that evolves after
/// each output, providing forward secrecy.
///
/// # Generic Parameters
/// - `D` - A hashing algorithm implementing the `Digest` trait (e.g.,
/// `Sha256`, `Sha512`).
/// - `T` - Integer type for the counter and other integer values used
/// internally. Must be `u32` or `u64`.
///
/// # Security Considerations
/// The generator's security depends on the seed array containing sufficient
/// entropy. Low entropy inputs should be properly handled before use with
/// `Drbg`. The counter will panic if it reaches its maximum value (`u32::MAX`
/// or `u64::MAX`). Lastly, all outputs are deterministic given the same array
/// of seed material, context, and operations.
pub struct Drbg<D, T> {
    arr: Vec<Vec<u8>>,
    prk: Vec<u8>,
    context: String,
    ctr: T,
    endian: Endian,
    _digest: PhantomData<D>,
}

impl<D, T> Drbg<D, T>
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
    T: UnsignedInt,
{
    /// Create a new [Drbg] instance, using little-endian byte order, from an
    /// array of seed material and a context string.
    ///
    /// When the `init` parameter is `true`, the [Drbg::initialize] function is
    /// called to process the seed material. Using a nonce created from a hash
    /// of the array, this creates commitments and applies one round of mixing
    /// before creating the new instance from the processed material.
    pub fn new_le(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        init: bool,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        let endian = Endian::LittleEndian;
        if init {
            let arr_concat: Vec<u8> = arr.iter().flatten().copied().collect();
            let mut hasher = D::new();
            hasher.update(&arr_concat);
            let nonce = hasher.finalize().to_vec();
            let arr_init = Self::initialize(&arr, context, nonce, 1, endian);
            Ok(Self::new_from(&arr_init, context, endian))
        } else {
            Ok(Self::new_from(&arr, context, endian))
        }
    }
    /// Create a new [Drbg] instance, using big-endian byte order, from an
    /// array of seed material and a context string.
    ///
    /// When the `init` parameter is `true`, the [Drbg::initialize] function is
    /// called to process the seed material. Using a nonce created from a hash
    /// of the array, this creates commitments and applies one round of mixing
    /// before creating the new instance from the processed material.
    pub fn new_be(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        init: bool,
    ) -> Result<Self, DrbgError> {
        Self::validate_array(arr)?;
        Self::validate_digest()?;
        let endian = Endian::BigEndian;
        if init {
            let arr_concat: Vec<u8> = arr.iter().flatten().copied().collect();
            let mut hasher = D::new();
            hasher.update(&arr_concat);
            let nonce = hasher.finalize().to_vec();
            let arr_init = Self::initialize(&arr, context, nonce, 1, endian);
            Ok(Self::new_from(&arr_init, context, endian))
        } else {
            Ok(Self::new_from(&arr, context, endian))
        }
    }
    /// Initialize an array of seed material.
    ///
    /// First, creates commitments for all elements in the array of seed
    /// material, binding each to their position, length, and content. This
    /// helps to prevent reordering or substitution. Next, rounds of
    /// SHAKE256-based mixing are applied to diffuse entropy across all
    /// elements from the array of seed material. More rounds provide increased
    /// diffusion at a higher computational cost. One round should be suitable
    /// for most cases.
    ///
    /// # Arguments
    /// - `arr` - Array of seed material.
    /// - `context` - Optional context string for domain separation.
    /// - `nonce` - A unique value used for initialization keys.
    /// - `rounds` - The number of mixing rounds to apply.
    /// - `endian` - Byte order enum for representing integers as byte arrays.
    ///
    /// # Returns
    /// A new array which has undergone the initialization steps.
    pub fn initialize(
        arr: &[Vec<u8>],
        context: Option<&str>,
        nonce: Vec<u8>,
        rounds: usize,
        endian: Endian,
    ) -> Vec<Vec<u8>> {
        // Key length based on hashing algorithm
        let key_len = <D as OutputSizeUser>::output_size();
        // Concatenate all array elements
        let arr_concat: Vec<u8> = arr.iter().flatten().copied().collect();
        // PRK from HKDF-Extract, expand into commit and mix keys
        let prk = Self::derive_prk(&arr_concat, &nonce);
        let hk = Hkdf::<D>::from_prk(&prk).expect("PRK should be large enough");
        // Commitments key
        let mut key_1 = vec![0u8; key_len];
        let mut info = format!("{}-COMMIT", context.unwrap_or(""));
        hk.expand(&info.as_bytes().to_vec(), &mut key_1)
            .expect("okm length should match the hash digest length");
        // Mixing key
        let mut key_2 = vec![0u8; key_len];
        info = format!("{}-MIX", context.unwrap_or(""));
        hk.expand(&info.as_bytes().to_vec(), &mut key_2)
            .expect("okm length should match the hash digest length");
        // Commit each element to their position, length, and content
        let committed: Vec<Vec<u8>>;
        match endian {
            Endian::LittleEndian => {
                committed =
                    Prf::<D>::init_commits(&arr, &key_1, T::to_le_bytes);
            }
            Endian::BigEndian => {
                committed =
                    Prf::<D>::init_commits(&arr, &key_1, T::to_be_bytes);
            }
        }
        // Mix with rounds of SHAKE256 for entropy diffusion across elements
        let mixed: Vec<Vec<u8>>;
        match endian {
            Endian::LittleEndian => {
                mixed =
                    Prf::<D>::mix(&committed, &key_2, rounds, T::to_le_bytes);
            }
            Endian::BigEndian => {
                mixed =
                    Prf::<D>::mix(&committed, &key_2, rounds, T::to_be_bytes);
            }
        }
        mixed
    }
    /// Return the next random `u32`, seeded by a subset of elements from the
    /// [Drbg] state.
    ///
    /// Generates output by finalizing a subset of elements from the array of
    /// seed material with the current counter value. Provides forward secrecy
    /// by updating the internal state after each call. Decodes a 32 bit
    /// unsigned integer based on endianness from the state.
    ///
    /// # Arguments
    /// - `subset` - Number of elements from the array of seed material to seed
    /// the generator with. Clamped to array length.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX`). This prevents counter overflow.
    pub fn next_u32_subset(&mut self, subset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes_subset(subset, &mut bytes);
        match self.endian {
            Endian::LittleEndian => u32::from_le_bytes(bytes),
            Endian::BigEndian => u32::from_be_bytes(bytes),
        }
    }
    /// Return the next random `u64`, seeded by a subset of elements from the
    /// [Drbg] state.
    ///
    /// Generates output by finalizing a subset of elements from the array of
    /// seed material with the current counter value. Provides forward secrecy
    /// by updating the internal state after each call. Decodes a 64 bit
    /// unsigned integer based on endianness from the state.
    ///
    /// # Arguments
    /// - `subset` - Number of elements from the array of seed material to seed
    /// the generator with. Clamped to array length.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX`). This prevents counter overflow.
    pub fn next_u64_subset(&mut self, subset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes_subset(subset, &mut bytes);
        match self.endian {
            Endian::LittleEndian => u64::from_le_bytes(bytes),
            Endian::BigEndian => u64::from_be_bytes(bytes),
        }
    }
    /// Fills a destination buffer with random bytes, seeded by a subset of
    /// elements from the [Drbg] state.
    ///
    /// Generates output by finalizing a subset of elements from the array of
    /// seed material with the current counter value. Provides forward secrecy
    /// by updating the internal state after each call: re-mixing the seed
    /// material, deriving a new PRK from the mixed state, and incrementing the
    /// counter.
    ///
    /// # Arguments
    /// - `subset` - Number of elements from the array of seed material to seed
    /// the generator with. Clamped to array length.
    /// - `dst` - Destination buffer to fill with random bytes.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX`). This prevents counter overflow.
    pub fn fill_bytes_subset(&mut self, subset: usize, dst: &mut [u8]) {
        // Clamp subset to array length
        let subset = subset.min(self.arr.len());
        // Check to prevent counter overflow
        match T::SIZE {
            4 => {
                if self.ctr == T::MAX {
                    panic!("Counter exhausted u32 range")
                }
            }
            8 => {
                if self.ctr == T::MAX {
                    panic!("Counter exhausted u64 range")
                }
            }
            _ => unreachable!("Only u32 and u64 supported"),
        }
        // Finalize subset of elements using PRK and counter
        match &mut self.endian {
            Endian::LittleEndian => Prf::<D>::next(
                &self.arr,
                &self.context,
                &self.prk,
                subset,
                self.ctr,
                T::to_le_bytes,
                T::from_le_bytes,
                dst,
            ),
            Endian::BigEndian => Prf::<D>::next(
                &self.arr,
                &self.context,
                &self.prk,
                subset,
                self.ctr,
                T::to_be_bytes,
                T::from_be_bytes,
                dst,
            ),
        }
        // Increment counter
        self.ctr = self.ctr.wrapping_add(T::from(1));
        // Prepend the context to the label
        let label = format!("{}-UPDATE", &self.context);
        let label_bytes = &label.as_bytes().to_vec();
        // PRK to re-mix elements
        let mut tmp_prk = Self::derive_prk(&dst.to_vec(), &label_bytes);
        // Mix the array from the current state
        let tmp_arr = match self.endian {
            Endian::LittleEndian => {
                Prf::<D>::mix(&self.arr, &tmp_prk, 1, T::to_le_bytes)
            }
            Endian::BigEndian => {
                Prf::<D>::mix(&self.arr, &tmp_prk, 1, T::to_be_bytes)
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
    fn derive_prk(ikm: &Vec<u8>, salt: &Vec<u8>) -> Vec<u8> {
        // PRK length based on hashing algorithm
        let prk_len = <D as OutputSizeUser>::output_size();
        // PRK from HKDF-Extract
        let (prk_arr, _) = Hkdf::<D>::extract(Some(&salt), &ikm);
        let mut prk = vec![0u8; prk_len];
        prk.copy_from_slice(&prk_arr);
        prk
    }
    fn new_from(
        arr: &Vec<Vec<u8>>,
        context: Option<&str>,
        endian: Endian,
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
            ctr: T::from(0),
            endian: endian,
            _digest: PhantomData,
        }
    }
}

impl<D, T> RngCore for Drbg<D, T>
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
    T: UnsignedInt,
{
    /// Return the next random `u32`.
    ///
    /// Generates output by finalizing all elements from the array of seed
    /// material with the current counter value. Provides forward secrecy by
    /// updating the internal state after each call. Decodes a 32 bit unsigned
    /// integer based on endianness from the state.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX`). This prevents counter overflow.
    fn next_u32(&mut self) -> u32 {
        return self.next_u32_subset(self.arr.len());
    }
    /// Return the next random `u64`.
    ///
    /// Generates output by finalizing all elements from the array of seed
    /// material with the current counter value. Provides forward secrecy by
    /// updating the internal state after each call. Decodes a 64 bit unsigned
    /// integer based on endianness from the state.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX`). This prevents counter overflow.
    fn next_u64(&mut self) -> u64 {
        return self.next_u64_subset(self.arr.len());
    }
    /// Fills a destination buffer with random bytes.
    ///
    /// Generates output by finalizing all elements from the array of seed
    /// material with the current counter value. Provides forward secrecy by
    /// updating the internal state after each call: re-mixing the seed
    /// material, deriving a new PRK from the mixed state, and incrementing the
    /// counter.
    ///
    /// # Arguments
    /// - `dst` - Destination buffer to fill with random bytes.
    ///
    /// # Panics
    /// This method will panic if the counter reaches its maximum value
    /// (`u32::MAX` or `u64::MAX`). This prevents counter overflow.
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.fill_bytes_subset(self.arr.len(), dst);
    }
}

impl<D, T> Drop for Drbg<D, T> {
    fn drop(&mut self) {
        self.prk.zeroize();
        for element in &mut self.arr {
            element.zeroize();
        }
    }
}
