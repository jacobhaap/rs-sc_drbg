# Rust::SC_DRBG
A Rust implementation of the **Subset Counter-Based Deterministic Random Bit Generator** (SC_DRBG).

> This is a new and experimental function that has not undergone any review or audit. In the absence of cryptanalysis, use at your own risk.

SC_DRBG is a deterministic random bit generator that utilizes an internal array of seed elements maintained in the internal state, rather than a single seed, that allows for a configurable subset of those elements (1 to N) for use in the generation of each output.

The following features are supported by SC_DRBG:
- Supports 32 bit and 32 bit unsigned integers for the internal counter, and other integer values.
- Configurable endianness for integer encoding and decoding.
- Binding of array elements to their positions, lengths, and contents via cryptographic commitment.
- A configurable number of mixing rounds for entropy distribution across seed elements.
- Provides forward security through continuous state evolution.
- Implements [RngCore](https://docs.rs/rand_core/0.9.3/rand_core/trait.RngCore.html) for compatibility with the Rust random ecosystem.
- Secure memory zeroization on drop.

The `Drbg` struct supports initialization via eight different constructors:
- **new_u32_le**: Uses a 32 bit counter with little-endian encoding. Applies binding and mixing, where each element in the seed array is committed to its position, length, and content, then rounds of SHAKE256 mixing are applied for entropy distribution across seed elements.
- **new_from_u32_le**: Uses a 32 bit counter with little-endian encoding. Bypasses binding and mixing, instead directly using a provided seed array to initialize the `Drbg` state. Use this to process seed material that has been processed externally, or to restore from a previous state.
- **new_u32_be**: Uses a 32 bit counter with big-endian encoding. Like the `new_u32_le` constructor, but adjusted for endianness.
- **new_from_u32_be**: Uses a 32 bit counter with big-endian encoding. Like the `new_from_u32_le` constructor, but adjusted for endianness.
- **new_u64_le**: Uses a 64 bit counter with little-endian encoding. Like the 32 bit versions of `new_*`, but with unsigned 64 bit integers.
- **new_from_u64_le**: Uses a 64 bit counter with little-endian encoding. Like the 32 bit versions of `new_from_*`, but with unsigned 64 bit integers.
- **new_u64_be**: Uses a 64 bit counter with big-endian encoding. Like the `new_u64_le` constructor, but adjusted for endianness.
- **new_from_u64_be**: Uses a 64 bit counter with big-endian encoding. Like the `new_from_u64_le` constructor, but adjusted for endianness.

When initializing using a `new_from_*` constructor, seed material can still utilize binding and mixing, via the `bind` and mix `methods`. These methods are functionally identical to those which are automatically applied in the `new_*` constructors, and return the bound/mixed elements are returned

Regardless of how the struct is initialized, the following methods are always available:
- **next_u32**: From the _RngCore_ implementation. Returns the next random unsigned 32 bit integer.
- **next_u32_subset**: Returns the next random unsigned 32 bit integer, seeded by a subset of elements from the internal state. The number of elements to use must be specified, and is clamped to the total array length.
- **next_u64**: From the _RngCore_ implementation. Returns the next random unsigned 64 bit integer.
- **next_u64_subset**: Returns the next random unsigned 64 bit integer, seeded by a subset of elements from the internal state. The number of elements to use must be specified, and is clamped to the total array length.
- **fill_bytes**: From the _RngCore_ implementation. Fills a destination buffer with random bytes.
- **fill_bytes_subset**: Fills a destination buffer with random bytes, seeded by a subset of elements from the internal state. The number of elements to use must be specified, and is clamped to the total array length.

## Example Use
```rust
use rand_core::RngCore;
use sc_drbg::Drbg;
use sha2::Sha256;

fn main() {
    // Define array elements and optional context string
    let arr = vec![
        b"L01X00T47".to_vec(),
        b"MUSTERMANN".to_vec(),
        b"ERIKA".to_vec(),
        b"12081983".to_vec(),
        b"DEUTSCH".to_vec(),
        b"BERLIN".to_vec(),
    ];
    let context = "my-app";

    // Create DRBG
    let mut drbg = Drbg::<Sha256>::new_u32_le(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");

    // Fill dst with 32 bytes from Drbg
    let mut dst = [0u8; 32];
    drbg.fill_bytes(&mut dst);

    // Fill dst using subset of 4 elements
    drbg.fill_bytes_subset(4, &mut dst);

    // Get 64 bit unsigned integer via rand_core
   let num = drbg.next_u64();
}
```
