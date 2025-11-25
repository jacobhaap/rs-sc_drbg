use hex::{FromHexError, decode};
use rand_core::RngCore;
use sc_drbg::Drbg;
use sha3::Sha3_256;

fn get_seed_vec() -> Result<Vec<Vec<u8>>, FromHexError> {
    let arr = vec![
        decode("ca33496c5c9e5f3ce6e932a0670d320f")?,
        decode("e17baaae2056f7cea2083482f9818b1c")?,
        decode("2c1aef2c624598ae937eed2b5ad9448b")?,
        decode("6932a3726327aa4a092771dabf198fc7")?,
        decode("fe9fe0c3b16f8ae27b09856bd0f487d1")?,
        decode("87c83f8f122b3bcccf42a97f487133f9")?,
        decode("5bc58505a5cc3406168facc39ba0f5dc")?,
    ];
    Ok(arr)
}

#[test]
fn drbg_u32_le() {
    // Expected u32 and u64 outputs
    let u32_le_u32: [u32; 5] =
        [1088321269, 574267334, 2789630583, 2361077724, 2428529226];
    let u32_le_u64: [u64; 5] = [
        6034093503353353973,
        6716340068268398770,
        4715358673953101616,
        5740942628896112298,
        7334600668779912220,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec().expect("Should decode all hex strings");
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 32 bit counter, little-endian
    let mut drbg = Drbg::<Sha3_256>::new_u32_le(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u32_le_u32[i]);
    }
    // Re-initialize DRBG
    drbg = Drbg::<Sha3_256>::new_u32_le(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u64 matches expected output
    for i in 0..5 {
        let num = drbg.next_u64();
        assert_eq!(num, u32_le_u64[i]);
    }
}

#[test]
fn drbg_u32_be() {
    // Expected u32 and u64 outputs
    let u32_be_u32: [u32; 5] =
        [2270311602, 3589045505, 3682340443, 1261300795, 3223195470];
    let u32_be_u64: [u64; 5] = [
        9750914083921614167,
        17033913984057126318,
        875900545375946641,
        13800722825688937135,
        14352485036659351884,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec().expect("Should decode all hex strings");
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 32 bit counter, big-endian
    let mut drbg = Drbg::<Sha3_256>::new_u32_be(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u32_be_u32[i]);
    }
    // Re-initialize DRBG
    drbg = Drbg::<Sha3_256>::new_u32_be(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u64 matches expected output
    for i in 0..5 {
        let num = drbg.next_u64();
        assert_eq!(num, u32_be_u64[i]);
    }
}

#[test]
fn drbg_u64_le() {
    // Expected u32 and u64 outputs
    let u64_le_u32: [u32; 5] =
        [1557638083, 476095602, 48395877, 2710624076, 3776901043];
    let u64_le_u64: [u64; 5] = [
        10416173465413856195,
        272724317746412691,
        3862251445925633354,
        1841283581078576857,
        3344596433754050210,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec().expect("Should decode all hex strings");
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 64 bit counter, little-endian
    let mut drbg = Drbg::<Sha3_256>::new_u64_le(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u64_le_u32[i]);
    }
    // Re-initialize DRBG
    drbg = Drbg::<Sha3_256>::new_u64_le(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u64 matches expected output
    for i in 0..5 {
        let num = drbg.next_u64();
        assert_eq!(num, u64_le_u64[i]);
    }
}

#[test]
fn drbg_u64_be() {
    // Expected u32 and u64 outputs
    let u64_be_u32: [u32; 5] =
        [3747155193, 2319339581, 1968096256, 2233033939, 3671142433];
    let u64_be_u64: [u64; 5] = [
        16093909010339455819,
        1212188418513365825,
        14575403774737134300,
        12232231267039432147,
        918691564519710065,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec().expect("Should decode all hex strings");
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 64 bit counter, big-endian
    let mut drbg = Drbg::<Sha3_256>::new_u64_be(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u64_be_u32[i]);
    }
    // Re-initialize DRBG
    drbg = Drbg::<Sha3_256>::new_u64_be(&arr, Some(context), 1)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u64 matches expected output
    for i in 0..5 {
        let num = drbg.next_u64();
        assert_eq!(num, u64_be_u64[i]);
    }
}
