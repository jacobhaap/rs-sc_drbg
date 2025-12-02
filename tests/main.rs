use hex_literal::hex;
use rand_core::RngCore;
use sc_drbg::Drbg;
use sha3::Sha3_256;

fn get_seed_vec() -> Vec<Vec<u8>> {
    let arr = vec![
        hex!("ca33496c5c9e5f3ce6e932a0670d320f").to_vec(),
        hex!("e17baaae2056f7cea2083482f9818b1c").to_vec(),
        hex!("2c1aef2c624598ae937eed2b5ad9448b").to_vec(),
        hex!("6932a3726327aa4a092771dabf198fc7").to_vec(),
        hex!("fe9fe0c3b16f8ae27b09856bd0f487d1").to_vec(),
        hex!("87c83f8f122b3bcccf42a97f487133f9").to_vec(),
        hex!("5bc58505a5cc3406168facc39ba0f5dc").to_vec(),
    ];
    arr
}

#[test]
fn drbg_u32_le() {
    // Expected u32 and u64 outputs
    let u32_le_u32: [u32; 5] =
        [2296859039, 3520090129, 755322988, 1089056308, 1233950592];
    let u32_le_u64: [u64; 5] = [
        14627290128518171039,
        14312161537058068219,
        15005291635268623789,
        3355993008263979106,
        14800901245741747956,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec();
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 32 bit counter, little-endian
    let mut drbg = Drbg::<Sha3_256, u32>::new_le(&arr, Some(context), true)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u32_le_u32[i]);
    }
    // Re-initialize DRBG
    let mut drbg = Drbg::<Sha3_256, u32>::new_le(&arr, Some(context), true)
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
        [1063137602, 2826121088, 3298000299, 2890410248, 3294535920];
    let u32_be_u64: [u64; 5] = [
        4566141234723800237,
        2655253991924942313,
        11414807746746846060,
        14120807454358857646,
        15529248475412121348,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec();
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 32 bit counter, big-endian
    let mut drbg = Drbg::<Sha3_256, u32>::new_be(&arr, Some(context), true)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u32_be_u32[i]);
    }
    // Re-initialize DRBG
    let mut drbg = Drbg::<Sha3_256, u32>::new_be(&arr, Some(context), true)
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
        [3513012354, 3115741082, 3418770424, 1178855421, 2303171038];
    let u64_le_u64: [u64; 5] = [
        4347230222507331714,
        16466604991238817181,
        12219542919680157343,
        13248978728273083570,
        7071113371231795053,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec();
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 64 bit counter, little-endian
    let mut drbg = Drbg::<Sha3_256, u64>::new_le(&arr, Some(context), true)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u64_le_u32[i]);
    }
    // Re-initialize DRBG
    let mut drbg = Drbg::<Sha3_256, u64>::new_le(&arr, Some(context), true)
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
        [502628020, 2880383839, 3798114914, 3862077194, 2667019303];
    let u64_be_u64: [u64; 5] = [
        2158770911501693864,
        57669768752051356,
        14834690014904699227,
        1061605113615837153,
        17929217830921720000,
    ];
    // Get seed elements from hex strings, set context
    let arr = get_seed_vec();
    let context = "some-test-app";
    // Create DRBG using SHA3-256, 64 bit counter, big-endian
    let mut drbg = Drbg::<Sha3_256, u64>::new_be(&arr, Some(context), true)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u32 matches expected output
    for i in 0..5 {
        let num = drbg.next_u32();
        assert_eq!(num, u64_be_u32[i]);
    }
    // Re-initialize DRBG
    let mut drbg = Drbg::<Sha3_256, u64>::new_be(&arr, Some(context), true)
        .expect("Should create new SC_DRBG instance");
    // Check that each generated u64 matches expected output
    for i in 0..5 {
        let num = drbg.next_u64();
        assert_eq!(num, u64_be_u64[i]);
    }
}
