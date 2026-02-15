//! BIP39 known test vectors and end-to-end HD derivation tests.
//!
//! Test vectors sourced from:
//! - BIP39: <https://github.com/trezor/python-mnemonic/blob/master/vectors.json>
//! - SLIP-0010: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>

use bitevachat_crypto::hd_derive::{derive_ed25519_keypair, derive_x25519_keypair};
use bitevachat_crypto::mnemonic::{
    entropy_to_mnemonic, mnemonic_to_seed, validate_mnemonic, Seed,
};
use bitevachat_crypto::signing::verify;
use bitevachat_types::BitevachatError;

// ===================================================================
// Helper
// ===================================================================

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    let chars: Vec<char> = clean.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        let high = chars[i].to_digit(16).unwrap_or(0) as u8;
        let low = chars[i + 1].to_digit(16).unwrap_or(0) as u8;
        bytes.push((high << 4) | low);
        i += 2;
    }
    bytes
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn entropy_to_array(hex: &str) -> [u8; 32] {
    let v = hex_to_bytes(hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    arr
}

// ===================================================================
// BIP39 Test Vector 1: all-zero entropy (256 bits)
// Source: TREZOR reference vectors
// Passphrase: "TREZOR"
// ===================================================================

#[test]
fn bip39_vector1_entropy_to_mnemonic() -> std::result::Result<(), BitevachatError> {
    let entropy = entropy_to_array(
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let mnemonic = entropy_to_mnemonic(&entropy)?;

    let expected = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";
    assert_eq!(mnemonic.as_str(), expected);
    Ok(())
}

#[test]
fn bip39_vector1_validate() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";
    validate_mnemonic(mnemonic)?;
    Ok(())
}

#[test]
fn bip39_vector1_seed() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let seed = mnemonic_to_seed(mnemonic, "TREZOR")?;

    let expected = hex_to_bytes(
        "bda85446c68413707090a52022edd26a1c946229\
         5029f2e60cd7c4f2bbd3097170af7a4d73245caf\
         a9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d6\
         8f92fcc8",
    );
    assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
    Ok(())
}

// ===================================================================
// BIP39 Test Vector 2: all-0x7F entropy (256 bits)
// Source: TREZOR reference vectors
// Passphrase: "TREZOR"
// ===================================================================

#[test]
fn bip39_vector2_entropy_to_mnemonic() -> std::result::Result<(), BitevachatError> {
    let entropy = entropy_to_array(
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    );
    let mnemonic = entropy_to_mnemonic(&entropy)?;

    let expected = "legal winner thank year wave sausage worth useful \
                    legal winner thank year wave sausage worth useful \
                    legal winner thank year wave sausage worth title";
    assert_eq!(mnemonic.as_str(), expected);
    Ok(())
}

#[test]
fn bip39_vector2_seed() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "legal winner thank year wave sausage worth useful \
                    legal winner thank year wave sausage worth useful \
                    legal winner thank year wave sausage worth title";

    let seed = mnemonic_to_seed(mnemonic, "TREZOR")?;

    let expected = hex_to_bytes(
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9\
         dda30cd63699232578480a4021b146ad717fbb7e\
         451ce9eb835f43620bf5c514db0f8add49f5d121\
         449d3e87",
    );
    assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
    Ok(())
}

// ===================================================================
// BIP39 Test Vector 3: all-0xFF entropy (256 bits)
// Source: TREZOR reference vectors
// Passphrase: "TREZOR"
// ===================================================================

#[test]
fn bip39_vector3_entropy_to_mnemonic() -> std::result::Result<(), BitevachatError> {
    let entropy = entropy_to_array(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let mnemonic = entropy_to_mnemonic(&entropy)?;

    // Last word depends on SHA-256(0xFF × 32) checksum.
    let expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                    zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    assert_eq!(mnemonic.as_str(), expected);
    Ok(())
}

#[test]
fn bip39_vector3_seed() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                    zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

    let seed = mnemonic_to_seed(mnemonic, "TREZOR")?;

    let expected = hex_to_bytes(
        "dd48c104698c30cfe2b6142103248622fb7bb0ff\
         692eebb00089b32d22484e1613912f0a5b694407\
         be899ffd31ed3992c456cdf60f5d4564b8ba3f05\
         a69890ad",
    );
    assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
    Ok(())
}

// ===================================================================
// BIP39 Test Vector 4: realistic mixed entropy (256 bits)
// Source: TREZOR reference vectors
// entropy: 68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c
// ===================================================================

#[test]
fn bip39_vector4_entropy_to_mnemonic() -> std::result::Result<(), BitevachatError> {
    let entropy = entropy_to_array(
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    );
    let mnemonic = entropy_to_mnemonic(&entropy)?;

    let expected = "hamster diagram private dutch cause delay private meat \
                    slide toddler razor book happy fancy gospel tennis maple \
                    dilemma loan word shrug inflict delay length";
    assert_eq!(mnemonic.as_str(), expected);
    Ok(())
}

#[test]
fn bip39_vector4_seed() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "hamster diagram private dutch cause delay private meat \
                    slide toddler razor book happy fancy gospel tennis maple \
                    dilemma loan word shrug inflict delay length";

    let seed = mnemonic_to_seed(mnemonic, "TREZOR")?;

    let expected = hex_to_bytes(
        "64c87cde7e12ecf6704ab95bb1408bef047c22db\
         4cc7491c4271d170a1b213d20b385bc1588d9c7b\
         38f1b39d415665b8a9030c9ec653d75e65f847d8\
         fc1fc440",
    );
    assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
    Ok(())
}

// ===================================================================
// End-to-end: mnemonic → seed → HD derive → sign/verify
// ===================================================================

#[test]
fn end_to_end_mnemonic_to_signing() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    validate_mnemonic(mnemonic)?;
    let seed = mnemonic_to_seed(mnemonic, "")?;
    let keypair = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/0'")?;

    // Sign and verify a message.
    let message = b"bitevachat end-to-end test";
    let sig = keypair.sign(message);
    verify(&keypair.public_key(), message, &sig)?;
    Ok(())
}

#[test]
fn end_to_end_deterministic() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let seed1 = mnemonic_to_seed(mnemonic, "pass")?;
    let seed2 = mnemonic_to_seed(mnemonic, "pass")?;
    let kp1 = derive_ed25519_keypair(&seed1, "m/44'/0'/0'/0'/0'")?;
    let kp2 = derive_ed25519_keypair(&seed2, "m/44'/0'/0'/0'/0'")?;

    assert_eq!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    Ok(())
}

#[test]
fn end_to_end_x25519_derivation() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let seed = mnemonic_to_seed(mnemonic, "")?;
    let ed_kp = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/0'")?;
    let x_kp = derive_x25519_keypair(&ed_kp)?;

    // X25519 public key derived from secret must match.
    assert_eq!(
        x_kp.secret.public_key().as_bytes(),
        x_kp.public.as_bytes()
    );
    Ok(())
}

// ===================================================================
// Validation edge cases
// ===================================================================

#[test]
fn validate_rejects_23_words() {
    let phrase = "abandon ".repeat(23).trim().to_string();
    assert!(validate_mnemonic(&phrase).is_err());
}

#[test]
fn validate_rejects_25_words() {
    let phrase = "abandon ".repeat(25).trim().to_string();
    assert!(validate_mnemonic(&phrase).is_err());
}

#[test]
fn validate_rejects_invalid_word() {
    let mut words: Vec<&str> = vec!["abandon"; 23];
    words.push("art");
    words[10] = "invalidxyz";
    let phrase = words.join(" ");
    assert!(validate_mnemonic(&phrase).is_err());
}

#[test]
fn validate_rejects_empty() {
    assert!(validate_mnemonic("").is_err());
}

// ===================================================================
// HD derivation path edge cases
// ===================================================================

#[test]
fn hd_rejects_non_hardened_path() {
    let seed = Seed::from_bytes([0x42; 64]);
    let result = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0/0'");
    assert!(result.is_err());
}

#[test]
fn hd_rejects_invalid_path_prefix() {
    let seed = Seed::from_bytes([0x42; 64]);
    let result = derive_ed25519_keypair(&seed, "44'/0'/0'");
    assert!(result.is_err());
}

#[test]
fn different_passphrase_different_seed() -> std::result::Result<(), BitevachatError> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let seed_a = mnemonic_to_seed(mnemonic, "alpha")?;
    let seed_b = mnemonic_to_seed(mnemonic, "bravo")?;
    assert_ne!(seed_a.as_bytes(), seed_b.as_bytes());

    let kp_a = derive_ed25519_keypair(&seed_a, "m/44'/0'/0'")?;
    let kp_b = derive_ed25519_keypair(&seed_b, "m/44'/0'/0'")?;
    assert_ne!(kp_a.public_key().as_bytes(), kp_b.public_key().as_bytes());
    Ok(())
}