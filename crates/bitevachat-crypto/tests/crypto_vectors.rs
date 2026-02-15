//! Known-vector tests for cryptographic primitives.
//!
//! Test vectors sourced from:
//! - Ed25519: RFC 8032 §7.1 — TEST 1
//! - SHA3-256: NIST FIPS 202 examples
//! - X25519:  RFC 7748 §6.1
//! - AEAD:    Deterministic roundtrip (XChaCha20-Poly1305)
//! - Argon2:  Deterministic output stability
//! - Checksum: Roundtrip and Bech32

use bitevachat_crypto::aead::{
    decrypt_xchacha20, encrypt_xchacha20, generate_aead_nonce, AeadNonce,
};
use bitevachat_crypto::checksum::{append_checksum, verify_checksum, AddressWithChecksum};
use bitevachat_crypto::ecdh::{
    ecdh_derive_shared, ed25519_to_x25519, X25519PublicKey, X25519StaticSecret,
};
use bitevachat_crypto::hash::{compute_message_id, sha3_256};
use bitevachat_crypto::kdf::{argon2id_derive_key, Argon2Params};
use bitevachat_crypto::signing::{pubkey_to_address, verify, Keypair};
use bitevachat_types::{Address, BitevachatError, Nonce, Timestamp};

// ===================================================================
// Ed25519 — RFC 8032 §7.1, TEST 1 (empty message)
// ===================================================================

#[test]
fn ed25519_rfc8032_test1_sign_verify() -> std::result::Result<(), BitevachatError> {
    // RFC 8032 TEST 1 — seed (private key), public key, signature
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let expected_pubkey: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0xf4, 0xa1,
        0x84, 0x46, 0xb7, 0xc8, 0xc7, 0xa8, 0xb4, 0x1a,
    ];
    let expected_sig: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    ];

    let kp = Keypair::from_seed(&seed);
    let pk = kp.public_key();

    // Verify public key derivation matches RFC vector.
    assert_eq!(pk.as_bytes(), &expected_pubkey);

    // Sign empty message.
    let sig = kp.sign(b"");
    assert_eq!(sig.as_bytes(), &expected_sig);

    // Verify the signature.
    verify(&pk, b"", &sig)?;
    Ok(())
}

#[test]
fn ed25519_wrong_message_rejects() {
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let kp = Keypair::from_seed(&seed);
    let pk = kp.public_key();
    let sig = kp.sign(b"");

    // Signature for empty message must not verify against "x".
    assert!(verify(&pk, b"x", &sig).is_err());
}

// ===================================================================
// SHA3-256 — NIST FIPS 202
// ===================================================================

#[test]
fn sha3_256_nist_empty() {
    let expected: [u8; 32] = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
    ];
    assert_eq!(sha3_256(b""), expected);
}

#[test]
fn sha3_256_nist_abc() {
    let expected: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    ];
    assert_eq!(sha3_256(b"abc"), expected);
}

// ===================================================================
// X25519 — RFC 7748 §6.1
// ===================================================================

#[test]
fn x25519_rfc7748_shared_secret() {
    // Alice's key material.
    let alice_private: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ];
    let alice_expected_pub: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    ];

    // Bob's key material.
    let bob_private: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    ];
    let bob_expected_pub: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];

    // Expected shared secret.
    let expected_shared: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    ];

    // Construct secrets via x25519-dalek (clamping is internal).
    let alice_secret = X25519StaticSecret::from_raw(alice_private);
    let bob_secret = X25519StaticSecret::from_raw(bob_private);
    let alice_pub = alice_secret.public_key();
    let bob_pub = bob_secret.public_key();

    // Verify public key derivation.
    assert_eq!(alice_pub.as_bytes(), &alice_expected_pub);
    assert_eq!(bob_pub.as_bytes(), &bob_expected_pub);

    // Both parties derive the same shared secret.
    let shared_ab = ecdh_derive_shared(&alice_secret, &bob_pub);
    let shared_ba = ecdh_derive_shared(&bob_secret, &alice_pub);
    assert_eq!(shared_ab.as_bytes(), &expected_shared);
    assert_eq!(shared_ba.as_bytes(), &expected_shared);
}

// ===================================================================
// XChaCha20-Poly1305 AEAD — roundtrip
// ===================================================================

#[test]
fn aead_encrypt_decrypt_roundtrip() -> std::result::Result<(), BitevachatError> {
    let key = [0x42u8; 32];
    let nonce = AeadNonce::from_bytes([0x01; 24]);
    let plaintext = b"RFC test roundtrip";
    let aad = b"authenticated header";

    let enc = encrypt_xchacha20(&key, &nonce, plaintext, aad)?;
    let dec = decrypt_xchacha20(&key, &enc.nonce, &enc.ciphertext, aad)?;
    assert_eq!(dec.as_slice(), plaintext.as_slice());
    Ok(())
}

#[test]
fn aead_deterministic_ciphertext() -> std::result::Result<(), BitevachatError> {
    let key = [0xCC; 32];
    let nonce = AeadNonce::from_bytes([0xDD; 24]);
    let msg = b"determinism";

    let enc1 = encrypt_xchacha20(&key, &nonce, msg, b"")?;
    let enc2 = encrypt_xchacha20(&key, &nonce, msg, b"")?;
    assert_eq!(enc1.ciphertext, enc2.ciphertext);
    Ok(())
}

#[test]
fn aead_tampered_ciphertext_rejected() -> std::result::Result<(), BitevachatError> {
    let key = [0xEE; 32];
    let nonce = generate_aead_nonce();

    let enc = encrypt_xchacha20(&key, &nonce, b"payload", b"")?;
    let mut bad = enc.ciphertext.clone();
    if let Some(b) = bad.first_mut() {
        *b ^= 0xFF;
    }
    assert!(decrypt_xchacha20(&key, &nonce, &bad, b"").is_err());
    Ok(())
}

// ===================================================================
// Argon2id — determinism
// ===================================================================

#[test]
fn argon2id_deterministic() -> std::result::Result<(), BitevachatError> {
    let params = Argon2Params {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let password = b"test_password";
    let salt = b"0123456789abcdef";

    let k1 = argon2id_derive_key(password, salt, &params)?;
    let k2 = argon2id_derive_key(password, salt, &params)?;
    assert_eq!(k1.as_bytes(), k2.as_bytes());
    assert_ne!(k1.as_bytes(), &[0u8; 32]);
    Ok(())
}

#[test]
fn argon2id_different_passwords_different_keys() -> std::result::Result<(), BitevachatError> {
    let params = Argon2Params {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let salt = b"0123456789abcdef";

    let k1 = argon2id_derive_key(b"alpha", salt, &params)?;
    let k2 = argon2id_derive_key(b"bravo", salt, &params)?;
    assert_ne!(k1.as_bytes(), k2.as_bytes());
    Ok(())
}

// ===================================================================
// Checksum — roundtrip & Bech32
// ===================================================================

#[test]
fn checksum_roundtrip() -> std::result::Result<(), BitevachatError> {
    let hash = [0x99; 32];
    let addr = append_checksum(&hash);
    verify_checksum(&addr.as_bytes())?;
    assert_eq!(addr.hash(), &hash);
    Ok(())
}

#[test]
fn checksum_corrupt_detected() {
    let addr = append_checksum(&[0x88; 32]);
    let mut bytes = addr.as_bytes();
    bytes[34] ^= 0x01;
    assert!(verify_checksum(&bytes).is_err());
}

#[test]
fn bech32_roundtrip() -> std::result::Result<(), BitevachatError> {
    let hash = [0x77; 32];
    let addr = append_checksum(&hash);
    let encoded = addr.to_bech32()?;
    let decoded = AddressWithChecksum::from_bech32(&encoded)?;
    assert_eq!(decoded, addr);
    Ok(())
}

// ===================================================================
// pubkey_to_address — consistency
// ===================================================================

#[test]
fn pubkey_to_address_deterministic() {
    let seed = [0x11; 32];
    let kp = Keypair::from_seed(&seed);
    let pk = kp.public_key();
    let a1 = pubkey_to_address(&pk);
    let a2 = pubkey_to_address(&pk);
    assert_eq!(a1, a2);

    // Address must equal SHA3-256 of the public key bytes.
    let expected = sha3_256(pk.as_bytes());
    assert_eq!(a1.as_bytes(), &expected);
}

// ===================================================================
// compute_message_id — determinism
// ===================================================================

#[test]
fn message_id_deterministic() {
    let sender = Address::new([0x01; 32]);
    let ts = Timestamp::now();
    let nonce = Nonce::new([0xAA; 12]);

    let id1 = compute_message_id(&sender, &ts, &nonce);
    let id2 = compute_message_id(&sender, &ts, &nonce);
    assert_eq!(id1, id2);
}

// ===================================================================
// Ed25519 → X25519 conversion — consistency
// ===================================================================

#[test]
fn ed25519_to_x25519_conversion_consistent()
    -> std::result::Result<(), BitevachatError>
{
    let seed = [0x33; 32];
    let kp = Keypair::from_seed(&seed);

    let (sec1, pub1) = ed25519_to_x25519(&kp)?;
    let (_, pub2) = ed25519_to_x25519(&kp)?;

    // Same seed → same X25519 public key.
    assert_eq!(pub1.as_bytes(), pub2.as_bytes());

    // Public key derived from secret matches.
    assert_eq!(sec1.public_key().as_bytes(), pub1.as_bytes());
    Ok(())
}
