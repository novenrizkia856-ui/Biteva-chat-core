//! Integration tests for Bitevachat E2E encryption.
//!
//! All tests use deterministic Ed25519 keypairs (fixed seeds).
//! Ephemeral key and nonce uniqueness tests rely on the OS CSPRNG
//! producing distinct values across calls (which is guaranteed for
//! correctly functioning entropy sources).

use bitevachat_crypto::signing::Keypair;
use bitevachat_types::BitevachatError;

use bitevachat_protocol::e2e::{decrypt_message, encrypt_message};

// ---------------------------------------------------------------------------
// Keypairs
// ---------------------------------------------------------------------------

fn alice() -> Keypair {
    Keypair::from_seed(&[0xAA; 32])
}

fn bob() -> Keypair {
    Keypair::from_seed(&[0xBB; 32])
}

fn charlie() -> Keypair {
    Keypair::from_seed(&[0xCC; 32])
}

// ---------------------------------------------------------------------------
// 1. Encrypt → Decrypt roundtrip
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip_text() -> std::result::Result<(), BitevachatError> {
    let plaintext = b"Hello Bob, this is Alice speaking.";
    let payload = encrypt_message(&alice(), bob().public_key().as_bytes(), plaintext)?;
    let decrypted = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload)?;
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    Ok(())
}

#[test]
fn encrypt_decrypt_roundtrip_empty() -> std::result::Result<(), BitevachatError> {
    let payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"")?;
    let decrypted = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload)?;
    assert!(decrypted.is_empty());
    Ok(())
}

#[test]
fn encrypt_decrypt_roundtrip_large() -> std::result::Result<(), BitevachatError> {
    let plaintext = vec![0x42u8; 65536]; // 64 KiB
    let payload = encrypt_message(&alice(), bob().public_key().as_bytes(), &plaintext)?;
    let decrypted = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn bidirectional_communication() -> std::result::Result<(), BitevachatError> {
    // Alice → Bob
    let p1 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"from alice")?;
    let d1 = decrypt_message(&bob(), alice().public_key().as_bytes(), &p1)?;
    assert_eq!(d1, b"from alice");

    // Bob → Alice
    let p2 = encrypt_message(&bob(), alice().public_key().as_bytes(), b"from bob")?;
    let d2 = decrypt_message(&alice(), bob().public_key().as_bytes(), &p2)?;
    assert_eq!(d2, b"from bob");
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Wrong recipient key → fail
// ---------------------------------------------------------------------------

#[test]
fn wrong_recipient_cannot_decrypt() -> std::result::Result<(), BitevachatError> {
    let payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"secret")?;

    // Charlie tries to decrypt a message intended for Bob.
    let result = decrypt_message(&charlie(), alice().public_key().as_bytes(), &payload);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn wrong_sender_pubkey_in_decrypt_fails() -> std::result::Result<(), BitevachatError> {
    let payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"secret")?;

    // Bob tries to decrypt but claims the sender is Charlie.
    // HKDF context mismatch → different session key → AEAD failure.
    let result = decrypt_message(&bob(), charlie().public_key().as_bytes(), &payload);
    assert!(result.is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Tampered ciphertext → fail
// ---------------------------------------------------------------------------

#[test]
fn tampered_ciphertext_detected() -> std::result::Result<(), BitevachatError> {
    let mut payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"secret")?;

    // Flip first byte of ciphertext.
    if let Some(byte) = payload.ciphertext.first_mut() {
        *byte ^= 0xFF;
    }

    let result = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn tampered_nonce_detected() -> std::result::Result<(), BitevachatError> {
    let mut payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"secret")?;

    // Flip first byte of nonce.
    payload.nonce[0] ^= 0xFF;

    let result = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn tampered_ephemeral_pubkey_detected() -> std::result::Result<(), BitevachatError> {
    let mut payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"secret")?;

    // Flip first byte of ephemeral pubkey → different shared secret.
    payload.ephemeral_pubkey[0] ^= 0xFF;

    let result = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn truncated_ciphertext_detected() -> std::result::Result<(), BitevachatError> {
    let mut payload = encrypt_message(&alice(), bob().public_key().as_bytes(), b"secret msg")?;

    // Remove last byte (part of Poly1305 tag).
    payload.ciphertext.pop();

    let result = decrypt_message(&bob(), alice().public_key().as_bytes(), &payload);
    assert!(result.is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Ephemeral key uniqueness
// ---------------------------------------------------------------------------

#[test]
fn ephemeral_pubkeys_differ_per_message() -> std::result::Result<(), BitevachatError> {
    let p1 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"msg1")?;
    let p2 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"msg1")?;

    // Even with identical plaintext, ephemeral keys must differ.
    assert_ne!(
        p1.ephemeral_pubkey, p2.ephemeral_pubkey,
        "ephemeral pubkeys must be unique per message"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Nonce uniqueness
// ---------------------------------------------------------------------------

#[test]
fn nonces_differ_per_message() -> std::result::Result<(), BitevachatError> {
    let p1 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"msg1")?;
    let p2 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"msg1")?;

    assert_ne!(
        p1.nonce, p2.nonce,
        "AEAD nonces must be unique per message"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Additional: ciphertext differs for same plaintext
// ---------------------------------------------------------------------------

#[test]
fn ciphertext_differs_for_same_plaintext() -> std::result::Result<(), BitevachatError> {
    let p1 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"same")?;
    let p2 = encrypt_message(&alice(), bob().public_key().as_bytes(), b"same")?;

    // Different ephemeral key → different shared secret → different ciphertext.
    assert_ne!(p1.ciphertext, p2.ciphertext);
    Ok(())
}