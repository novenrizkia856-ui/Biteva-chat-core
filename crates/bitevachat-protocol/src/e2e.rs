//! End-to-end message encryption using ephemeral X25519 ECDH.
//!
//! Every message generates a fresh X25519 ephemeral keypair, performs
//! Diffie-Hellman with the recipient's X25519 public key (derived
//! from their Ed25519 verifying key), derives a symmetric session key
//! via HKDF-SHA256, and encrypts the plaintext with
//! XChaCha20-Poly1305.
//!
//! This provides lightweight forward secrecy: compromise of the
//! recipient's long-term key does not reveal messages encrypted with
//! already-discarded ephemeral keys.
//!
//! # Encryption flow (sender)
//!
//! ```text
//! 1. ephemeral ← X25519.generate()
//! 2. recipient_x25519 ← ed25519_pubkey_bytes → montgomery
//! 3. shared ← ECDH(ephemeral, recipient_x25519)
//! 4. session_key ← HKDF-SHA256(shared, salt="Bitevachat-E2E",
//!                               info=sender_pk||recipient_pk)
//! 5. nonce ← random 24 bytes
//! 6. ciphertext ← XChaCha20-Poly1305.encrypt(session_key, nonce, plaintext)
//! 7. return (ephemeral.public, nonce, ciphertext)
//! ```
//!
//! # Decryption flow (recipient)
//!
//! ```text
//! 1. recipient_x25519 ← ed25519_to_x25519(recipient_keypair)
//! 2. ephemeral_pub ← payload.ephemeral_pubkey
//! 3. shared ← ECDH(recipient_x25519, ephemeral_pub)
//! 4. session_key ← HKDF-SHA256(shared, same salt, same info)
//! 5. plaintext ← XChaCha20-Poly1305.decrypt(session_key, nonce, ciphertext)
//! ```

use bitevachat_crypto::aead::{decrypt_xchacha20, encrypt_xchacha20, generate_aead_nonce, AeadNonce};
use bitevachat_crypto::ecdh::{
    ecdh_derive_shared, ecdh_derive_shared_ephemeral, ed25519_pubkey_bytes_to_x25519,
    ed25519_to_x25519, X25519EphemeralSecret, X25519PublicKey,
};
use bitevachat_crypto::signing::Keypair;
use bitevachat_types::{BitevachatError, Result};

use crate::session::derive_session_key;

// ---------------------------------------------------------------------------
// EncryptedPayload
// ---------------------------------------------------------------------------

/// Encrypted message payload for E2E delivery.
///
/// Contains everything the recipient needs to derive the shared
/// secret and decrypt:
///
/// - The sender's ephemeral X25519 public key (used for ECDH).
/// - The 24-byte nonce for XChaCha20-Poly1305.
/// - The ciphertext with the 16-byte Poly1305 authentication tag
///   appended.
pub struct EncryptedPayload {
    /// Ephemeral X25519 public key generated per message (32 bytes).
    pub ephemeral_pubkey: [u8; 32],
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// Ciphertext with Poly1305 tag appended (length = plaintext + 16).
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypts a plaintext message for a specific recipient.
///
/// Generates a **fresh ephemeral X25519 keypair per call**, ensuring
/// that each message has a unique shared secret even if sender and
/// recipient are the same across calls.
///
/// # Parameters
///
/// - `sender_keypair` — the sender's Ed25519 signing keypair (used
///   to extract the sender public key for HKDF context binding).
/// - `recipient_pubkey` — the recipient's Ed25519 public key bytes
///   (32 bytes). Converted internally to X25519.
/// - `plaintext` — the message bytes to encrypt.
///
/// # Security properties
///
/// - Fresh ephemeral key per message (forward secrecy).
/// - Random 24-byte nonce per encryption.
/// - HKDF info binds the session key to both sender and recipient.
/// - Poly1305 tag detects any ciphertext tampering.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if the recipient public key is
///   invalid, ECDH fails, HKDF fails, or AEAD encryption fails.
pub fn encrypt_message(
    sender_keypair: &Keypair,
    recipient_pubkey: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedPayload> {
    // 1. Generate fresh ephemeral X25519 keypair.
    let ephemeral = X25519EphemeralSecret::generate();
    let ephemeral_pub = ephemeral.public_key();

    // 2. Convert recipient Ed25519 pubkey → X25519 pubkey.
    let recipient_x25519 = ed25519_pubkey_bytes_to_x25519(recipient_pubkey)?;

    // 3. ECDH: ephemeral_secret × recipient_x25519_pubkey → shared secret.
    let shared_secret = ecdh_derive_shared_ephemeral(ephemeral, &recipient_x25519);

    // 4. Build HKDF context: sender_ed25519_pubkey || recipient_ed25519_pubkey.
    let sender_pk = sender_keypair.public_key();
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(sender_pk.as_bytes());
    context.extend_from_slice(recipient_pubkey);

    // 5. Derive session key via HKDF.
    let session_key = derive_session_key(shared_secret.as_bytes(), &context)?;

    // 6. Generate random 24-byte nonce.
    let nonce = generate_aead_nonce();

    // 7. Encrypt with XChaCha20-Poly1305 (empty AAD; binding is in HKDF info).
    let encrypted = encrypt_xchacha20(
        session_key.symmetric_key(),
        &nonce,
        plaintext,
        &[],
    )?;

    Ok(EncryptedPayload {
        ephemeral_pubkey: *ephemeral_pub.as_bytes(),
        nonce: *nonce.as_bytes(),
        ciphertext: encrypted.ciphertext,
    })
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypts an [`EncryptedPayload`] received from a sender.
///
/// # Parameters
///
/// - `recipient_keypair` — the recipient's Ed25519 signing keypair.
///   Converted internally to X25519 for ECDH.
/// - `sender_pubkey` — the sender's Ed25519 public key bytes (32).
///   Used for HKDF context binding (must match what the sender used).
/// - `encrypted` — the encrypted payload containing the ephemeral
///   public key, nonce, and ciphertext.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if the recipient key conversion
///   fails, ECDH fails, HKDF fails, or AEAD decryption fails (wrong
///   key, tampered ciphertext, wrong sender/recipient).
pub fn decrypt_message(
    recipient_keypair: &Keypair,
    sender_pubkey: &[u8; 32],
    encrypted: &EncryptedPayload,
) -> Result<Vec<u8>> {
    // 1. Convert recipient Ed25519 keypair → X25519 static secret.
    let (recipient_x25519_secret, _) = ed25519_to_x25519(recipient_keypair)?;

    // 2. Extract ephemeral X25519 public key from payload.
    let ephemeral_x25519 = X25519PublicKey::from_bytes(encrypted.ephemeral_pubkey);

    // 3. ECDH: recipient_x25519_secret × ephemeral_pubkey → shared secret.
    let shared_secret = ecdh_derive_shared(&recipient_x25519_secret, &ephemeral_x25519);

    // 4. Build same HKDF context: sender_ed25519_pubkey || recipient_ed25519_pubkey.
    let recipient_pk = recipient_keypair.public_key();
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(sender_pubkey);
    context.extend_from_slice(recipient_pk.as_bytes());

    // 5. Derive session key via HKDF (same parameters as encrypt).
    let session_key = derive_session_key(shared_secret.as_bytes(), &context)?;

    // 6. Decrypt with XChaCha20-Poly1305.
    let aead_nonce = AeadNonce::from_bytes(encrypted.nonce);
    decrypt_xchacha20(
        session_key.symmetric_key(),
        &aead_nonce,
        &encrypted.ciphertext,
        &[],
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_keypair() -> Keypair {
        Keypair::from_seed(&[0xAA; 32])
    }

    fn bob_keypair() -> Keypair {
        Keypair::from_seed(&[0xBB; 32])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();
        let plaintext = b"hello from alice to bob";

        let payload = encrypt_message(&alice, bob.public_key().as_bytes(), plaintext)?;
        let decrypted = decrypt_message(&bob, alice.public_key().as_bytes(), &payload)?;

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn wrong_recipient_fails_decrypt() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();
        let charlie = Keypair::from_seed(&[0xCC; 32]);

        let payload = encrypt_message(&alice, bob.public_key().as_bytes(), b"secret")?;

        // Charlie tries to decrypt → must fail.
        let result = decrypt_message(&charlie, alice.public_key().as_bytes(), &payload);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();

        let mut payload = encrypt_message(&alice, bob.public_key().as_bytes(), b"secret")?;

        // Flip a bit in ciphertext.
        if let Some(byte) = payload.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_message(&bob, alice.public_key().as_bytes(), &payload);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn ephemeral_keys_unique_per_message() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();

        let p1 = encrypt_message(&alice, bob.public_key().as_bytes(), b"msg1")?;
        let p2 = encrypt_message(&alice, bob.public_key().as_bytes(), b"msg2")?;
        assert_ne!(p1.ephemeral_pubkey, p2.ephemeral_pubkey);
        Ok(())
    }

    #[test]
    fn nonces_unique_per_message() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();

        let p1 = encrypt_message(&alice, bob.public_key().as_bytes(), b"msg1")?;
        let p2 = encrypt_message(&alice, bob.public_key().as_bytes(), b"msg2")?;
        assert_ne!(p1.nonce, p2.nonce);
        Ok(())
    }

    #[test]
    fn empty_plaintext_roundtrip() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();

        let payload = encrypt_message(&alice, bob.public_key().as_bytes(), b"")?;
        assert_eq!(payload.ciphertext.len(), 16); // tag only

        let decrypted = decrypt_message(&bob, alice.public_key().as_bytes(), &payload)?;
        assert!(decrypted.is_empty());
        Ok(())
    }

    #[test]
    fn wrong_sender_pubkey_in_context_fails() -> std::result::Result<(), BitevachatError> {
        let alice = alice_keypair();
        let bob = bob_keypair();
        let charlie = Keypair::from_seed(&[0xCC; 32]);

        let payload = encrypt_message(&alice, bob.public_key().as_bytes(), b"secret")?;

        // Bob tries to decrypt but passes Charlie's pubkey as sender → context mismatch.
        let result = decrypt_message(&bob, charlie.public_key().as_bytes(), &payload);
        assert!(result.is_err());
        Ok(())
    }
}