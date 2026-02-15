//! XChaCha20-Poly1305 authenticated encryption with associated data.
//!
//! All symmetric encryption in Bitevachat uses XChaCha20-Poly1305 AEAD
//! with 192-bit (24-byte) nonces. Nonces are generated from OS entropy
//! and **must never be reused** with the same key.

use bitevachat_types::{BitevachatError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

// ---------------------------------------------------------------------------
// AeadNonce
// ---------------------------------------------------------------------------

/// 192-bit (24-byte) nonce for XChaCha20-Poly1305.
///
/// Distinct from the 96-bit [`bitevachat_types::Nonce`] used for
/// message-level replay detection. This nonce is specific to the
/// AEAD cipher and must be unique per encryption operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadNonce([u8; 24]);

impl AeadNonce {
    /// Fixed byte length of an XChaCha20-Poly1305 nonce.
    pub const LEN: usize = 24;

    /// Creates an [`AeadNonce`] from raw bytes.
    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 24-byte array.
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

/// Generates a fresh 192-bit random nonce from OS entropy.
///
/// Each call produces a unique nonce suitable for a single
/// XChaCha20-Poly1305 encryption. The 192-bit space makes
/// accidental collision negligible.
pub fn generate_aead_nonce() -> AeadNonce {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    AeadNonce(bytes)
}

// ---------------------------------------------------------------------------
// CiphertextWithTag
// ---------------------------------------------------------------------------

/// Bundle of nonce + ciphertext produced by [`encrypt_xchacha20`].
///
/// The `ciphertext` field includes the 16-byte Poly1305 authentication
/// tag appended by the AEAD cipher.
#[derive(Clone, Debug)]
pub struct CiphertextWithTag {
    /// Nonce used for this encryption. Must be transmitted alongside
    /// the ciphertext so the recipient can decrypt.
    pub nonce: AeadNonce,
    /// Encrypted payload with the Poly1305 tag appended
    /// (length = plaintext length + 16).
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

/// Encrypts `plaintext` with XChaCha20-Poly1305.
///
/// # Parameters
///
/// - `key` — 256-bit symmetric key.
/// - `nonce` — 192-bit nonce (must be unique per key; use
///   [`generate_aead_nonce`]).
/// - `plaintext` — data to encrypt.
/// - `aad` — additional authenticated data. Authenticated but **not**
///   encrypted. Pass `&[]` if unused.
///
/// # Returns
///
/// A [`CiphertextWithTag`] containing the nonce and the ciphertext
/// with the appended 16-byte authentication tag.
pub fn encrypt_xchacha20(
    key: &[u8; 32],
    nonce: &AeadNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<CiphertextWithTag> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(&nonce.0);
    let payload = Payload { msg: plaintext, aad };

    let ciphertext = cipher.encrypt(xnonce, payload).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("XChaCha20-Poly1305 encryption failed: {e}"),
        }
    })?;

    Ok(CiphertextWithTag {
        nonce: *nonce,
        ciphertext,
    })
}

/// Decrypts `ciphertext` with XChaCha20-Poly1305.
///
/// # Parameters
///
/// - `key` — 256-bit symmetric key (must match the one used for encryption).
/// - `nonce` — 192-bit nonce used during encryption.
/// - `ciphertext` — encrypted data with the Poly1305 tag appended.
/// - `aad` — additional authenticated data (must match what was passed
///   to [`encrypt_xchacha20`]).
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if the tag verification
/// fails (wrong key, wrong nonce, tampered ciphertext, or wrong AAD).
pub fn decrypt_xchacha20(
    key: &[u8; 32],
    nonce: &AeadNonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(&nonce.0);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher.decrypt(xnonce, payload).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("XChaCha20-Poly1305 decryption failed: {e}"),
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() -> std::result::Result<(), BitevachatError> {
        let key = [0x42u8; 32];
        let nonce = generate_aead_nonce();
        let plaintext = b"hello bitevachat";
        let aad = b"metadata";

        let encrypted = encrypt_xchacha20(&key, &nonce, plaintext, aad)?;
        assert_ne!(encrypted.ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16);

        let decrypted = decrypt_xchacha20(&key, &encrypted.nonce, &encrypted.ciphertext, aad)?;
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn empty_plaintext_roundtrip() -> std::result::Result<(), BitevachatError> {
        let key = [0x01u8; 32];
        let nonce = generate_aead_nonce();

        let encrypted = encrypt_xchacha20(&key, &nonce, b"", b"")?;
        assert_eq!(encrypted.ciphertext.len(), 16); // tag only

        let decrypted = decrypt_xchacha20(&key, &nonce, &encrypted.ciphertext, b"")?;
        assert!(decrypted.is_empty());
        Ok(())
    }

    #[test]
    fn wrong_key_fails_decrypt() -> std::result::Result<(), BitevachatError> {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = generate_aead_nonce();

        let encrypted = encrypt_xchacha20(&key, &nonce, b"secret", b"")?;
        let result = decrypt_xchacha20(&wrong_key, &nonce, &encrypted.ciphertext, b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn wrong_nonce_fails_decrypt() -> std::result::Result<(), BitevachatError> {
        let key = [0x42u8; 32];
        let nonce = generate_aead_nonce();
        let wrong_nonce = generate_aead_nonce();

        let encrypted = encrypt_xchacha20(&key, &nonce, b"secret", b"")?;
        let result = decrypt_xchacha20(&key, &wrong_nonce, &encrypted.ciphertext, b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn wrong_aad_fails_decrypt() -> std::result::Result<(), BitevachatError> {
        let key = [0x42u8; 32];
        let nonce = generate_aead_nonce();

        let encrypted = encrypt_xchacha20(&key, &nonce, b"secret", b"correct aad")?;
        let result = decrypt_xchacha20(&key, &nonce, &encrypted.ciphertext, b"wrong aad");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() -> std::result::Result<(), BitevachatError> {
        let key = [0x42u8; 32];
        let nonce = generate_aead_nonce();

        let encrypted = encrypt_xchacha20(&key, &nonce, b"secret", b"")?;
        let mut tampered = encrypted.ciphertext.clone();
        if let Some(byte) = tampered.first_mut() {
            *byte ^= 0xFF;
        }
        let result = decrypt_xchacha20(&key, &nonce, &tampered, b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn deterministic_with_same_inputs() -> std::result::Result<(), BitevachatError> {
        let key = [0xAA; 32];
        let nonce = AeadNonce::from_bytes([0xBB; 24]);
        let plaintext = b"determinism test";
        let aad = b"aad";

        let enc1 = encrypt_xchacha20(&key, &nonce, plaintext, aad)?;
        let enc2 = encrypt_xchacha20(&key, &nonce, plaintext, aad)?;
        assert_eq!(enc1.ciphertext, enc2.ciphertext);
        Ok(())
    }

    #[test]
    fn generated_nonces_are_unique() {
        let n1 = generate_aead_nonce();
        let n2 = generate_aead_nonce();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }
}
