//! Session key derivation from ECDH shared secrets.
//!
//! A [`SessionKey`] is derived via HKDF-SHA256 from a raw X25519
//! shared secret and a context string that binds the key to the
//! specific sender/recipient pair. The raw shared secret is **never**
//! used directly as a symmetric key.
//!
//! # Key derivation parameters
//!
//! - **IKM**: X25519 shared secret (32 bytes).
//! - **Salt**: `b"Bitevachat-E2E"` (fixed domain separator).
//! - **Info**: caller-supplied context (typically
//!   `sender_pubkey || recipient_pubkey`).
//! - **Output**: 32 bytes (one XChaCha20-Poly1305 key).

use bitevachat_crypto::hkdf::hkdf_sha256;
use bitevachat_types::{BitevachatError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed HKDF salt for E2E session key derivation.
///
/// Acts as a domain separator, ensuring that keys derived for
/// Bitevachat E2E encryption are cryptographically independent from
/// keys derived with the same shared secret for other purposes.
const E2E_SALT: &[u8] = b"Bitevachat-E2E";

// ---------------------------------------------------------------------------
// SessionKey
// ---------------------------------------------------------------------------

/// Symmetric session key derived from an ECDH shared secret.
///
/// Contains the 32-byte XChaCha20-Poly1305 key and the context
/// information used during derivation. Both fields are zeroized on
/// drop.
pub struct SessionKey {
    /// 256-bit symmetric key for AEAD.
    symmetric_key: [u8; 32],
    /// Context info used during HKDF derivation (for auditability).
    context: Vec<u8>,
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.symmetric_key.zeroize();
        self.context.zeroize();
    }
}

// SessionKey does not implement Clone/Debug to prevent leakage.

impl SessionKey {
    /// Returns the 32-byte symmetric key.
    pub fn symmetric_key(&self) -> &[u8; 32] {
        &self.symmetric_key
    }

    /// Returns the context info used during derivation.
    pub fn context(&self) -> &[u8] {
        &self.context
    }
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// Derives a 32-byte session key from an ECDH shared secret.
///
/// # Parameters
///
/// - `shared_secret` — raw X25519 shared secret (32 bytes). Must
///   **not** be used directly as a symmetric key.
/// - `context_info` — application-specific context (e.g.
///   `sender_pubkey || recipient_pubkey`). Bound into the HKDF `info`
///   parameter.
///
/// # Process
///
/// ```text
/// session_key = HKDF-SHA256(
///     IKM  = shared_secret,
///     salt = b"Bitevachat-E2E",
///     info = context_info,
///     L    = 32
/// )
/// ```
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if HKDF derivation fails.
pub fn derive_session_key(
    shared_secret: &[u8],
    context_info: &[u8],
) -> Result<SessionKey> {
    let hkdf_output = hkdf_sha256(shared_secret, E2E_SALT, context_info, 32)?;

    let output_bytes = hkdf_output.as_bytes();
    if output_bytes.len() != 32 {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "HKDF output length mismatch: expected 32, got {}",
                output_bytes.len()
            ),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(output_bytes);

    Ok(SessionKey {
        symmetric_key: key,
        context: context_info.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let shared = [0x42u8; 32];
        let ctx = b"sender||recipient";

        let sk1 = derive_session_key(&shared, ctx)?;
        let sk2 = derive_session_key(&shared, ctx)?;
        assert_eq!(sk1.symmetric_key(), sk2.symmetric_key());
        Ok(())
    }

    #[test]
    fn different_shared_secret_different_key() -> std::result::Result<(), BitevachatError> {
        let ctx = b"ctx";
        let sk1 = derive_session_key(&[0x01; 32], ctx)?;
        let sk2 = derive_session_key(&[0x02; 32], ctx)?;
        assert_ne!(sk1.symmetric_key(), sk2.symmetric_key());
        Ok(())
    }

    #[test]
    fn different_context_different_key() -> std::result::Result<(), BitevachatError> {
        let shared = [0x42u8; 32];
        let sk1 = derive_session_key(&shared, b"context-a")?;
        let sk2 = derive_session_key(&shared, b"context-b")?;
        assert_ne!(sk1.symmetric_key(), sk2.symmetric_key());
        Ok(())
    }

    #[test]
    fn key_is_non_zero() -> std::result::Result<(), BitevachatError> {
        let sk = derive_session_key(&[0x42; 32], b"ctx")?;
        assert_ne!(sk.symmetric_key(), &[0u8; 32]);
        Ok(())
    }

    #[test]
    fn context_stored_correctly() -> std::result::Result<(), BitevachatError> {
        let ctx = b"my-context-info";
        let sk = derive_session_key(&[0x42; 32], ctx)?;
        assert_eq!(sk.context(), ctx.as_slice());
        Ok(())
    }
}