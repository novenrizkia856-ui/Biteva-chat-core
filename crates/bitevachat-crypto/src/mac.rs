//! HMAC-SHA256 message authentication codes.
//!
//! Provides keyed HMAC-SHA256 computation and verification for
//! tamper detection. Used by the storage engine to authenticate
//! encrypted records before decryption (Encrypt-then-MAC).

use bitevachat_types::{BitevachatError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Fixed output length of HMAC-SHA256 in bytes.
pub const HMAC_SHA256_LEN: usize = 32;

/// Computes HMAC-SHA256 over `data` using `key`.
///
/// # Parameters
///
/// - `key` — HMAC key (any length; 32 bytes recommended).
/// - `data` — data to authenticate.
///
/// # Returns
///
/// A 32-byte HMAC-SHA256 tag.
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if HMAC initialisation fails
/// (should not happen with SHA-256, but we avoid `unwrap`).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("HMAC-SHA256 key init failed: {e}"),
        }
    })?;
    mac.update(data);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    Ok(output)
}

/// Verifies an HMAC-SHA256 tag in constant time.
///
/// # Parameters
///
/// - `key` — HMAC key (must match the one used for [`hmac_sha256`]).
/// - `data` — data that was authenticated.
/// - `expected` — the 32-byte tag to verify against.
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if:
/// - HMAC initialisation fails, or
/// - the computed tag does not match `expected` (tamper detected).
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8; 32]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("HMAC-SHA256 key init failed: {e}"),
        }
    })?;
    mac.update(data);

    mac.verify_slice(expected).map_err(|_| BitevachatError::CryptoError {
        reason: "HMAC-SHA256 verification failed: tag mismatch (possible tampering)".into(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip() -> std::result::Result<(), BitevachatError> {
        let key = [0x42u8; 32];
        let data = b"hello bitevachat";
        let tag = hmac_sha256(&key, data)?;
        verify_hmac_sha256(&key, data, &tag)?;
        Ok(())
    }

    #[test]
    fn hmac_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let key = [0xAA; 32];
        let data = b"determinism test";
        let tag1 = hmac_sha256(&key, data)?;
        let tag2 = hmac_sha256(&key, data)?;
        assert_eq!(tag1, tag2);
        Ok(())
    }

    #[test]
    fn different_key_different_tag() -> std::result::Result<(), BitevachatError> {
        let data = b"same data";
        let tag_a = hmac_sha256(&[0x01; 32], data)?;
        let tag_b = hmac_sha256(&[0x02; 32], data)?;
        assert_ne!(tag_a, tag_b);
        Ok(())
    }

    #[test]
    fn different_data_different_tag() -> std::result::Result<(), BitevachatError> {
        let key = [0x42; 32];
        let tag_a = hmac_sha256(&key, b"data A")?;
        let tag_b = hmac_sha256(&key, b"data B")?;
        assert_ne!(tag_a, tag_b);
        Ok(())
    }

    #[test]
    fn wrong_tag_fails_verify() -> std::result::Result<(), BitevachatError> {
        let key = [0x42; 32];
        let tag = hmac_sha256(&key, b"correct data")?;
        let result = verify_hmac_sha256(&key, b"wrong data", &tag);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn tampered_tag_fails_verify() -> std::result::Result<(), BitevachatError> {
        let key = [0x42; 32];
        let data = b"test data";
        let mut tag = hmac_sha256(&key, data)?;
        tag[0] ^= 0xFF;
        let result = verify_hmac_sha256(&key, data, &tag);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn wrong_key_fails_verify() -> std::result::Result<(), BitevachatError> {
        let data = b"test data";
        let tag = hmac_sha256(&[0x01; 32], data)?;
        let result = verify_hmac_sha256(&[0x02; 32], data, &tag);
        assert!(result.is_err());
        Ok(())
    }

    /// RFC 4231 Test Case 2: HMAC-SHA-256.
    #[test]
    fn rfc4231_test_case_2() -> std::result::Result<(), BitevachatError> {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let tag = hmac_sha256(key, data)?;
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(tag, expected);
        Ok(())
    }

    #[test]
    fn empty_data() -> std::result::Result<(), BitevachatError> {
        let key = [0x42; 32];
        let tag = hmac_sha256(&key, b"")?;
        verify_hmac_sha256(&key, b"", &tag)?;
        assert_ne!(tag, [0u8; 32]);
        Ok(())
    }
}