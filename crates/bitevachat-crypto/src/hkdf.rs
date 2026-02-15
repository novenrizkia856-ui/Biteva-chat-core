//! HKDF-SHA256 key derivation for session keys and E2E encryption.
//!
//! Implements the HMAC-based Extract-and-Expand Key Derivation Function
//! (RFC 5869) using SHA-256 as the underlying hash. Used to derive
//! symmetric encryption keys from ECDH shared secrets.
//!
//! The output is automatically zeroized on drop to minimize the time
//! sensitive material resides in memory.

use bitevachat_types::{BitevachatError, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum output length in bytes.
///
/// HKDF-SHA256 can produce up to `255 × 32 = 8160` bytes, but we cap
/// at 64 to prevent misuse. Typical usage is 32 bytes (one AES-256 or
/// XChaCha20 key).
const MAX_OUTPUT_LEN: usize = 64;

// ---------------------------------------------------------------------------
// HkdfOutput
// ---------------------------------------------------------------------------

/// Variable-length key material derived by HKDF-SHA256.
///
/// Automatically zeroized when dropped to prevent sensitive material
/// from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HkdfOutput {
    /// Raw derived bytes.
    bytes: Vec<u8>,
}

impl HkdfOutput {
    /// Returns the derived key material as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the derived key material.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the output is empty (should never be the case
    /// for a successful derivation).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// HkdfOutput does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives key material from input keying material using HKDF-SHA256.
///
/// # Parameters
///
/// - `ikm` — input keying material (e.g. ECDH shared secret).
/// - `salt` — optional salt value. An empty slice is valid per RFC 5869
///   §3.1; the HKDF implementation uses a zero-filled salt of hash
///   length in that case.
/// - `info` — context and application-specific information. Should
///   contain sender and recipient identifiers for E2E encryption.
/// - `output_len` — desired output length in bytes. Must be in the
///   range `1..=64`.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if `output_len` is 0 or
///   exceeds [`MAX_OUTPUT_LEN`] (64), or if HKDF expansion fails.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<HkdfOutput> {
    if output_len == 0 {
        return Err(BitevachatError::CryptoError {
            reason: "HKDF output length must be at least 1 byte".into(),
        });
    }

    if output_len > MAX_OUTPUT_LEN {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "HKDF output length {output_len} exceeds maximum {MAX_OUTPUT_LEN}"
            ),
        });
    }

    // Use provided salt, or empty (HKDF spec: empty → zeroed salt).
    let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt) };

    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);

    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm).map_err(|e| BitevachatError::CryptoError {
        reason: format!("HKDF-SHA256 expansion failed: {e}"),
    })?;

    Ok(HkdfOutput { bytes: okm })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_32_bytes_deterministic() -> std::result::Result<(), BitevachatError> {
        let ikm = [0x42u8; 32];
        let salt = b"test-salt";
        let info = b"test-info";

        let out1 = hkdf_sha256(&ikm, salt, info, 32)?;
        let out2 = hkdf_sha256(&ikm, salt, info, 32)?;
        assert_eq!(out1.as_bytes(), out2.as_bytes());
        assert_eq!(out1.len(), 32);
        Ok(())
    }

    #[test]
    fn different_ikm_different_output() -> std::result::Result<(), BitevachatError> {
        let salt = b"salt";
        let info = b"info";

        let out_a = hkdf_sha256(&[0x01; 32], salt, info, 32)?;
        let out_b = hkdf_sha256(&[0x02; 32], salt, info, 32)?;
        assert_ne!(out_a.as_bytes(), out_b.as_bytes());
        Ok(())
    }

    #[test]
    fn different_info_different_output() -> std::result::Result<(), BitevachatError> {
        let ikm = [0x42u8; 32];
        let salt = b"salt";

        let out_a = hkdf_sha256(&ikm, salt, b"info-a", 32)?;
        let out_b = hkdf_sha256(&ikm, salt, b"info-b", 32)?;
        assert_ne!(out_a.as_bytes(), out_b.as_bytes());
        Ok(())
    }

    #[test]
    fn different_salt_different_output() -> std::result::Result<(), BitevachatError> {
        let ikm = [0x42u8; 32];
        let info = b"info";

        let out_a = hkdf_sha256(&ikm, b"salt-a", info, 32)?;
        let out_b = hkdf_sha256(&ikm, b"salt-b", info, 32)?;
        assert_ne!(out_a.as_bytes(), out_b.as_bytes());
        Ok(())
    }

    #[test]
    fn empty_salt_is_valid() -> std::result::Result<(), BitevachatError> {
        let ikm = [0x42u8; 32];
        let out = hkdf_sha256(&ikm, b"", b"info", 32)?;
        assert_eq!(out.len(), 32);
        assert_ne!(out.as_bytes(), &[0u8; 32]);
        Ok(())
    }

    #[test]
    fn output_len_64_is_valid() -> std::result::Result<(), BitevachatError> {
        let out = hkdf_sha256(&[0x01; 32], b"salt", b"info", 64)?;
        assert_eq!(out.len(), 64);
        Ok(())
    }

    #[test]
    fn output_len_zero_rejected() {
        let result = hkdf_sha256(&[0x01; 32], b"salt", b"info", 0);
        assert!(result.is_err());
    }

    #[test]
    fn output_len_too_large_rejected() {
        let result = hkdf_sha256(&[0x01; 32], b"salt", b"info", 65);
        assert!(result.is_err());
    }

    /// RFC 5869 Test Case 1 (HKDF-SHA256).
    ///
    /// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    /// salt = 0x000102030405060708090a0b0c (13 bytes)
    /// info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    /// L    = 42
    /// OKM  = 0x3cb25f25fcedb... (42 bytes)
    #[test]
    fn rfc5869_test_vector_1() -> std::result::Result<(), BitevachatError> {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();

        let out = hkdf_sha256(&ikm, &salt, &info, 42)?;
        assert_eq!(out.len(), 42);

        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65,
        ];
        assert_eq!(out.as_bytes(), &expected);
        Ok(())
    }
}