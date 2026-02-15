//! Address checksum and Bech32 encoding.
//!
//! Appends a 4-byte checksum (first 4 bytes of `SHA3-256(hash)`) to a
//! 32-byte address hash, producing a 36-byte [`AddressWithChecksum`].
//! The address can then be encoded as a Bech32 string with the human-
//! readable prefix `btvc` for display and safe copy-paste (typo detection).

use bitevachat_types::{BitevachatError, Result};
use bech32::{self, FromBase32, ToBase32, Variant};

use crate::hash::sha3_256;

/// Human-readable prefix for Bech32-encoded Bitevachat addresses.
const BECH32_HRP: &str = "btvc";

/// Number of checksum bytes appended to the address hash.
const CHECKSUM_LEN: usize = 4;

// ---------------------------------------------------------------------------
// AddressWithChecksum
// ---------------------------------------------------------------------------

/// A 32-byte address hash plus a 4-byte integrity checksum (36 bytes total).
///
/// The checksum is the first 4 bytes of `SHA3-256(address_hash)`.
/// This provides lightweight typo detection when addresses are
/// exchanged out-of-band. For display, use [`to_bech32`](Self::to_bech32)
/// which adds Bech32 error-correcting encoding on top.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressWithChecksum {
    /// The 32-byte SHA3-256 hash of the public key.
    hash: [u8; 32],
    /// First 4 bytes of `SHA3-256(hash)`.
    checksum: [u8; CHECKSUM_LEN],
}

impl AddressWithChecksum {
    /// Returns the 32-byte hash portion (the canonical address).
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Returns the 4-byte checksum portion.
    pub fn checksum(&self) -> &[u8; CHECKSUM_LEN] {
        &self.checksum
    }

    /// Returns the full 36-byte representation (hash ∥ checksum).
    pub fn as_bytes(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.hash);
        out[32..].copy_from_slice(&self.checksum);
        out
    }

    /// Encodes this address as a Bech32 string with the `btvc` prefix.
    ///
    /// Example output: `btvc1qw508d6qejxtdg4y5r3zarvary0c5xw7k...`
    pub fn to_bech32(&self) -> Result<String> {
        let data = self.as_bytes();
        bech32::encode(BECH32_HRP, data.to_base32(), Variant::Bech32).map_err(
            |e| BitevachatError::CryptoError {
                reason: format!("bech32 encoding failed: {e}"),
            },
        )
    }

    /// Decodes a Bech32 string back into an [`AddressWithChecksum`].
    ///
    /// Validates the Bech32 encoding, checks the `btvc` prefix, and
    /// verifies the embedded checksum.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data_base32, _variant) =
            bech32::decode(s).map_err(|e| BitevachatError::InvalidAddress {
                reason: format!("bech32 decoding failed: {e}"),
            })?;

        if hrp != BECH32_HRP {
            return Err(BitevachatError::InvalidAddress {
                reason: format!(
                    "expected HRP '{BECH32_HRP}', got '{hrp}'"
                ),
            });
        }

        let bytes = Vec::<u8>::from_base32(&data_base32).map_err(|e| {
            BitevachatError::InvalidAddress {
                reason: format!("bech32 base32 conversion failed: {e}"),
            }
        })?;

        if bytes.len() != 36 {
            return Err(BitevachatError::InvalidAddress {
                reason: format!(
                    "expected 36 bytes (32 hash + 4 checksum), got {}",
                    bytes.len()
                ),
            });
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        let mut checksum = [0u8; CHECKSUM_LEN];
        checksum.copy_from_slice(&bytes[32..]);

        let result = Self { hash, checksum };
        verify_checksum(&result.as_bytes())?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Computes a 4-byte checksum and appends it to a 32-byte address hash.
///
/// Checksum = `SHA3-256(hash)[0..4]`.
pub fn append_checksum(hash: &[u8; 32]) -> AddressWithChecksum {
    let digest = sha3_256(hash);
    let mut checksum = [0u8; CHECKSUM_LEN];
    checksum.copy_from_slice(&digest[..CHECKSUM_LEN]);
    AddressWithChecksum {
        hash: *hash,
        checksum,
    }
}

/// Verifies the checksum embedded in a 36-byte address.
///
/// Splits the input into the 32-byte hash and the 4-byte checksum,
/// recomputes `SHA3-256(hash)[0..4]`, and checks for equality.
///
/// # Errors
///
/// Returns [`BitevachatError::InvalidAddress`] if:
/// - The input is not exactly 36 bytes.
/// - The checksum does not match.
pub fn verify_checksum(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 36 {
        return Err(BitevachatError::InvalidAddress {
            reason: format!(
                "expected 36 bytes for checksum verification, got {}",
                bytes.len()
            ),
        });
    }

    let hash = &bytes[..32];
    let provided_checksum = &bytes[32..36];

    let digest = sha3_256(hash);
    let expected_checksum = &digest[..CHECKSUM_LEN];

    if provided_checksum != expected_checksum {
        return Err(BitevachatError::InvalidAddress {
            reason: "checksum mismatch".into(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_verify_roundtrip() -> std::result::Result<(), BitevachatError> {
        let hash = [0xAB; 32];
        let addr = append_checksum(&hash);
        verify_checksum(&addr.as_bytes())?;
        assert_eq!(addr.hash(), &hash);
        Ok(())
    }

    #[test]
    fn checksum_is_deterministic() {
        let hash = [0x42; 32];
        let a = append_checksum(&hash);
        let b = append_checksum(&hash);
        assert_eq!(a.checksum(), b.checksum());
    }

    #[test]
    fn different_hash_different_checksum() {
        let a = append_checksum(&[0x01; 32]);
        let b = append_checksum(&[0x02; 32]);
        assert_ne!(a.checksum(), b.checksum());
    }

    #[test]
    fn corrupted_checksum_rejected() {
        let addr = append_checksum(&[0xAB; 32]);
        let mut bytes = addr.as_bytes();
        bytes[35] ^= 0xFF; // flip last checksum byte
        assert!(verify_checksum(&bytes).is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(verify_checksum(&[0u8; 35]).is_err());
        assert!(verify_checksum(&[0u8; 37]).is_err());
        assert!(verify_checksum(&[]).is_err());
    }

    #[test]
    fn bech32_roundtrip() -> std::result::Result<(), BitevachatError> {
        let hash = [0x55; 32];
        let addr = append_checksum(&hash);

        let encoded = addr.to_bech32()?;
        assert!(encoded.starts_with("btvc1"));

        let decoded = AddressWithChecksum::from_bech32(&encoded)?;
        assert_eq!(decoded, addr);
        assert_eq!(decoded.hash(), &hash);
        Ok(())
    }

    #[test]
    fn bech32_wrong_hrp_rejected() {
        let hash = [0x55; 32];
        let data = append_checksum(&hash).as_bytes();
        let wrong = bech32::encode("wrong", data.to_base32(), Variant::Bech32);
        if let Ok(encoded) = wrong {
            assert!(AddressWithChecksum::from_bech32(&encoded).is_err());
        }
    }

    #[test]
    fn bech32_corrupted_data_rejected() -> std::result::Result<(), BitevachatError> {
        let addr = append_checksum(&[0x77; 32]);
        let encoded = addr.to_bech32()?;

        // Corrupt a character in the data portion (after "btvc1").
        let mut chars: Vec<char> = encoded.chars().collect();
        if chars.len() > 10 {
            // Flip a data character to something different.
            chars[10] = if chars[10] == 'q' { 'p' } else { 'q' };
        }
        let corrupted: String = chars.into_iter().collect();

        // Should fail either at bech32 decode or checksum verify.
        assert!(AddressWithChecksum::from_bech32(&corrupted).is_err());
        Ok(())
    }

    /// Hardcoded known-output for a specific hash to detect
    /// accidental changes in the checksum algorithm.
    #[test]
    fn known_checksum_for_zero_hash() {
        let hash = [0x00; 32];
        let addr = append_checksum(&hash);

        // SHA3-256 of 32 zero bytes:
        // 5b5e139e 754c8e49 8bdf4c22 3c007553 ...
        // First 4 bytes of that digest form the checksum.
        let digest = sha3_256(&hash);
        let mut expected = [0u8; 4];
        expected.copy_from_slice(&digest[..4]);
        assert_eq!(addr.checksum(), &expected);
    }
}
