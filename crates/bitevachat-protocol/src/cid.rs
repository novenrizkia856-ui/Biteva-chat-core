//! Content identifier for deterministic content addressing.
//!
//! A [`Cid`] is the SHA3-256 hash of arbitrary data, used primarily
//! for avatar content addressing. Only the CID (32 bytes) is
//! broadcast over gossip — never the raw data.

use bitevachat_crypto::hash::sha3_256;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Hex helpers (no external crate)
// ---------------------------------------------------------------------------

/// Encodes bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decodes a hex string to bytes.
///
/// Returns `None` if the string length is odd or contains
/// non-hex characters.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let chars = s.as_bytes();
    for chunk in chars.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

/// Returns the numeric value of a hex char, or `None`.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cid
// ---------------------------------------------------------------------------

/// Content identifier: SHA3-256 hash of data.
///
/// Deterministic — identical input always produces identical CID.
/// Display format is lowercase hex (64 chars).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Cid([u8; 32]);

impl Cid {
    /// Fixed byte length.
    pub const LEN: usize = 32;

    /// Creates a CID from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses a CID from a hex string.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::ProtocolError` if the hex is invalid
    /// or the length is not 32 bytes.
    pub fn from_hex(s: &str) -> bitevachat_types::Result<Self> {
        let bytes = hex_decode(s).ok_or_else(|| {
            bitevachat_types::BitevachatError::ProtocolError {
                reason: "invalid hex encoding for CID".into(),
            }
        })?;
        if bytes.len() != 32 {
            return Err(bitevachat_types::BitevachatError::ProtocolError {
                reason: format!("CID must be 32 bytes, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

// ---------------------------------------------------------------------------
// compute_cid
// ---------------------------------------------------------------------------

/// Computes a deterministic CID for the given data.
///
/// `CID = SHA3-256(data)`
///
/// This function is pure and deterministic — identical input always
/// produces identical output.
pub fn compute_cid(data: &[u8]) -> Cid {
    Cid(sha3_256(data))
}

/// Validates that a CID matches the given data.
///
/// Returns `true` if `cid == SHA3-256(data)`.
pub fn validate_cid(cid: &Cid, data: &[u8]) -> bool {
    let expected = sha3_256(data);
    constant_time_eq(&cid.0, &expected)
}

/// Constant-time comparison of two 32-byte arrays.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_cid_deterministic() {
        let data = b"hello world";
        let cid1 = compute_cid(data);
        let cid2 = compute_cid(data);
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn different_data_different_cid() {
        let cid1 = compute_cid(b"hello");
        let cid2 = compute_cid(b"world");
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn validate_cid_correct() {
        let data = b"test data";
        let cid = compute_cid(data);
        assert!(validate_cid(&cid, data));
    }

    #[test]
    fn validate_cid_wrong_data() {
        let cid = compute_cid(b"original");
        assert!(!validate_cid(&cid, b"tampered"));
    }

    #[test]
    fn cid_hex_roundtrip() {
        let cid = compute_cid(b"roundtrip test");
        let hex_str = cid.to_string();
        let parsed = Cid::from_hex(&hex_str).expect("valid hex");
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_hex_display_is_64_chars() {
        let cid = compute_cid(b"test");
        assert_eq!(cid.to_string().len(), 64);
    }

    #[test]
    fn cid_from_hex_invalid() {
        assert!(Cid::from_hex("not-hex").is_err());
        assert!(Cid::from_hex("abcd").is_err()); // too short
    }

    #[test]
    fn empty_data_has_valid_cid() {
        let cid = compute_cid(b"");
        assert_eq!(cid.as_bytes().len(), 32);
    }
}