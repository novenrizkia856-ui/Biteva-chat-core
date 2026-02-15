//! SHA3-256 hashing and deterministic message ID computation.
//!
//! All hashing in Bitevachat uses SHA3-256 (Keccak). Message IDs are
//! computed deterministically from `sender || timestamp || nonce` to
//! guarantee uniqueness and reproducibility.

use bitevachat_types::{Address, MessageId, Nonce, Timestamp};
use sha3::{Digest, Sha3_256};

/// Computes the SHA3-256 hash of arbitrary data.
///
/// Returns a fixed 32-byte digest. Deterministic: identical inputs
/// always produce identical outputs.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Computes a deterministic message ID from the sender address,
/// timestamp, and nonce.
///
/// Formula: `MessageId = SHA3-256(sender_bytes || timestamp_millis_be || nonce_bytes)`
///
/// - `sender_bytes`: 32-byte raw address
/// - `timestamp_millis_be`: 8-byte big-endian UTC milliseconds since epoch
/// - `nonce_bytes`: 12-byte message nonce
///
/// Total preimage: 52 bytes → 32-byte digest.
///
/// This function is pure and deterministic: given the same inputs, it
/// always returns the same [`MessageId`].
pub fn compute_message_id(
    sender: &Address,
    timestamp: &Timestamp,
    nonce: &Nonce,
) -> MessageId {
    let ts_millis = timestamp.as_datetime().timestamp_millis();
    let ts_bytes = ts_millis.to_be_bytes();

    let mut hasher = Sha3_256::new();
    hasher.update(sender.as_ref());
    hasher.update(ts_bytes);
    hasher.update(nonce.as_ref());

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    MessageId::new(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// NIST SHA3-256 test vector: empty input.
    #[test]
    fn sha3_256_empty_input() {
        let hash = sha3_256(b"");
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(hash, expected);
    }

    /// NIST SHA3-256 test vector: "abc".
    #[test]
    fn sha3_256_abc() {
        let hash = sha3_256(b"abc");
        let expected = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sha3_256_is_deterministic() {
        let data = b"bitevachat determinism";
        assert_eq!(sha3_256(data), sha3_256(data));
    }

    #[test]
    fn compute_message_id_is_deterministic() {
        let sender = Address::new([0x01; 32]);
        let dt = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0);
        let ts = Timestamp::from_datetime(
            dt.single().unwrap_or_else(chrono::Utc::now),
        );
        let nonce = Nonce::new([0xAA; 12]);

        let id1 = compute_message_id(&sender, &ts, &nonce);
        let id2 = compute_message_id(&sender, &ts, &nonce);
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_nonce_produces_different_id() {
        let sender = Address::new([0x01; 32]);
        let dt = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0);
        let ts = Timestamp::from_datetime(
            dt.single().unwrap_or_else(chrono::Utc::now),
        );
        let nonce_a = Nonce::new([0xAA; 12]);
        let nonce_b = Nonce::new([0xBB; 12]);

        let id_a = compute_message_id(&sender, &ts, &nonce_a);
        let id_b = compute_message_id(&sender, &ts, &nonce_b);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn different_sender_produces_different_id() {
        let sender_a = Address::new([0x01; 32]);
        let sender_b = Address::new([0x02; 32]);
        let dt = chrono::Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0);
        let ts = Timestamp::from_datetime(
            dt.single().unwrap_or_else(chrono::Utc::now),
        );
        let nonce = Nonce::new([0xCC; 12]);

        let id_a = compute_message_id(&sender_a, &ts, &nonce);
        let id_b = compute_message_id(&sender_b, &ts, &nonce);
        assert_ne!(id_a, id_b);
    }
}
