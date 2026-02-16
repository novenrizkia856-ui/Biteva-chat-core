//! Proof-of-Work for anti-spam protection.
//!
//! Senders whose [`TrustLevel`] is `Unknown` must attach a valid PoW
//! to their message. The PoW is **transport-level metadata**, not part
//! of the [`MessageEnvelope`].
//!
//! # Algorithm
//!
//! ```text
//! hash = SHA3-256(message_hash || nonce_le_bytes)
//! valid = leading_zero_bits(hash) >= difficulty
//! ```
//!
//! # Difficulty cap
//!
//! Difficulty is capped at [`MAX_DIFFICULTY`] (24 bits) to prevent
//! CPU exhaustion attacks via malicious difficulty values.

use bitevachat_crypto::hash::sha3_256;
use bitevachat_types::BitevachatError;

/// Maximum allowed PoW difficulty in leading zero bits.
///
/// 24 bits ≈ 16 million hash attempts on average, which takes a few
/// seconds on modern hardware. Higher values risk excessive CPU usage.
pub const MAX_DIFFICULTY: u8 = 24;

/// Maximum iterations for PoW generation to prevent infinite loops.
const MAX_ITERATIONS: u64 = 1 << 26; // ~67M

// ---------------------------------------------------------------------------
// ProofOfWork
// ---------------------------------------------------------------------------

/// Proof-of-work token attached as transport metadata.
#[derive(Clone, Debug)]
pub struct ProofOfWork {
    /// The nonce that produces a hash with sufficient leading zeros.
    pub nonce: u64,
    /// The difficulty (leading zero bits) this proof targets.
    pub difficulty: u8,
    /// The resulting SHA3-256 hash (for quick verification).
    pub hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generates a proof-of-work for the given message hash.
///
/// Iterates nonces from 0 until a hash with at least `difficulty`
/// leading zero bits is found, or [`MAX_ITERATIONS`] is reached.
///
/// # Warning
///
/// This function is CPU-intensive. Callers in async contexts should
/// use `tokio::task::spawn_blocking` to avoid blocking the runtime.
///
/// # Errors
///
/// - `BitevachatError::ProtocolError` if `difficulty` exceeds
///   [`MAX_DIFFICULTY`].
/// - `BitevachatError::ProtocolError` if no valid nonce is found
///   within the iteration limit.
pub fn generate_pow(
    message_hash: &[u8; 32],
    difficulty: u8,
) -> std::result::Result<ProofOfWork, BitevachatError> {
    if difficulty > MAX_DIFFICULTY {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "PoW difficulty {} exceeds maximum {}",
                difficulty, MAX_DIFFICULTY,
            ),
        });
    }

    if difficulty == 0 {
        // Difficulty 0 means any hash is valid.
        let hash = compute_pow_hash(message_hash, 0);
        return Ok(ProofOfWork {
            nonce: 0,
            difficulty,
            hash,
        });
    }

    for nonce in 0..MAX_ITERATIONS {
        let hash = compute_pow_hash(message_hash, nonce);
        if leading_zero_bits(&hash) >= difficulty {
            return Ok(ProofOfWork {
                nonce,
                difficulty,
                hash,
            });
        }
    }

    Err(BitevachatError::ProtocolError {
        reason: format!(
            "PoW generation failed: no valid nonce found within {} iterations",
            MAX_ITERATIONS,
        ),
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verifies a proof-of-work against a message hash.
///
/// Recomputes the hash from scratch (does NOT trust the embedded
/// `pow.hash` field) and checks that leading zero bits meet the
/// claimed difficulty.
///
/// # Errors
///
/// - `BitevachatError::ProtocolError` if `pow.difficulty` exceeds
///   [`MAX_DIFFICULTY`].
/// - `BitevachatError::InvalidMessage` if verification fails.
pub fn verify_pow(
    pow: &ProofOfWork,
    message_hash: &[u8; 32],
) -> std::result::Result<(), BitevachatError> {
    if pow.difficulty > MAX_DIFFICULTY {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "PoW difficulty {} exceeds maximum {}",
                pow.difficulty, MAX_DIFFICULTY,
            ),
        });
    }

    // Recompute hash — never trust the provided hash.
    let recomputed = compute_pow_hash(message_hash, pow.nonce);

    // Constant-time comparison of the embedded hash against recomputed.
    if !constant_time_eq(&pow.hash, &recomputed) {
        return Err(BitevachatError::InvalidMessage {
            reason: "PoW hash does not match recomputed hash".into(),
        });
    }

    // Check leading zero bits.
    if leading_zero_bits(&recomputed) < pow.difficulty {
        return Err(BitevachatError::InvalidMessage {
            reason: format!(
                "PoW has {} leading zero bits, need {}",
                leading_zero_bits(&recomputed),
                pow.difficulty,
            ),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes `SHA3-256(message_hash || nonce_le)`.
fn compute_pow_hash(message_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
    let nonce_bytes = nonce.to_le_bytes();
    let mut preimage = [0u8; 40]; // 32 + 8
    preimage[..32].copy_from_slice(message_hash);
    preimage[32..].copy_from_slice(&nonce_bytes);
    sha3_256(&preimage)
}

/// Counts the number of leading zero bits in a 32-byte hash.
fn leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut count: u8 = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            count = count.saturating_add(8);
        } else {
            count = count.saturating_add(byte.leading_zeros() as u8);
            break;
        }
    }
    count
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
    fn leading_zero_bits_all_zeros() {
        let hash = [0u8; 32];
        assert_eq!(leading_zero_bits(&hash), 255); // saturates at 256 but u8 max is 255
    }

    #[test]
    fn leading_zero_bits_first_byte_nonzero() {
        let mut hash = [0u8; 32];
        hash[0] = 0b0000_1000; // 4 leading zeros
        assert_eq!(leading_zero_bits(&hash), 4);
    }

    #[test]
    fn leading_zero_bits_second_byte() {
        let mut hash = [0u8; 32];
        hash[0] = 0;
        hash[1] = 0b0010_0000; // 8 + 2 = 10 leading zeros
        assert_eq!(leading_zero_bits(&hash), 10);
    }

    #[test]
    fn leading_zero_bits_high_bit_set() {
        let mut hash = [0u8; 32];
        hash[0] = 0b1000_0000; // 0 leading zeros
        assert_eq!(leading_zero_bits(&hash), 0);
    }

    #[test]
    fn generate_verify_roundtrip_low_difficulty() {
        let msg_hash = sha3_256(b"test message");
        let pow = generate_pow(&msg_hash, 4).expect("should find nonce");
        assert!(verify_pow(&pow, &msg_hash).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message_hash() {
        let msg_hash = sha3_256(b"original");
        let pow = generate_pow(&msg_hash, 4).expect("should find nonce");

        let wrong_hash = sha3_256(b"different");
        assert!(verify_pow(&pow, &wrong_hash).is_err());
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let msg_hash = sha3_256(b"test");
        let mut pow = generate_pow(&msg_hash, 4).expect("should find nonce");
        pow.nonce = pow.nonce.wrapping_add(1);
        assert!(verify_pow(&pow, &msg_hash).is_err());
    }

    #[test]
    fn difficulty_zero_always_valid() {
        let msg_hash = sha3_256(b"anything");
        let pow = generate_pow(&msg_hash, 0).expect("difficulty 0");
        assert!(verify_pow(&pow, &msg_hash).is_ok());
    }

    #[test]
    fn difficulty_exceeds_max_rejected() {
        let msg_hash = sha3_256(b"test");
        let result = generate_pow(&msg_hash, MAX_DIFFICULTY + 1);
        assert!(result.is_err());
    }

    #[test]
    fn verify_difficulty_exceeds_max_rejected() {
        let pow = ProofOfWork {
            nonce: 0,
            difficulty: MAX_DIFFICULTY + 1,
            hash: [0u8; 32],
        };
        let msg_hash = sha3_256(b"test");
        assert!(verify_pow(&pow, &msg_hash).is_err());
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        let c = [0xCDu8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}