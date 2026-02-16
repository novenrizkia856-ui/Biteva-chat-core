//! Per-sender token bucket rate limiter.
//!
//! Each sender address gets an independent bucket. Tokens refill
//! at a configurable rate using **integer-only arithmetic** (no
//! floats). Expired buckets are cleaned up periodically to prevent
//! unbounded memory growth.
//!
//! Thread-safe via `std::sync::Mutex` — no external crate required.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use bitevachat_types::{Address, BitevachatError};

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

/// Duration after which an idle bucket is eligible for cleanup.
const BUCKET_EXPIRY_SECS: u64 = 300; // 5 minutes

/// Minimum interval between cleanup sweeps.
const CLEANUP_INTERVAL_SECS: u64 = 60; // 1 minute

// ---------------------------------------------------------------------------
// Bucket
// ---------------------------------------------------------------------------

/// Per-sender token state.
struct Bucket {
    /// Current number of available tokens.
    tokens: u32,
    /// Timestamp of the last refill computation.
    last_refill: Instant,
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Thread-safe, per-sender token bucket rate limiter.
///
/// Each sender starts with `tokens_per_min` tokens. Consuming a
/// token succeeds if `tokens > 0`; otherwise the sender is rate-
/// limited. Tokens refill continuously based on elapsed time.
pub struct RateLimiter {
    /// Per-sender buckets.
    buckets: Mutex<RateLimiterInner>,
    /// Maximum tokens per sender (= messages per minute).
    tokens_per_min: u32,
}

/// Interior mutable state behind the mutex.
struct RateLimiterInner {
    map: HashMap<Address, Bucket>,
    last_cleanup: Instant,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given per-minute token count.
    pub fn new(tokens_per_min: u32) -> Self {
        Self {
            buckets: Mutex::new(RateLimiterInner {
                map: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            tokens_per_min,
        }
    }

    /// Checks and consumes one token for the given sender.
    ///
    /// Returns `Ok(())` if the sender has remaining capacity, or
    /// `Err(BitevachatError::RateLimitExceeded)` if the bucket is
    /// empty.
    ///
    /// This method also triggers periodic cleanup of expired buckets.
    pub fn check_rate(&self, sender: &Address) -> BResult<()> {
        let mut inner = self.buckets.lock().map_err(|_| {
            BitevachatError::ProtocolError {
                reason: "rate limiter lock poisoned".into(),
            }
        })?;

        let now = Instant::now();

        // Periodic cleanup.
        self.maybe_cleanup(&mut inner, now);

        let tokens_per_min = self.tokens_per_min;
        let bucket = inner.map.entry(*sender).or_insert_with(|| Bucket {
            tokens: tokens_per_min,
            last_refill: now,
        });

        // Refill tokens based on elapsed time (integer arithmetic).
        refill_bucket(bucket, tokens_per_min, now);

        // Consume one token.
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            Ok(())
        } else {
            Err(BitevachatError::RateLimitExceeded {
                reason: format!(
                    "sender {} exceeded {} messages/min",
                    sender, tokens_per_min,
                ),
            })
        }
    }

    /// Removes expired buckets to prevent unbounded memory growth.
    fn maybe_cleanup(&self, inner: &mut RateLimiterInner, now: Instant) {
        let elapsed = now.duration_since(inner.last_cleanup).as_secs();
        if elapsed < CLEANUP_INTERVAL_SECS {
            return;
        }

        inner.last_cleanup = now;
        inner.map.retain(|_, bucket| {
            let idle = now.duration_since(bucket.last_refill).as_secs();
            idle < BUCKET_EXPIRY_SECS
        });
    }

    /// Returns the number of currently tracked senders.
    ///
    /// Useful for monitoring and tests.
    pub fn tracked_senders(&self) -> usize {
        self.buckets
            .lock()
            .map(|inner| inner.map.len())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Refill logic (integer-only)
// ---------------------------------------------------------------------------

/// Refills a bucket based on elapsed time since the last refill.
///
/// Uses integer-only arithmetic:
/// ```text
/// elapsed_ms = now - last_refill (milliseconds)
/// refill = elapsed_ms * tokens_per_min / 60_000
/// ```
///
/// All intermediate values use `u64` to prevent overflow.
fn refill_bucket(bucket: &mut Bucket, tokens_per_min: u32, now: Instant) {
    let elapsed_ms = now.duration_since(bucket.last_refill).as_millis();
    if elapsed_ms == 0 {
        return;
    }

    // Cap elapsed_ms to prevent overflow in multiplication.
    // 600_000 ms = 10 minutes — more than enough for any realistic gap.
    let capped_ms: u64 = if elapsed_ms > 600_000 {
        600_000
    } else {
        elapsed_ms as u64
    };

    // Integer division: tokens_to_add = elapsed_ms * tokens_per_min / 60_000
    let refill = capped_ms
        .saturating_mul(tokens_per_min as u64)
        / 60_000;

    if refill > 0 {
        // Cap at tokens_per_min (bucket cannot exceed max capacity).
        let new_tokens = (bucket.tokens as u64)
            .saturating_add(refill)
            .min(tokens_per_min as u64);
        bucket.tokens = new_tokens as u32;
        bucket.last_refill = now;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn allows_up_to_limit() {
        let limiter = RateLimiter::new(3);
        let sender = Address::new([0x01; 32]);

        assert!(limiter.check_rate(&sender).is_ok());
        assert!(limiter.check_rate(&sender).is_ok());
        assert!(limiter.check_rate(&sender).is_ok());
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = RateLimiter::new(3);
        let sender = Address::new([0x01; 32]);

        for _ in 0..3 {
            assert!(limiter.check_rate(&sender).is_ok());
        }
        // 4th message should fail.
        let result = limiter.check_rate(&sender);
        assert!(result.is_err());
    }

    #[test]
    fn different_senders_independent() {
        let limiter = RateLimiter::new(2);
        let alice = Address::new([0x01; 32]);
        let bob = Address::new([0x02; 32]);

        // Exhaust Alice's bucket.
        assert!(limiter.check_rate(&alice).is_ok());
        assert!(limiter.check_rate(&alice).is_ok());
        assert!(limiter.check_rate(&alice).is_err());

        // Bob's bucket is untouched.
        assert!(limiter.check_rate(&bob).is_ok());
        assert!(limiter.check_rate(&bob).is_ok());
    }

    #[test]
    fn tokens_refill_after_time() {
        // Use a high rate to make refill observable in a short sleep.
        // 600/min = 10/sec → 1 token per 100ms.
        let limiter = RateLimiter::new(600);
        let sender = Address::new([0x01; 32]);

        // Exhaust all 600 tokens.
        for _ in 0..600 {
            let _ = limiter.check_rate(&sender);
        }
        assert!(limiter.check_rate(&sender).is_err());

        // Wait 200ms → should refill ~2 tokens at 10/sec.
        thread::sleep(Duration::from_millis(200));
        assert!(limiter.check_rate(&sender).is_ok());
    }

    #[test]
    fn tracked_senders_count() {
        let limiter = RateLimiter::new(10);
        let a = Address::new([0x01; 32]);
        let b = Address::new([0x02; 32]);

        assert_eq!(limiter.tracked_senders(), 0);

        let _ = limiter.check_rate(&a);
        assert_eq!(limiter.tracked_senders(), 1);

        let _ = limiter.check_rate(&b);
        assert_eq!(limiter.tracked_senders(), 2);
    }
}