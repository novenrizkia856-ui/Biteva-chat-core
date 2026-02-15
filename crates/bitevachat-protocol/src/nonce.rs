//! Bounded FIFO nonce cache for replay detection.
//!
//! The [`NonceCache`] prevents nonce reuse within a sliding window.
//! Nonce uniqueness is scoped per sender address: the same nonce
//! value from two different senders does **not** constitute a replay.
//!
//! Implementation: `HashMap` for O(1) lookup + `VecDeque` for FIFO
//! eviction ordering. When the cache reaches capacity, the oldest
//! entry is evicted before inserting the new one.

use bitevachat_types::{Address, BitevachatError, Nonce, Result};
use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum number of entries in the nonce cache.
pub const DEFAULT_NONCE_CACHE_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// NonceCache
// ---------------------------------------------------------------------------

/// Bounded FIFO cache that tracks recently seen `(sender, nonce)` pairs.
///
/// Used by the message validation pipeline to reject replayed
/// messages. Once a `(sender, nonce)` pair has been inserted, any
/// subsequent attempt to insert the same pair will fail with
/// [`BitevachatError::NonceReplay`].
///
/// When the cache is full, the **oldest** entry is evicted to make
/// room. This guarantees bounded memory usage regardless of message
/// throughput.
pub struct NonceCache {
    /// O(1) membership test.
    seen: HashMap<(Address, Nonce), ()>,
    /// FIFO insertion order for eviction.
    order: VecDeque<(Address, Nonce)>,
    /// Maximum number of entries.
    capacity: usize,
}

impl NonceCache {
    /// Creates a new [`NonceCache`] with the given capacity.
    ///
    /// # Panics
    ///
    /// Does **not** panic. A capacity of 0 is treated as 1 to ensure
    /// at least one entry can be tracked.
    pub fn new(capacity: usize) -> Self {
        let cap = if capacity == 0 { 1 } else { capacity };
        Self {
            seen: HashMap::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    /// Creates a new [`NonceCache`] with the default capacity
    /// ([`DEFAULT_NONCE_CACHE_SIZE`]).
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_NONCE_CACHE_SIZE)
    }

    /// Checks whether `(sender, nonce)` has been seen before.
    ///
    /// - If **not seen**: inserts the pair and returns `Ok(())`.
    /// - If **already seen**: returns [`BitevachatError::NonceReplay`].
    ///
    /// When the cache is at capacity, the oldest entry is evicted
    /// before the new entry is inserted.
    ///
    /// # Errors
    ///
    /// Returns [`BitevachatError::NonceReplay`] on duplicate.
    pub fn check_and_insert(&mut self, sender: &Address, nonce: &Nonce) -> Result<()> {
        let key = (*sender, *nonce);

        if self.seen.contains_key(&key) {
            return Err(BitevachatError::NonceReplay {
                reason: format!(
                    "duplicate nonce from sender {sender}"
                ),
            });
        }

        // Evict oldest if at capacity.
        if self.seen.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }

        self.seen.insert(key, ());
        self.order.push_back(key);

        Ok(())
    }

    /// Returns the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn nonce(byte: u8) -> Nonce {
        Nonce::new([byte; 12])
    }

    #[test]
    fn insert_new_nonce_succeeds() -> std::result::Result<(), BitevachatError> {
        let mut cache = NonceCache::new(100);
        cache.check_and_insert(&addr(0x01), &nonce(0xAA))?;
        assert_eq!(cache.len(), 1);
        Ok(())
    }

    #[test]
    fn duplicate_nonce_rejected() -> std::result::Result<(), BitevachatError> {
        let mut cache = NonceCache::new(100);
        let a = addr(0x01);
        let n = nonce(0xAA);
        cache.check_and_insert(&a, &n)?;
        let result = cache.check_and_insert(&a, &n);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn same_nonce_different_sender_allowed() -> std::result::Result<(), BitevachatError> {
        let mut cache = NonceCache::new(100);
        let n = nonce(0xAA);
        cache.check_and_insert(&addr(0x01), &n)?;
        cache.check_and_insert(&addr(0x02), &n)?;
        assert_eq!(cache.len(), 2);
        Ok(())
    }

    #[test]
    fn eviction_on_capacity() -> std::result::Result<(), BitevachatError> {
        let mut cache = NonceCache::new(3);
        let a = addr(0x01);
        cache.check_and_insert(&a, &nonce(0x01))?;
        cache.check_and_insert(&a, &nonce(0x02))?;
        cache.check_and_insert(&a, &nonce(0x03))?;

        // Cache is full (3). Insert a 4th; oldest (0x01) gets evicted.
        cache.check_and_insert(&a, &nonce(0x04))?;
        assert_eq!(cache.len(), 3);

        // Nonce 0x01 was evicted; re-inserting should succeed.
        cache.check_and_insert(&a, &nonce(0x01))?;
        assert_eq!(cache.len(), 3);

        Ok(())
    }

    #[test]
    fn zero_capacity_treated_as_one() -> std::result::Result<(), BitevachatError> {
        let mut cache = NonceCache::new(0);
        let a = addr(0x01);
        cache.check_and_insert(&a, &nonce(0x01))?;
        // Only 1 slot; inserting a second evicts the first.
        cache.check_and_insert(&a, &nonce(0x02))?;
        assert_eq!(cache.len(), 1);
        Ok(())
    }

    #[test]
    fn default_capacity_is_ten_thousand() {
        let cache = NonceCache::with_default_capacity();
        assert_eq!(cache.capacity, DEFAULT_NONCE_CACHE_SIZE);
    }
}