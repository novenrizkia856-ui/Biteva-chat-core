//! Trust scoring for anti-spam decisions.
//!
//! Each address accumulates an interaction count through successful
//! message exchanges. The count maps deterministically to a
//! [`TrustScore`] level:
//!
//! | Interactions         | Score     |
//! |---------------------|-----------|
//! | 0                   | `Unknown` |
//! | ≥ threshold         | `Seen`    |
//! | ≥ threshold × 3     | `Trusted` |
//!
//! The scorer operates on an **in-memory cache** for fast lookups.
//! Persistence is handled by explicit `load_from_storage` /
//! `save_to_storage` calls at startup and shutdown.

use std::collections::HashMap;
use std::sync::Mutex;

use bitevachat_types::Address;

// ---------------------------------------------------------------------------
// TrustScore
// ---------------------------------------------------------------------------

/// Trust level derived from interaction history.
///
/// Higher trust levels relax anti-spam requirements:
/// - `Unknown` → PoW required (if enabled).
/// - `Seen` → PoW not required, normal rate limits.
/// - `Trusted` → all anti-spam checks relaxed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustScore {
    /// No prior interaction. First contact.
    Unknown,
    /// Has exchanged messages successfully (≥ threshold interactions).
    Seen,
    /// Stable, long-term interaction history (≥ threshold × 3).
    Trusted,
}

impl std::fmt::Display for TrustScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("Unknown"),
            Self::Seen => f.write_str("Seen"),
            Self::Trusted => f.write_str("Trusted"),
        }
    }
}

// ---------------------------------------------------------------------------
// TrustScorer
// ---------------------------------------------------------------------------

/// In-memory trust scorer backed by interaction counts.
///
/// Thread-safe via `Mutex`. Counts are loaded from persistent storage
/// at startup and flushed back at shutdown.
pub struct TrustScorer {
    /// Interaction count threshold for `Seen` level.
    threshold: u32,
    /// In-memory interaction counts per address.
    counts: Mutex<HashMap<Address, u32>>,
}

impl TrustScorer {
    /// Creates a new scorer with the given threshold.
    ///
    /// - `Unknown` → `Seen` at `threshold` interactions.
    /// - `Seen` → `Trusted` at `threshold * 3` interactions.
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Records one successful interaction with the given address.
    ///
    /// Increments the in-memory count using saturating arithmetic.
    /// Caller is responsible for persisting via `save_to_storage`
    /// when appropriate.
    pub fn record_interaction(&self, address: &Address) {
        if let Ok(mut counts) = self.counts.lock() {
            let count = counts.entry(*address).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    /// Returns the current trust score for an address.
    pub fn get_trust_score(&self, address: &Address) -> TrustScore {
        let count = self
            .counts
            .lock()
            .ok()
            .and_then(|counts| counts.get(address).copied())
            .unwrap_or(0);

        self.score_from_count(count)
    }

    /// Returns the raw interaction count for an address.
    ///
    /// Useful for debugging and tests.
    pub fn get_interaction_count(&self, address: &Address) -> u32 {
        self.counts
            .lock()
            .ok()
            .and_then(|counts| counts.get(address).copied())
            .unwrap_or(0)
    }

    /// Loads all trust data from a [`bitevachat_storage::trust::TrustStore`].
    ///
    /// Replaces the in-memory cache with data from storage.
    ///
    /// # Type note
    ///
    /// Takes a slice of `(Address, u32)` pairs to avoid coupling
    /// to the storage crate's concrete type. The caller fetches
    /// the data via `TrustStore::list_all()`.
    pub fn load_from_pairs(&self, pairs: &[(Address, u32)]) {
        if let Ok(mut counts) = self.counts.lock() {
            counts.clear();
            for (addr, count) in pairs {
                counts.insert(*addr, *count);
            }
        }
    }

    /// Exports all trust data as `(Address, u32)` pairs.
    ///
    /// The caller persists via `TrustStore::set_interaction_count`.
    pub fn export_pairs(&self) -> Vec<(Address, u32)> {
        self.counts
            .lock()
            .ok()
            .map(|counts| {
                counts.iter().map(|(a, c)| (*a, *c)).collect()
            })
            .unwrap_or_default()
    }

    /// Maps an interaction count to a trust score.
    fn score_from_count(&self, count: u32) -> TrustScore {
        let trusted_threshold = self.threshold.saturating_mul(3);
        if count >= trusted_threshold {
            TrustScore::Trusted
        } else if count >= self.threshold {
            TrustScore::Seen
        } else {
            TrustScore::Unknown
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    #[test]
    fn new_address_is_unknown() {
        let scorer = TrustScorer::new(3);
        assert_eq!(scorer.get_trust_score(&make_addr(0x01)), TrustScore::Unknown);
    }

    #[test]
    fn becomes_seen_at_threshold() {
        let scorer = TrustScorer::new(3);
        let addr = make_addr(0x01);

        scorer.record_interaction(&addr);
        scorer.record_interaction(&addr);
        assert_eq!(scorer.get_trust_score(&addr), TrustScore::Unknown);

        scorer.record_interaction(&addr);
        assert_eq!(scorer.get_trust_score(&addr), TrustScore::Seen);
    }

    #[test]
    fn becomes_trusted_at_3x_threshold() {
        let scorer = TrustScorer::new(3);
        let addr = make_addr(0x01);

        for _ in 0..8 {
            scorer.record_interaction(&addr);
        }
        assert_eq!(scorer.get_trust_score(&addr), TrustScore::Seen);

        scorer.record_interaction(&addr); // 9th = 3 * 3
        assert_eq!(scorer.get_trust_score(&addr), TrustScore::Trusted);
    }

    #[test]
    fn no_auto_promote_without_interaction() {
        let scorer = TrustScorer::new(3);
        let addr = make_addr(0x01);

        // Just checking score doesn't change it.
        for _ in 0..100 {
            let _ = scorer.get_trust_score(&addr);
        }
        assert_eq!(scorer.get_trust_score(&addr), TrustScore::Unknown);
        assert_eq!(scorer.get_interaction_count(&addr), 0);
    }

    #[test]
    fn different_addresses_independent() {
        let scorer = TrustScorer::new(2);
        let a = make_addr(0x01);
        let b = make_addr(0x02);

        scorer.record_interaction(&a);
        scorer.record_interaction(&a);
        assert_eq!(scorer.get_trust_score(&a), TrustScore::Seen);
        assert_eq!(scorer.get_trust_score(&b), TrustScore::Unknown);
    }

    #[test]
    fn load_from_pairs() {
        let scorer = TrustScorer::new(3);
        let addr = make_addr(0x01);

        scorer.load_from_pairs(&[(addr, 9)]);
        assert_eq!(scorer.get_trust_score(&addr), TrustScore::Trusted);
        assert_eq!(scorer.get_interaction_count(&addr), 9);
    }

    #[test]
    fn export_pairs() {
        let scorer = TrustScorer::new(3);
        let a = make_addr(0x01);
        let b = make_addr(0x02);

        scorer.record_interaction(&a);
        scorer.record_interaction(&b);
        scorer.record_interaction(&b);

        let pairs = scorer.export_pairs();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn saturating_count() {
        let scorer = TrustScorer::new(3);
        let addr = make_addr(0x01);

        // Pre-load near u32::MAX.
        scorer.load_from_pairs(&[(addr, u32::MAX - 1)]);
        scorer.record_interaction(&addr);
        assert_eq!(scorer.get_interaction_count(&addr), u32::MAX);

        // One more — should saturate, not overflow.
        scorer.record_interaction(&addr);
        assert_eq!(scorer.get_interaction_count(&addr), u32::MAX);
    }

    #[test]
    fn trust_score_ordering() {
        assert!(TrustScore::Unknown < TrustScore::Seen);
        assert!(TrustScore::Seen < TrustScore::Trusted);
    }
}