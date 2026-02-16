//! Anti-spam filter orchestrator.
//!
//! The [`SpamFilter`] coordinates all anti-spam subsystems in a
//! strict evaluation order:
//!
//! 1. **Blocklist** — reject if sender is blocked (whitelist overrides).
//! 2. **Rate limit** — reject if sender exceeds message rate.
//! 3. **Trust score** — check sender's trust level.
//! 4. **PoW check** — require proof-of-work for `Unknown` senders.
//! 5. **Accept** — all checks passed.
//!
//! This order MUST NOT be changed. Blocklist must be first (cheapest
//! rejection), PoW last (most expensive verification).

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

use bitevachat_protocol::pow::{self, ProofOfWork};
use bitevachat_types::{Address, BitevachatError};

use crate::rate_limiter::RateLimiter;
use crate::trust::{TrustScore, TrustScorer};

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

/// Default maximum size of the PoW nonce replay cache.
const DEFAULT_POW_CACHE_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// FilterResult
// ---------------------------------------------------------------------------

/// Outcome of the spam filter evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterResult {
    /// Message passes all checks.
    Accept,
    /// Sender exceeded rate limit.
    RateLimit,
    /// Sender is on the blocklist.
    Blocked,
    /// Sender is unknown and must provide proof-of-work.
    PowRequired,
    /// Message rejected for a specific reason.
    Reject { reason: String },
}

// ---------------------------------------------------------------------------
// SpamConfig
// ---------------------------------------------------------------------------

/// Anti-spam configuration extracted from `AppConfig`.
#[derive(Clone, Debug)]
pub struct SpamConfig {
    /// Messages per minute per sender.
    pub rate_limit_per_min: u32,
    /// PoW difficulty in leading zero bits.
    pub pow_difficulty: u8,
    /// Whether PoW is required for unknown senders.
    pub enable_pow: bool,
    /// Interaction count threshold for trust promotion.
    pub trust_threshold: u32,
    /// Whether the blocklist is active.
    pub blocklist_enabled: bool,
}

impl From<&bitevachat_types::config::AppConfig> for SpamConfig {
    fn from(config: &bitevachat_types::config::AppConfig) -> Self {
        Self {
            rate_limit_per_min: config.rate_limit_per_min,
            pow_difficulty: config.pow_difficulty,
            enable_pow: config.enable_pow,
            trust_threshold: config.trust_threshold,
            blocklist_enabled: config.blocklist_enabled,
        }
    }
}

// ---------------------------------------------------------------------------
// PoW nonce replay cache
// ---------------------------------------------------------------------------

/// Bounded cache for detecting PoW nonce reuse.
///
/// Stores `(nonce, message_hash)` pairs. When the cache is full,
/// the oldest entry is evicted (FIFO). This prevents replay of
/// valid PoW proofs with different messages.
struct PowNonceCache {
    /// Set of seen `nonce_bytes ++ message_hash` (40 bytes each).
    seen: HashSet<[u8; 40]>,
    /// Insertion order for FIFO eviction.
    order: VecDeque<[u8; 40]>,
    /// Maximum cache size.
    max_size: usize,
}

impl PowNonceCache {
    fn new(max_size: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(max_size.min(1024)),
            order: VecDeque::with_capacity(max_size.min(1024)),
            max_size,
        }
    }

    /// Checks if a `(nonce, message_hash)` pair has been seen before.
    ///
    /// If not seen, inserts it into the cache and returns `true`.
    /// If already seen (replay), returns `false`.
    fn check_and_insert(&mut self, nonce: u64, message_hash: &[u8; 32]) -> bool {
        let key = Self::make_key(nonce, message_hash);

        if self.seen.contains(&key) {
            return false; // replay detected
        }

        // Evict oldest entries if at capacity.
        while self.order.len() >= self.max_size {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }

        self.seen.insert(key);
        self.order.push_back(key);
        true
    }

    /// Builds the 40-byte cache key: `nonce_le(8) || message_hash(32)`.
    fn make_key(nonce: u64, message_hash: &[u8; 32]) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[..8].copy_from_slice(&nonce.to_le_bytes());
        key[8..].copy_from_slice(message_hash);
        key
    }
}

// ---------------------------------------------------------------------------
// In-memory blocklist cache
// ---------------------------------------------------------------------------

/// In-memory blocklist and whitelist cache.
///
/// Loaded from `BlocklistStore` at startup. Modified via explicit
/// `add_*` / `remove_*` methods and synced back to storage by the
/// caller.
struct BlocklistCache {
    blocked: HashSet<Address>,
    whitelisted: HashSet<Address>,
}

impl BlocklistCache {
    fn new() -> Self {
        Self {
            blocked: HashSet::new(),
            whitelisted: HashSet::new(),
        }
    }

    /// Returns `true` if the address is effectively blocked.
    ///
    /// Whitelist overrides blocklist.
    fn is_blocked(&self, address: &Address) -> bool {
        self.blocked.contains(address) && !self.whitelisted.contains(address)
    }
}

// ---------------------------------------------------------------------------
// SpamFilter
// ---------------------------------------------------------------------------

/// Anti-spam filter that coordinates blocklist, rate limiting, trust
/// scoring, and proof-of-work verification.
///
/// All hot-path state is in-memory. Storage persistence is handled
/// by explicit load/save calls at startup and shutdown.
pub struct SpamFilter {
    /// Per-sender token bucket rate limiter.
    rate_limiter: RateLimiter,
    /// Trust scoring engine.
    trust_scorer: TrustScorer,
    /// PoW nonce replay detection cache.
    pow_cache: Mutex<PowNonceCache>,
    /// In-memory blocklist + whitelist.
    blocklist: Mutex<BlocklistCache>,
    /// PoW difficulty (leading zero bits).
    pow_difficulty: u8,
    /// Whether PoW is enabled.
    enable_pow: bool,
    /// Whether blocklist checks are active.
    blocklist_enabled: bool,
}

impl SpamFilter {
    /// Creates a new `SpamFilter` from configuration.
    pub fn new(config: SpamConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::new(config.rate_limit_per_min),
            trust_scorer: TrustScorer::new(config.trust_threshold),
            pow_cache: Mutex::new(PowNonceCache::new(DEFAULT_POW_CACHE_SIZE)),
            blocklist: Mutex::new(BlocklistCache::new()),
            pow_difficulty: config.pow_difficulty,
            enable_pow: config.enable_pow,
            blocklist_enabled: config.blocklist_enabled,
        }
    }

    // -----------------------------------------------------------------------
    // Core filter
    // -----------------------------------------------------------------------

    /// Evaluates an incoming message against all anti-spam rules.
    ///
    /// The `message_hash` is typically the message ID bytes
    /// (`envelope.message.message_id`). The `pow` is optional
    /// transport-level metadata.
    ///
    /// # Evaluation order (MUST NOT change)
    ///
    /// 1. Blocklist check
    /// 2. Rate limit check
    /// 3. Trust score check
    /// 4. PoW verification (for `Unknown` senders only)
    /// 5. Accept
    pub fn filter_incoming(
        &self,
        sender: &Address,
        message_hash: &[u8; 32],
        pow: Option<&ProofOfWork>,
    ) -> BResult<FilterResult> {
        // 1. Blocklist check.
        if self.blocklist_enabled {
            if self.is_blocked(sender) {
                return Ok(FilterResult::Blocked);
            }
        }

        // 2. Rate limit check.
        if let Err(_) = self.rate_limiter.check_rate(sender) {
            return Ok(FilterResult::RateLimit);
        }

        // 3. Trust score check.
        let trust = self.trust_scorer.get_trust_score(sender);

        // 4. PoW verification (only for Unknown senders when enabled).
        if self.enable_pow && trust == TrustScore::Unknown {
            match pow {
                None => {
                    return Ok(FilterResult::PowRequired);
                }
                Some(proof) => {
                    // Verify difficulty matches config.
                    if proof.difficulty < self.pow_difficulty {
                        return Ok(FilterResult::Reject {
                            reason: format!(
                                "PoW difficulty {} below required {}",
                                proof.difficulty, self.pow_difficulty,
                            ),
                        });
                    }

                    // Verify the proof itself.
                    pow::verify_pow(proof, message_hash).map_err(|e| {
                        BitevachatError::InvalidMessage {
                            reason: format!("PoW verification failed: {e}"),
                        }
                    })?;

                    // Check nonce replay.
                    let is_new = self
                        .pow_cache
                        .lock()
                        .map_err(|_| BitevachatError::ProtocolError {
                            reason: "PoW cache lock poisoned".into(),
                        })?
                        .check_and_insert(proof.nonce, message_hash);

                    if !is_new {
                        return Ok(FilterResult::Reject {
                            reason: "PoW nonce already used".into(),
                        });
                    }
                }
            }
        }

        // 5. Accept.
        Ok(FilterResult::Accept)
    }

    // -----------------------------------------------------------------------
    // Trust management
    // -----------------------------------------------------------------------

    /// Records a successful interaction for trust promotion.
    ///
    /// Call this AFTER a message has been fully processed and stored.
    pub fn record_successful_interaction(&self, address: &Address) {
        self.trust_scorer.record_interaction(address);
    }

    /// Returns the trust score for an address.
    pub fn get_trust_score(&self, address: &Address) -> TrustScore {
        self.trust_scorer.get_trust_score(address)
    }

    /// Returns a reference to the trust scorer for persistence ops.
    pub fn trust_scorer(&self) -> &TrustScorer {
        &self.trust_scorer
    }

    // -----------------------------------------------------------------------
    // Blocklist management
    // -----------------------------------------------------------------------

    /// Adds an address to the in-memory blocklist.
    pub fn add_to_blocklist(&self, address: Address) {
        if let Ok(mut bl) = self.blocklist.lock() {
            bl.blocked.insert(address);
        }
    }

    /// Removes an address from the in-memory blocklist.
    pub fn remove_from_blocklist(&self, address: &Address) {
        if let Ok(mut bl) = self.blocklist.lock() {
            bl.blocked.remove(address);
        }
    }

    /// Adds an address to the in-memory whitelist.
    pub fn add_to_whitelist(&self, address: Address) {
        if let Ok(mut bl) = self.blocklist.lock() {
            bl.whitelisted.insert(address);
        }
    }

    /// Removes an address from the in-memory whitelist.
    pub fn remove_from_whitelist(&self, address: &Address) {
        if let Ok(mut bl) = self.blocklist.lock() {
            bl.whitelisted.remove(address);
        }
    }

    /// Returns `true` if an address is effectively blocked.
    pub fn is_blocked(&self, address: &Address) -> bool {
        self.blocklist
            .lock()
            .ok()
            .map(|bl| bl.is_blocked(address))
            .unwrap_or(false)
    }

    /// Loads blocklist data from external pairs (e.g. from storage).
    ///
    /// Each pair is `(address, blocked, whitelisted)`.
    pub fn load_blocklist(
        &self,
        entries: &[(Address, bool, bool)],
    ) {
        if let Ok(mut bl) = self.blocklist.lock() {
            bl.blocked.clear();
            bl.whitelisted.clear();
            for (addr, blocked, whitelisted) in entries {
                if *blocked {
                    bl.blocked.insert(*addr);
                }
                if *whitelisted {
                    bl.whitelisted.insert(*addr);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitevachat_crypto::hash::sha3_256;

    fn test_config() -> SpamConfig {
        SpamConfig {
            rate_limit_per_min: 5,
            pow_difficulty: 4,
            enable_pow: true,
            trust_threshold: 3,
            blocklist_enabled: true,
        }
    }

    fn make_addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    fn make_hash(data: &[u8]) -> [u8; 32] {
        sha3_256(data)
    }

    #[test]
    fn accept_normal_message() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        // Promote sender to Seen (skip PoW requirement).
        for _ in 0..3 {
            filter.record_successful_interaction(&sender);
        }

        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::Accept);
    }

    #[test]
    fn blocklist_rejects() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        filter.add_to_blocklist(sender);
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::Blocked);
    }

    #[test]
    fn whitelist_overrides_blocklist() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        filter.add_to_blocklist(sender);
        filter.add_to_whitelist(sender);

        // Sender is blocked BUT whitelisted → not blocked.
        // Still Unknown trust → PowRequired.
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_ne!(result, FilterResult::Blocked);
    }

    #[test]
    fn rate_limit_rejects_after_n() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);

        // Promote to Seen to skip PoW.
        for _ in 0..3 {
            filter.record_successful_interaction(&sender);
        }

        // rate_limit_per_min = 5.
        for i in 0..5 {
            let hash = make_hash(&[i]);
            let result = filter
                .filter_incoming(&sender, &hash, None)
                .expect("should not error");
            assert_eq!(result, FilterResult::Accept, "message {} should pass", i);
        }

        // 6th message → rate limited.
        let hash = make_hash(b"excess");
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::RateLimit);
    }

    #[test]
    fn pow_required_for_unknown_sender() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::PowRequired);
    }

    #[test]
    fn valid_pow_accepted_for_unknown_sender() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        // Generate valid PoW.
        let proof = pow::generate_pow(&hash, 4).expect("should generate");

        let result = filter
            .filter_incoming(&sender, &hash, Some(&proof))
            .expect("should not error");
        assert_eq!(result, FilterResult::Accept);
    }

    #[test]
    fn invalid_pow_rejected() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        // Create a bogus PoW.
        let bad_proof = ProofOfWork {
            nonce: 999999,
            difficulty: 4,
            hash: [0xFF; 32],
        };

        let result = filter.filter_incoming(&sender, &hash, Some(&bad_proof));
        assert!(result.is_err());
    }

    #[test]
    fn pow_nonce_replay_rejected() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        let proof = pow::generate_pow(&hash, 4).expect("should generate");

        // First use → accept.
        let result = filter
            .filter_incoming(&sender, &hash, Some(&proof))
            .expect("should not error");
        assert_eq!(result, FilterResult::Accept);

        // Second use with same nonce + hash → replay rejected.
        // Need a fresh rate limiter token — use a different filter.
        let filter2 = SpamFilter::new(test_config());
        // Manually pre-insert the nonce.
        filter2
            .pow_cache
            .lock()
            .expect("lock")
            .check_and_insert(proof.nonce, &hash);

        let result = filter2
            .filter_incoming(&sender, &hash, Some(&proof))
            .expect("should not error");
        assert_eq!(
            result,
            FilterResult::Reject {
                reason: "PoW nonce already used".into(),
            }
        );
    }

    #[test]
    fn pow_not_required_for_seen_sender() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        // Promote to Seen.
        for _ in 0..3 {
            filter.record_successful_interaction(&sender);
        }

        // No PoW attached, but sender is Seen → accept.
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::Accept);
    }

    #[test]
    fn pow_disabled_skips_check() {
        let mut config = test_config();
        config.enable_pow = false;
        let filter = SpamFilter::new(config);

        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        // Unknown sender, no PoW, but PoW disabled → accept.
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::Accept);
    }

    #[test]
    fn blocklist_disabled_skips_check() {
        let mut config = test_config();
        config.blocklist_enabled = false;
        let filter = SpamFilter::new(config);

        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");
        filter.add_to_blocklist(sender);

        // Blocked, but blocklist disabled. Unknown → PowRequired.
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_ne!(result, FilterResult::Blocked);
    }

    #[test]
    fn trust_score_progression() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);

        assert_eq!(filter.get_trust_score(&sender), TrustScore::Unknown);

        for _ in 0..3 {
            filter.record_successful_interaction(&sender);
        }
        assert_eq!(filter.get_trust_score(&sender), TrustScore::Seen);

        for _ in 0..6 {
            filter.record_successful_interaction(&sender);
        }
        assert_eq!(filter.get_trust_score(&sender), TrustScore::Trusted);
    }

    #[test]
    fn filter_ordering_blocklist_before_rate_limit() {
        let filter = SpamFilter::new(test_config());
        let sender = make_addr(0x01);
        let hash = make_hash(b"msg1");

        // Block sender AND exhaust rate limit.
        filter.add_to_blocklist(sender);
        for i in 0..10 {
            let h = make_hash(&[i]);
            let _ = filter.filter_incoming(&sender, &h, None);
        }

        // Should get Blocked (checked first), not RateLimit.
        let result = filter
            .filter_incoming(&sender, &hash, None)
            .expect("should not error");
        assert_eq!(result, FilterResult::Blocked);
    }
}