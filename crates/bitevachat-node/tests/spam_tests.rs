//! Integration tests for the Bitevachat anti-spam system.
//!
//! All tests are deterministic. PoW tests use low difficulty (4 bits)
//! to avoid slow brute-force in CI. No external dependencies required
//! — all components tested via their public API.

use bitevachat_crypto::hash::sha3_256;
use bitevachat_node::rate_limiter::RateLimiter;
use bitevachat_node::spam_filter::{FilterResult, SpamConfig, SpamFilter};
use bitevachat_node::trust::{TrustScore, TrustScorer};
use bitevachat_protocol::pow::{self, ProofOfWork, MAX_DIFFICULTY};
use bitevachat_types::Address;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_addr(b: u8) -> Address {
    Address::new([b; 32])
}

fn make_hash(data: &[u8]) -> [u8; 32] {
    sha3_256(data)
}

fn test_config() -> SpamConfig {
    SpamConfig {
        rate_limit_per_min: 5,
        pow_difficulty: 4,
        enable_pow: true,
        trust_threshold: 3,
        blocklist_enabled: true,
    }
}

// ===========================================================================
// Rate limiter tests
// ===========================================================================

#[test]
fn rate_limit_allows_up_to_limit() {
    let limiter = RateLimiter::new(3);
    let sender = make_addr(0x01);

    assert!(limiter.check_rate(&sender).is_ok());
    assert!(limiter.check_rate(&sender).is_ok());
    assert!(limiter.check_rate(&sender).is_ok());
}

#[test]
fn rate_limit_rejects_after_n_messages() {
    let limiter = RateLimiter::new(3);
    let sender = make_addr(0x01);

    for _ in 0..3 {
        assert!(limiter.check_rate(&sender).is_ok());
    }
    // 4th message exceeds limit.
    let result = limiter.check_rate(&sender);
    assert!(result.is_err());
}

#[test]
fn rate_limit_senders_are_independent() {
    let limiter = RateLimiter::new(2);
    let alice = make_addr(0x01);
    let bob = make_addr(0x02);

    // Exhaust Alice's tokens.
    assert!(limiter.check_rate(&alice).is_ok());
    assert!(limiter.check_rate(&alice).is_ok());
    assert!(limiter.check_rate(&alice).is_err());

    // Bob is unaffected.
    assert!(limiter.check_rate(&bob).is_ok());
}

// ===========================================================================
// Trust scoring tests
// ===========================================================================

#[test]
fn trust_new_address_is_unknown() {
    let scorer = TrustScorer::new(3);
    assert_eq!(scorer.get_trust_score(&make_addr(0x01)), TrustScore::Unknown);
}

#[test]
fn trust_becomes_seen_at_threshold() {
    let scorer = TrustScorer::new(3);
    let addr = make_addr(0x01);

    scorer.record_interaction(&addr);
    scorer.record_interaction(&addr);
    assert_eq!(scorer.get_trust_score(&addr), TrustScore::Unknown);

    scorer.record_interaction(&addr); // 3rd
    assert_eq!(scorer.get_trust_score(&addr), TrustScore::Seen);
}

#[test]
fn trust_becomes_trusted_at_3x_threshold() {
    let scorer = TrustScorer::new(3);
    let addr = make_addr(0x01);

    for _ in 0..9 {
        scorer.record_interaction(&addr);
    }
    assert_eq!(scorer.get_trust_score(&addr), TrustScore::Trusted);
}

#[test]
fn trust_no_auto_promote_without_interaction() {
    let scorer = TrustScorer::new(3);
    let addr = make_addr(0x01);

    // Repeated reads do not promote.
    for _ in 0..100 {
        let _ = scorer.get_trust_score(&addr);
    }
    assert_eq!(scorer.get_trust_score(&addr), TrustScore::Unknown);
    assert_eq!(scorer.get_interaction_count(&addr), 0);
}

#[test]
fn trust_score_progression_is_deterministic() {
    let scorer = TrustScorer::new(2);
    let addr = make_addr(0x01);

    let scores: Vec<TrustScore> = (0..7)
        .map(|_| {
            scorer.record_interaction(&addr);
            scorer.get_trust_score(&addr)
        })
        .collect();

    // threshold=2, trusted_threshold=6
    assert_eq!(scores[0], TrustScore::Unknown); // count=1
    assert_eq!(scores[1], TrustScore::Seen);    // count=2
    assert_eq!(scores[2], TrustScore::Seen);    // count=3
    assert_eq!(scores[3], TrustScore::Seen);    // count=4
    assert_eq!(scores[4], TrustScore::Seen);    // count=5
    assert_eq!(scores[5], TrustScore::Trusted); // count=6
    assert_eq!(scores[6], TrustScore::Trusted); // count=7
}

// ===========================================================================
// PoW tests
// ===========================================================================

#[test]
fn pow_generate_verify_roundtrip() {
    let msg_hash = make_hash(b"test message");
    let proof = pow::generate_pow(&msg_hash, 4).expect("should generate");
    assert!(pow::verify_pow(&proof, &msg_hash).is_ok());
}

#[test]
fn pow_rejects_wrong_message_hash() {
    let msg_hash = make_hash(b"original");
    let proof = pow::generate_pow(&msg_hash, 4).expect("should generate");

    let wrong = make_hash(b"different");
    assert!(pow::verify_pow(&proof, &wrong).is_err());
}

#[test]
fn pow_rejects_tampered_hash_field() {
    let msg_hash = make_hash(b"test");
    let mut proof = pow::generate_pow(&msg_hash, 4).expect("should generate");
    proof.hash[0] ^= 0xFF; // corrupt embedded hash
    assert!(pow::verify_pow(&proof, &msg_hash).is_err());
}

#[test]
fn pow_rejects_tampered_nonce() {
    let msg_hash = make_hash(b"test");
    let mut proof = pow::generate_pow(&msg_hash, 4).expect("should generate");
    proof.nonce = proof.nonce.wrapping_add(1);
    assert!(pow::verify_pow(&proof, &msg_hash).is_err());
}

#[test]
fn pow_difficulty_exceeds_max_rejected() {
    let msg_hash = make_hash(b"test");
    assert!(pow::generate_pow(&msg_hash, MAX_DIFFICULTY + 1).is_err());
}

#[test]
fn pow_verify_difficulty_exceeds_max_rejected() {
    let bad = ProofOfWork {
        nonce: 0,
        difficulty: MAX_DIFFICULTY + 1,
        hash: [0u8; 32],
    };
    assert!(pow::verify_pow(&bad, &make_hash(b"test")).is_err());
}

#[test]
fn pow_difficulty_zero_always_valid() {
    let msg_hash = make_hash(b"anything");
    let proof = pow::generate_pow(&msg_hash, 0).expect("difficulty 0");
    assert!(pow::verify_pow(&proof, &msg_hash).is_ok());
}

// ===========================================================================
// SpamFilter integration tests
// ===========================================================================

#[test]
fn spam_filter_blocklist_rejects() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    filter.add_to_blocklist(sender);
    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_eq!(result, FilterResult::Blocked);
}

#[test]
fn spam_filter_whitelist_overrides_blocklist() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    filter.add_to_blocklist(sender);
    filter.add_to_whitelist(sender);

    // Not blocked (whitelist overrides).
    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_ne!(result, FilterResult::Blocked);
}

#[test]
fn spam_filter_pow_required_for_unknown() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_eq!(result, FilterResult::PowRequired);
}

#[test]
fn spam_filter_valid_pow_accepted() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    let proof = pow::generate_pow(&hash, 4).expect("should generate");
    let result = filter
        .filter_incoming(&sender, &hash, Some(&proof))
        .expect("ok");
    assert_eq!(result, FilterResult::Accept);
}

#[test]
fn spam_filter_invalid_pow_rejected() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    let bad_proof = ProofOfWork {
        nonce: 999999,
        difficulty: 4,
        hash: [0xFF; 32],
    };

    // verify_pow fails -> error propagated.
    let result = filter.filter_incoming(&sender, &hash, Some(&bad_proof));
    assert!(result.is_err());
}

#[test]
fn spam_filter_rate_limit_after_n() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);

    // Promote to Seen to skip PoW.
    for _ in 0..3 {
        filter.record_successful_interaction(&sender);
    }

    // rate_limit_per_min = 5, send 5 messages.
    for i in 0u8..5 {
        let hash = make_hash(&[i]);
        let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
        assert_eq!(result, FilterResult::Accept);
    }

    // 6th message -> rate limited.
    let hash = make_hash(b"excess");
    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_eq!(result, FilterResult::RateLimit);
}

#[test]
fn spam_filter_trust_score_progression() {
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
fn spam_filter_seen_sender_skips_pow() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    // Promote to Seen.
    for _ in 0..3 {
        filter.record_successful_interaction(&sender);
    }

    // No PoW attached -> still accepted.
    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_eq!(result, FilterResult::Accept);
}

#[test]
fn spam_filter_blocklist_checked_before_rate_limit() {
    let filter = SpamFilter::new(test_config());
    let sender = make_addr(0x01);

    // Block and exhaust rate limit.
    filter.add_to_blocklist(sender);
    for _ in 0..3 {
        filter.record_successful_interaction(&sender);
    }
    for i in 0u8..20 {
        let _ = filter.filter_incoming(&sender, &make_hash(&[i]), None);
    }

    // Should be Blocked, not RateLimit.
    let result = filter
        .filter_incoming(&sender, &make_hash(b"final"), None)
        .expect("ok");
    assert_eq!(result, FilterResult::Blocked);
}

#[test]
fn spam_filter_pow_disabled_skips_check() {
    let mut config = test_config();
    config.enable_pow = false;
    let filter = SpamFilter::new(config);

    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");

    // Unknown sender, no PoW, PoW disabled -> Accept.
    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_eq!(result, FilterResult::Accept);
}

#[test]
fn spam_filter_blocklist_disabled_skips_check() {
    let mut config = test_config();
    config.blocklist_enabled = false;
    let filter = SpamFilter::new(config);

    let sender = make_addr(0x01);
    let hash = make_hash(b"msg1");
    filter.add_to_blocklist(sender);

    // Blocked but blocklist disabled. Unknown -> PowRequired.
    let result = filter.filter_incoming(&sender, &hash, None).expect("ok");
    assert_ne!(result, FilterResult::Blocked);
}