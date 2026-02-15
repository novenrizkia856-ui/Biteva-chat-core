//! Integration tests for bitevachat-protocol.
//!
//! All tests use deterministic keypairs (fixed seeds), fixed
//! timestamps, and fixed nonces. No test depends on randomness
//! for its assertions.

use bitevachat_crypto::hash::compute_message_id;
use bitevachat_crypto::signing::{pubkey_to_address, Keypair, PublicKey, Signature};
use bitevachat_types::{
    Address, BitevachatError, MessageId, NodeId, Nonce, PayloadType, Timestamp,
};
use chrono::TimeZone;

use bitevachat_protocol::canonical::{from_canonical_cbor, to_canonical_cbor};
use bitevachat_protocol::message::{Message, MessageEnvelope};
use bitevachat_protocol::nonce::NonceCache;
use bitevachat_protocol::signing::{sign_message, verify_envelope_with_skew};
use bitevachat_protocol::validation::{validate_message_id, validate_timestamp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic keypair from a fixed seed.
fn test_keypair() -> Keypair {
    Keypair::from_seed(&[0x42u8; 32])
}

/// Second deterministic keypair (different seed).
fn other_keypair() -> Keypair {
    Keypair::from_seed(&[0x99u8; 32])
}

/// Fixed deterministic timestamp.
fn fixed_timestamp() -> Timestamp {
    let dt = chrono::Utc
        .with_ymd_and_hms(2025, 6, 15, 12, 0, 0)
        .single()
        .unwrap_or_else(chrono::Utc::now);
    Timestamp::from_datetime(dt)
}

/// Builds a valid deterministic Message for testing.
///
/// Uses `test_keypair()` as the sender.
fn build_test_message() -> Message {
    let kp = test_keypair();
    let sender = pubkey_to_address(&kp.public_key());
    let recipient = Address::new([0x02; 32]);
    let node_id = NodeId::new([0x03; 32]);
    let nonce = Nonce::new([0xAA; 12]);
    let timestamp = fixed_timestamp();
    let message_id = compute_message_id(&sender, &timestamp, &nonce);

    Message {
        sender,
        recipient,
        payload_type: PayloadType::Text,
        payload_ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
        node_id,
        nonce,
        timestamp,
        message_id,
    }
}

/// Generous skew for tests with fixed (past) timestamps.
fn test_skew() -> chrono::Duration {
    chrono::Duration::days(365 * 100) // effectively infinite
}

// ---------------------------------------------------------------------------
// 1. Canonical determinism
// ---------------------------------------------------------------------------

#[test]
fn canonical_serialize_deserialize_roundtrip_identical_bytes(
) -> std::result::Result<(), BitevachatError> {
    let msg = build_test_message();
    let bytes1 = to_canonical_cbor(&msg)?;
    let decoded = from_canonical_cbor(&bytes1)?;
    let bytes2 = to_canonical_cbor(&decoded)?;
    assert_eq!(
        bytes1, bytes2,
        "serialize → deserialize → serialize must produce identical bytes"
    );
    Ok(())
}

#[test]
fn canonical_encoding_is_deterministic() -> std::result::Result<(), BitevachatError> {
    let msg = build_test_message();
    let a = to_canonical_cbor(&msg)?;
    let b = to_canonical_cbor(&msg)?;
    assert_eq!(a, b);
    Ok(())
}

#[test]
fn canonical_fields_roundtrip_correctly() -> std::result::Result<(), BitevachatError> {
    let original = build_test_message();
    let bytes = to_canonical_cbor(&original)?;
    let decoded = from_canonical_cbor(&bytes)?;

    assert_eq!(original.sender, decoded.sender);
    assert_eq!(original.recipient, decoded.recipient);
    assert_eq!(original.node_id, decoded.node_id);
    assert_eq!(original.nonce, decoded.nonce);
    assert_eq!(original.message_id, decoded.message_id);
    assert_eq!(original.payload_type, decoded.payload_type);
    assert_eq!(original.payload_ciphertext, decoded.payload_ciphertext);
    assert_eq!(
        original.timestamp.as_datetime(),
        decoded.timestamp.as_datetime()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Signature round-trip
// ---------------------------------------------------------------------------

#[test]
fn sign_and_verify_roundtrip() -> std::result::Result<(), BitevachatError> {
    let kp = test_keypair();
    let msg = build_test_message();
    let envelope = sign_message(&kp, msg)?;

    let verified = verify_envelope_with_skew(
        &envelope,
        &kp.public_key(),
        test_skew(),
    )?;

    assert_eq!(verified.message.sender, envelope.message.sender);
    assert_eq!(
        verified.sender_public_key.as_bytes(),
        kp.public_key().as_bytes()
    );
    Ok(())
}

#[test]
fn wrong_public_key_fails_verification() -> std::result::Result<(), BitevachatError> {
    let kp = test_keypair();
    let msg = build_test_message();
    let envelope = sign_message(&kp, msg)?;

    // Verify with a different key.
    let wrong_pk = other_keypair().public_key();
    let result = verify_envelope_with_skew(&envelope, &wrong_pk, test_skew());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn tampered_ciphertext_fails_signature() -> std::result::Result<(), BitevachatError> {
    let kp = test_keypair();
    let msg = build_test_message();
    let mut envelope = sign_message(&kp, msg)?;

    // Tamper with payload.
    envelope.message.payload_ciphertext = vec![0xFF; 100];

    let result = verify_envelope_with_skew(
        &envelope,
        &kp.public_key(),
        test_skew(),
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn forged_signature_rejected() -> std::result::Result<(), BitevachatError> {
    let kp = test_keypair();
    let msg = build_test_message();
    let original = sign_message(&kp, msg)?;

    // Forge a signature (sign with different keypair).
    let other = other_keypair();
    let canonical = to_canonical_cbor(&original.message)?;
    let forged_sig = other.sign(&canonical);

    let forged_envelope = MessageEnvelope {
        message: original.message.clone(),
        signature: forged_sig,
    };

    // Verify with original sender's key — must fail.
    let result = verify_envelope_with_skew(
        &forged_envelope,
        &kp.public_key(),
        test_skew(),
    );
    assert!(result.is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Replay rejection (NonceCache)
// ---------------------------------------------------------------------------

#[test]
fn nonce_cache_rejects_replay() -> std::result::Result<(), BitevachatError> {
    let mut cache = NonceCache::new(1000);
    let sender = Address::new([0x01; 32]);
    let nonce = Nonce::new([0xAA; 12]);

    cache.check_and_insert(&sender, &nonce)?;

    // Second insert of same (sender, nonce) must fail.
    let result = cache.check_and_insert(&sender, &nonce);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn nonce_cache_allows_different_sender_same_nonce() -> std::result::Result<(), BitevachatError> {
    let mut cache = NonceCache::new(1000);
    let nonce = Nonce::new([0xAA; 12]);

    cache.check_and_insert(&Address::new([0x01; 32]), &nonce)?;
    cache.check_and_insert(&Address::new([0x02; 32]), &nonce)?;
    assert_eq!(cache.len(), 2);
    Ok(())
}

#[test]
fn nonce_cache_eviction_allows_old_nonce_reuse() -> std::result::Result<(), BitevachatError> {
    let mut cache = NonceCache::new(2);
    let sender = Address::new([0x01; 32]);

    cache.check_and_insert(&sender, &Nonce::new([0x01; 12]))?;
    cache.check_and_insert(&sender, &Nonce::new([0x02; 12]))?;
    // Full. Insert third; evicts first.
    cache.check_and_insert(&sender, &Nonce::new([0x03; 12]))?;

    // First nonce was evicted; re-insert should succeed.
    cache.check_and_insert(&sender, &Nonce::new([0x01; 12]))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Timestamp skew rejection
// ---------------------------------------------------------------------------

#[test]
fn timestamp_far_past_rejected() {
    let dt = chrono::Utc
        .with_ymd_and_hms(2000, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(chrono::Utc::now);
    let ts = Timestamp::from_datetime(dt);
    let skew = chrono::Duration::seconds(300);
    assert!(validate_timestamp(&ts, skew).is_err());
}

#[test]
fn timestamp_far_future_rejected() {
    let dt = chrono::Utc::now() + chrono::Duration::hours(2);
    let ts = Timestamp::from_datetime(dt);
    let skew = chrono::Duration::seconds(300);
    assert!(validate_timestamp(&ts, skew).is_err());
}

#[test]
fn timestamp_within_skew_accepted() -> std::result::Result<(), BitevachatError> {
    let dt = chrono::Utc::now() - chrono::Duration::seconds(30);
    let ts = Timestamp::from_datetime(dt);
    let skew = chrono::Duration::seconds(300);
    validate_timestamp(&ts, skew)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Malformed CBOR rejection
// ---------------------------------------------------------------------------

#[test]
fn malformed_cbor_bytes_rejected() {
    let garbage = vec![0xFF, 0xFE, 0xFD, 0x00, 0x01];
    let result = from_canonical_cbor(&garbage);
    assert!(result.is_err());
}

#[test]
fn cbor_non_map_rejected() {
    let mut buf = Vec::new();
    let _ = ciborium::into_writer(&ciborium::Value::Integer(42.into()), &mut buf);
    let result = from_canonical_cbor(&buf);
    assert!(result.is_err());
}

#[test]
fn cbor_extra_field_rejected() {
    // 9 entries instead of 8.
    let entries: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (ciborium::Value::Text("nonce".into()), ciborium::Value::Bytes(vec![0xAA; 12])),
        (ciborium::Value::Text("sender".into()), ciborium::Value::Bytes(vec![0x01; 32])),
        (ciborium::Value::Text("node_id".into()), ciborium::Value::Bytes(vec![0x03; 32])),
        (ciborium::Value::Text("recipient".into()), ciborium::Value::Bytes(vec![0x02; 32])),
        (ciborium::Value::Text("timestamp".into()), ciborium::Value::Text("2025-06-15T12:00:00+00:00".into())),
        (ciborium::Value::Text("message_id".into()), ciborium::Value::Bytes(vec![0x00; 32])),
        (ciborium::Value::Text("payload_type".into()), ciborium::Value::Text("text".into())),
        (ciborium::Value::Text("payload_ciphertext".into()), ciborium::Value::Bytes(vec![0xDE])),
        (ciborium::Value::Text("extra_field".into()), ciborium::Value::Bool(true)),
    ];
    let mut buf = Vec::new();
    let _ = ciborium::into_writer(&ciborium::Value::Map(entries), &mut buf);
    let result = from_canonical_cbor(&buf);
    assert!(result.is_err());
}

#[test]
fn cbor_missing_field_rejected() {
    // 7 entries — missing "payload_ciphertext".
    let entries: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (ciborium::Value::Text("nonce".into()), ciborium::Value::Bytes(vec![0xAA; 12])),
        (ciborium::Value::Text("sender".into()), ciborium::Value::Bytes(vec![0x01; 32])),
        (ciborium::Value::Text("node_id".into()), ciborium::Value::Bytes(vec![0x03; 32])),
        (ciborium::Value::Text("recipient".into()), ciborium::Value::Bytes(vec![0x02; 32])),
        (ciborium::Value::Text("timestamp".into()), ciborium::Value::Text("2025-06-15T12:00:00+00:00".into())),
        (ciborium::Value::Text("message_id".into()), ciborium::Value::Bytes(vec![0x00; 32])),
        (ciborium::Value::Text("payload_type".into()), ciborium::Value::Text("text".into())),
    ];
    let mut buf = Vec::new();
    let _ = ciborium::into_writer(&ciborium::Value::Map(entries), &mut buf);
    let result = from_canonical_cbor(&buf);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 6. Message ID tampering rejection
// ---------------------------------------------------------------------------

#[test]
fn tampered_message_id_rejected_by_validation() -> std::result::Result<(), BitevachatError> {
    let mut msg = build_test_message();
    // Tamper with message_id.
    msg.message_id = MessageId::new([0xFF; 32]);
    assert!(validate_message_id(&msg).is_err());
    Ok(())
}

#[test]
fn tampered_message_id_rejected_during_verify() -> std::result::Result<(), BitevachatError> {
    let kp = test_keypair();
    let mut msg = build_test_message();

    // Build envelope with valid signature over original message.
    let envelope = sign_message(&kp, msg.clone())?;

    // Tamper with message_id in the envelope.
    let mut tampered_envelope = MessageEnvelope {
        message: envelope.message.clone(),
        signature: envelope.signature,
    };
    tampered_envelope.message.message_id = MessageId::new([0xFF; 32]);

    // Signature check will fail because canonical bytes changed.
    let result = verify_envelope_with_skew(
        &tampered_envelope,
        &kp.public_key(),
        test_skew(),
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn tampered_sender_rejected_during_verify() -> std::result::Result<(), BitevachatError> {
    let kp = test_keypair();
    let msg = build_test_message();
    let mut envelope = sign_message(&kp, msg)?;

    // Tamper with sender.
    envelope.message.sender = Address::new([0xFF; 32]);

    let result = verify_envelope_with_skew(
        &envelope,
        &kp.public_key(),
        test_skew(),
    );
    assert!(result.is_err());
    Ok(())
}