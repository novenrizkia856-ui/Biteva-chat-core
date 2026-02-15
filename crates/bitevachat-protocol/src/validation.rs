//! Message validation: timestamp skew, message-ID integrity, and
//! schema checks.
//!
//! These functions are called during envelope verification
//! ([`crate::signing::verify_envelope`]) but are also available
//! independently for custom validation pipelines.

use bitevachat_crypto::hash::compute_message_id;
use bitevachat_types::{BitevachatError, Result, Timestamp};
use chrono::Utc;

use crate::message::Message;

// ---------------------------------------------------------------------------
// Timestamp validation
// ---------------------------------------------------------------------------

/// Validates that a timestamp is within `±max_skew` of the current
/// UTC time.
///
/// # Errors
///
/// Returns [`BitevachatError::ProtocolError`] if:
/// - The timestamp is more than `max_skew` in the past.
/// - The timestamp is more than `max_skew` in the future.
pub fn validate_timestamp(ts: &Timestamp, max_skew: chrono::Duration) -> Result<()> {
    let now = Utc::now();
    let msg_time = ts.as_datetime();

    let delta = now.signed_duration_since(*msg_time);

    // delta > 0 means message is in the past.
    // delta < 0 means message is in the future.
    if delta > max_skew {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "timestamp too far in the past: message at {msg_time}, \
                 now {now}, delta {delta}"
            ),
        });
    }

    if delta < -max_skew {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "timestamp too far in the future: message at {msg_time}, \
                 now {now}, delta {delta}"
            ),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Message ID validation
// ---------------------------------------------------------------------------

/// Validates the `message_id` field by recomputing
/// `SHA3-256(sender || timestamp || nonce)` and comparing.
///
/// # Errors
///
/// Returns [`BitevachatError::ProtocolError`] if the recomputed ID
/// does not match `message.message_id`.
pub fn validate_message_id(message: &Message) -> Result<()> {
    let expected = compute_message_id(
        &message.sender,
        &message.timestamp,
        &message.nonce,
    );

    if expected != message.message_id {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "message_id mismatch: expected {expected}, got {}",
                message.message_id
            ),
        });
    }

    Ok(())
}

/// Validates the structural integrity of a [`Message`].
///
/// Checks that all fixed-length fields have the expected sizes. This
/// is a defence-in-depth measure — the type system already enforces
/// most constraints — but catches issues that could arise from
/// unchecked deserialization.
///
/// # Checks
///
/// - `sender`: 32 bytes (enforced by `Address`)
/// - `recipient`: 32 bytes (enforced by `Address`)
/// - `node_id`: 32 bytes (enforced by `NodeId`)
/// - `message_id`: 32 bytes (enforced by `MessageId`)
/// - `nonce`: 12 bytes (enforced by `Nonce`)
/// - `payload_ciphertext`: non-empty
///
/// # Errors
///
/// Returns [`BitevachatError::ProtocolError`] if any check fails.
pub fn validate_schema(message: &Message) -> Result<()> {
    // Fixed-size fields are enforced by the type system ([u8; N] newtypes).
    // Runtime check: payload_ciphertext must not be empty.
    if message.payload_ciphertext.is_empty() {
        return Err(BitevachatError::ProtocolError {
            reason: "payload_ciphertext must not be empty".into(),
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
    use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType};
    use chrono::TimeZone;

    fn make_valid_message() -> Message {
        let sender = Address::new([0x01; 32]);
        let nonce = Nonce::new([0xAA; 12]);
        let dt = Utc::now();
        let timestamp = Timestamp::from_datetime(dt);
        let message_id = compute_message_id(&sender, &timestamp, &nonce);

        Message {
            sender,
            recipient: Address::new([0x02; 32]),
            payload_type: PayloadType::Text,
            payload_ciphertext: vec![0xFF; 48],
            node_id: NodeId::new([0x03; 32]),
            nonce,
            timestamp,
            message_id,
        }
    }

    #[test]
    fn valid_message_passes_all_checks() -> std::result::Result<(), BitevachatError> {
        let msg = make_valid_message();
        validate_message_id(&msg)?;
        let skew = chrono::Duration::seconds(300);
        validate_timestamp(&msg.timestamp, skew)?;
        validate_schema(&msg)?;
        Ok(())
    }

    #[test]
    fn tampered_message_id_rejected() {
        let mut msg = make_valid_message();
        msg.message_id = MessageId::new([0xFF; 32]);
        assert!(validate_message_id(&msg).is_err());
    }

    #[test]
    fn timestamp_in_past_rejected() {
        let dt = chrono::Utc
            .with_ymd_and_hms(2020, 1, 1, 0, 0, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now);
        let ts = Timestamp::from_datetime(dt);
        let skew = chrono::Duration::seconds(300);
        assert!(validate_timestamp(&ts, skew).is_err());
    }

    #[test]
    fn timestamp_in_future_rejected() {
        let dt = Utc::now() + chrono::Duration::hours(1);
        let ts = Timestamp::from_datetime(dt);
        let skew = chrono::Duration::seconds(300);
        assert!(validate_timestamp(&ts, skew).is_err());
    }

    #[test]
    fn timestamp_within_skew_accepted() -> std::result::Result<(), BitevachatError> {
        let dt = Utc::now() - chrono::Duration::seconds(60);
        let ts = Timestamp::from_datetime(dt);
        let skew = chrono::Duration::seconds(300);
        validate_timestamp(&ts, skew)?;
        Ok(())
    }

    #[test]
    fn empty_payload_rejected() {
        let mut msg = make_valid_message();
        msg.payload_ciphertext = Vec::new();
        assert!(validate_schema(&msg).is_err());
    }
}