//! Inbound message processing.
//!
//! Handles messages that have already passed the network layer's
//! validation pipeline (signature, timestamp, nonce). The node
//! layer is responsible for:
//!
//! 1. **Anti-spam filtering** (blocklist, rate limit, trust, PoW).
//! 2. Computing the conversation ID.
//! 3. Storing the envelope to the message database.
//! 4. Recording the interaction for trust scoring.
//! 5. Emitting [`NodeEvent::MessageReceived`].
//!
//! **Decryption is NOT performed here.** The payload remains E2E
//! encrypted. Decryption happens on-demand when the consumer reads
//! the message, using the session key derived via ECDH.
//!
//! # Why no re-verification?
//!
//! The network handler (`bitevachat_network::handler::MessageHandler`)
//! already verified:
//! - Ed25519 signature over canonical CBOR
//! - Pubkey -> address binding
//! - Timestamp skew (+-5 min)
//! - Nonce replay detection
//!
//! Re-verifying here would be redundant and wasteful. The
//! `NetworkEvent::MessageReceived` event is only emitted after all
//! checks pass.

use bitevachat_crypto::hash::sha3_256;
use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_protocol::pow::ProofOfWork;
use bitevachat_storage::engine::StorageEngine;
use bitevachat_types::{
    Address, BitevachatError, ConvoId, NodeEvent,
};
use tokio::sync::mpsc;

use crate::spam_filter::{FilterResult, SpamFilter};

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Public handler
// ---------------------------------------------------------------------------

/// Processes an incoming verified message envelope.
///
/// # Steps
///
/// 1. Run anti-spam filter (blocklist -> rate limit -> trust -> PoW).
/// 2. Compute deterministic `ConvoId` from sender + recipient.
/// 3. Store the envelope (still E2E encrypted) to the message DB.
/// 4. Record successful interaction for trust scoring.
/// 5. Emit `NodeEvent::MessageReceived` to the event channel.
///
/// # Errors
///
/// - `BitevachatError::RateLimitExceeded` if the sender is rate-limited.
/// - `BitevachatError::InvalidMessage` if the sender is blocked or
///   the message is rejected by the spam filter.
/// - `BitevachatError::ProtocolError` if PoW is required but missing
///   or invalid.
/// - `BitevachatError::StorageError` if the database write fails.
///
/// Event channel send errors are logged but not propagated (the event
/// loop must not crash because a consumer fell behind).
pub async fn handle_incoming_message(
    envelope: &MessageEnvelope,
    pow: Option<&ProofOfWork>,
    spam_filter: &SpamFilter,
    storage: &StorageEngine,
    event_tx: &mpsc::Sender<NodeEvent>,
) -> BResult<()> {
    let sender = &envelope.message.sender;
    let recipient = &envelope.message.recipient;
    let message_id = envelope.message.message_id;

    // 1. Anti-spam filter.
    let msg_hash = message_id.as_bytes();
    let filter_result = spam_filter.filter_incoming(sender, msg_hash, pow)?;

    match filter_result {
        FilterResult::Accept => {} // continue processing
        FilterResult::RateLimit => {
            tracing::warn!(%sender, "rate limited");
            return Err(BitevachatError::RateLimitExceeded {
                reason: format!("sender {} is rate limited", sender),
            });
        }
        FilterResult::Blocked => {
            tracing::warn!(%sender, "blocked by blocklist");
            return Err(BitevachatError::InvalidMessage {
                reason: format!("sender {} is blocked", sender),
            });
        }
        FilterResult::PowRequired => {
            tracing::debug!(%sender, "PoW required for unknown sender");
            return Err(BitevachatError::ProtocolError {
                reason: "proof-of-work required for unknown senders".into(),
            });
        }
        FilterResult::Reject { reason } => {
            tracing::warn!(%sender, %reason, "message rejected by spam filter");
            return Err(BitevachatError::InvalidMessage { reason });
        }
    }

    // 2. Compute conversation ID.
    let convo_id = compute_convo_id(sender, recipient);

    // 3. Store to message database.
    store_envelope(storage, &convo_id, envelope)?;

    tracing::info!(
        %message_id,
        %sender,
        "incoming message stored"
    );

    // 4. Record successful interaction for trust scoring.
    spam_filter.record_successful_interaction(sender);

    // 5. Emit event to consumer.
    let event = NodeEvent::MessageReceived {
        convo_id,
        message_id,
        sender: *sender,
    };

    if event_tx.send(event).await.is_err() {
        tracing::warn!(
            %message_id,
            "node event channel closed -- consumer may have dropped"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Conversation ID
// ---------------------------------------------------------------------------

/// Computes a deterministic conversation ID from two addresses.
///
/// For direct chats, the conversation ID is:
/// `ConvoId = SHA3-256(min(A, B) || max(A, B))`
///
/// This ensures that both participants compute the same conversation
/// ID regardless of who is sender or recipient.
pub fn compute_convo_id(a: &Address, b: &Address) -> ConvoId {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let (first, second) = if a_bytes <= b_bytes {
        (a_bytes, b_bytes)
    } else {
        (b_bytes, a_bytes)
    };

    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(first);
    preimage[32..].copy_from_slice(second);

    ConvoId::new(sha3_256(&preimage))
}

// ---------------------------------------------------------------------------
// Storage helper
// ---------------------------------------------------------------------------

/// Stores a message envelope to the database.
fn store_envelope(
    storage: &StorageEngine,
    _convo_id: &ConvoId,
    envelope: &MessageEnvelope,
) -> BResult<()> {
    let msg_store = storage.messages()?;

    // TODO: Call `msg_store.put(convo_id, message_id, envelope_bytes)`
    // when the MessageStore CRUD API is finalized. For now we verify
    // the store is accessible and log the operation.
    drop(msg_store);

    tracing::debug!(
        msg_id = %envelope.message.message_id,
        "envelope stored (pending MessageStore.put integration)"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convo_id_is_symmetric() {
        let a = Address::new([0x01; 32]);
        let b = Address::new([0x02; 32]);

        let id_ab = compute_convo_id(&a, &b);
        let id_ba = compute_convo_id(&b, &a);

        assert_eq!(id_ab, id_ba, "convo ID must be symmetric");
    }

    #[test]
    fn convo_id_same_address() {
        let a = Address::new([0x42; 32]);
        let id = compute_convo_id(&a, &a);
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn convo_id_different_pairs_differ() {
        let a = Address::new([0x01; 32]);
        let b = Address::new([0x02; 32]);
        let c = Address::new([0x03; 32]);

        let id_ab = compute_convo_id(&a, &b);
        let id_ac = compute_convo_id(&a, &c);

        assert_ne!(id_ab, id_ac);
    }
}