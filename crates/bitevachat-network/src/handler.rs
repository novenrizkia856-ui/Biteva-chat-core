//! Inbound message validation handler.
//!
//! [`MessageHandler`] processes incoming [`WireMessage`]s through
//! the full validation pipeline: signature verification, timestamp
//! check, nonce replay detection. Only messages passing all checks
//! produce [`Ack::Ok`]; failures return the appropriate [`Ack`]
//! variant without storing or forwarding the message.
//!
//! # Validation order (security-critical)
//!
//! 1. Verify sender pubkey matches sender address.
//! 2. Verify Ed25519 signature (BEFORE any decryption).
//! 3. Validate timestamp skew.
//! 4. Validate nonce (replay detection).
//! 5. Emit [`NetworkEvent::MessageReceived`].
//! 6. Return [`Ack::Ok`].

use std::sync::{Arc, Mutex};

use bitevachat_crypto::signing::{pubkey_to_address, verify, PublicKey, Signature};
use bitevachat_protocol::canonical::to_canonical_cbor;
use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_protocol::nonce::NonceCache;
use bitevachat_types::Timestamp;
use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::events::NetworkEvent;
use crate::protocol::Ack;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum allowed clock skew for FUTURE timestamps
/// (message claims to be from the future -- strict: 5 minutes).
pub const DEFAULT_MAX_TIMESTAMP_SKEW_SECS: u64 = 300;

/// Maximum allowed age for PAST timestamps.
///
/// Messages relayed through circuit relays or retried from the
/// pending queue can arrive significantly later than their creation
/// time.  We allow up to 30 minutes of past drift to accommodate
/// relay setup, pending retries, and modest clock differences.
pub const MAX_PAST_TIMESTAMP_SKEW_SECS: u64 = 1800;

// ---------------------------------------------------------------------------
// HandlerResult
// ---------------------------------------------------------------------------

/// Result of processing an inbound message.
pub struct HandlerResult {
    /// The ACK to send back to the sender.
    pub ack: Ack,
}

// ---------------------------------------------------------------------------
// MessageHandler
// ---------------------------------------------------------------------------

/// Stateful handler for inbound message validation.
///
/// Holds shared references to the nonce cache and event channel.
/// Thread-safe via `Arc<Mutex<>>` on the nonce cache and `mpsc`
/// channel for events.
pub struct MessageHandler {
    /// Bounded FIFO nonce cache for replay detection.
    nonce_cache: Arc<Mutex<NonceCache>>,

    /// Maximum allowed clock skew in seconds.
    max_timestamp_skew_secs: u64,

    /// Channel for emitting validated network events.
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
}

impl MessageHandler {
    /// Creates a new handler.
    ///
    /// # Parameters
    ///
    /// - `nonce_cache` — shared nonce cache (same instance across
    ///   all handler invocations).
    /// - `max_timestamp_skew_secs` — maximum clock skew tolerance.
    /// - `event_sender` — channel for emitting `NetworkEvent`s.
    pub fn new(
        nonce_cache: Arc<Mutex<NonceCache>>,
        max_timestamp_skew_secs: u64,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
    ) -> Self {
        Self {
            nonce_cache,
            max_timestamp_skew_secs,
            event_sender,
        }
    }

    /// Processes an inbound message through the full validation pipeline.
    ///
    /// # Validation steps
    ///
    /// 1. Verify `SHA3-256(sender_pubkey) == envelope.message.sender`.
    /// 2. Verify the Ed25519 signature over the canonical CBOR bytes.
    /// 3. Check that the timestamp is within `±max_timestamp_skew_secs`.
    /// 4. Check the nonce against the replay cache.
    /// 5. Emit `NetworkEvent::MessageReceived`.
    /// 6. Return `Ack::Ok`.
    ///
    /// If any step fails, the appropriate [`Ack`] variant is returned
    /// and the message is NOT stored or forwarded.
    pub async fn on_message_received(
        &self,
        _peer_id: PeerId,
        envelope: MessageEnvelope,
        sender_pubkey: &[u8; 32],
    ) -> HandlerResult {
        // Step 1: Verify pubkey → address binding.
        let pubkey = PublicKey::from_bytes(*sender_pubkey);
        let derived_address = pubkey_to_address(&pubkey);
        if derived_address.as_bytes() != envelope.message.sender.as_bytes() {
            tracing::warn!("sender pubkey does not match sender address");
            return HandlerResult {
                ack: Ack::InvalidSignature,
            };
        }

        // Step 2: Verify Ed25519 signature (BEFORE decrypt).
        //
        // The signature covers the canonical CBOR encoding of the
        // Message, as produced by bitevachat_protocol::canonical.
        let canonical_bytes = match to_canonical_cbor(&envelope.message) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(%e, "failed to produce canonical CBOR for verification");
                return HandlerResult {
                    ack: Ack::InvalidSignature,
                };
            }
        };

        let signature = Signature::from_bytes(*envelope.signature.as_bytes());
        if verify(&pubkey, &canonical_bytes, &signature).is_err() {
            tracing::warn!("invalid signature on inbound message");
            return HandlerResult {
                ack: Ack::InvalidSignature,
            };
        }

        // Step 3: Validate timestamp skew (asymmetric).
        //
        // Messages can arrive late due to relay circuits, pending
        // queue retries, and network delays.  We use asymmetric
        // skew limits:
        //   - PAST:   message older than now → generous (30 min)
        //   - FUTURE: message ahead of now   → strict   (5 min)
        //
        // This prevents replay of ancient messages while tolerating
        // legitimate delivery delays through relay nodes.
        let now = Timestamp::now();
        let now_millis = now.as_datetime().timestamp_millis();
        let msg_millis = envelope.message.timestamp.as_datetime().timestamp_millis();
        let diff = now_millis - msg_millis; // positive = message is in the past

        if diff > 0 {
            // Message is from the past (normal case for relayed msgs).
            let max_past_ms = (MAX_PAST_TIMESTAMP_SKEW_SECS as i64).saturating_mul(1000);
            if diff > max_past_ms {
                tracing::warn!(
                    diff_ms = diff,
                    max_past_ms,
                    "message too old (past timestamp beyond limit)"
                );
                return HandlerResult {
                    ack: Ack::InvalidTimestamp,
                };
            }
        } else {
            // Message is from the future (clock ahead).
            let future_diff = diff.abs();
            let max_future_ms = (self.max_timestamp_skew_secs as i64).saturating_mul(1000);
            if future_diff > max_future_ms {
                tracing::warn!(
                    diff_ms = future_diff,
                    max_future_ms,
                    "message from the future (timestamp ahead of local clock)"
                );
                return HandlerResult {
                    ack: Ack::InvalidTimestamp,
                };
            }
        }

        // Step 4: Nonce replay check.
        {
            let mut cache = match self.nonce_cache.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    tracing::error!("nonce cache lock poisoned");
                    return HandlerResult {
                        ack: Ack::InvalidNonce,
                    };
                }
            };

            if cache
                .check_and_insert(
                    &envelope.message.sender,
                    &envelope.message.nonce,
                )
                .is_err()
            {
                tracing::warn!("nonce replay detected");
                return HandlerResult {
                    ack: Ack::InvalidNonce,
                };
            }
        }

        // Step 5: Emit event (decryption is delegated to higher layer).
        //
        // The handler deliberately does NOT decrypt here; decryption
        // requires the recipient's private key which the network
        // layer should not hold. The node core layer handles
        // decryption and storage upon receiving this event.
        let _ = self
            .event_sender
            .send(NetworkEvent::MessageReceived(envelope));

        // Step 6: ACK success.
        HandlerResult { ack: Ack::Ok }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitevachat_crypto::signing::Keypair;
    use bitevachat_protocol::message::{Message, MessageEnvelope};
    use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType, Timestamp};

    fn make_test_envelope(sender_kp: &Keypair) -> (MessageEnvelope, [u8; 32]) {
        let sender_pk = sender_kp.public_key();
        let sender_addr = pubkey_to_address(&sender_pk);

        let msg = Message {
            sender: sender_addr,
            recipient: Address::new([0xBB; 32]),
            payload_type: PayloadType::Text,
            payload_ciphertext: b"encrypted-data".to_vec(),
            node_id: NodeId::new([0x01; 32]),
            nonce: Nonce::new([0xAA; 12]),
            timestamp: Timestamp::now(),
            message_id: MessageId::new([0xCC; 32]),
        };

        // Sign the canonical CBOR encoding, same as the handler verifies.
        let canonical = to_canonical_cbor(&msg).expect("canonical CBOR");
        let signature = sender_kp.sign(&canonical);

        let envelope = MessageEnvelope { message: msg, signature };
        (envelope, *sender_pk.as_bytes())
    }

    fn setup_handler() -> (MessageHandler, mpsc::UnboundedReceiver<NetworkEvent>) {
        let cache = Arc::new(Mutex::new(NonceCache::new(1000)));
        let (tx, rx) = mpsc::unbounded_channel();
        let handler = MessageHandler::new(cache, DEFAULT_MAX_TIMESTAMP_SKEW_SECS, tx);
        (handler, rx)
    }

    #[tokio::test]
    async fn valid_message_returns_ack_ok() {
        let (handler, mut rx) = setup_handler();
        let sender_kp = Keypair::from_seed(&[0x01; 32]);
        let (envelope, pubkey) = make_test_envelope(&sender_kp);

        let peer_id = libp2p::PeerId::random();
        let result = handler
            .on_message_received(peer_id, envelope, &pubkey)
            .await;

        assert_eq!(result.ack, Ack::Ok);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn wrong_pubkey_returns_invalid_signature() {
        let (handler, _rx) = setup_handler();
        let sender_kp = Keypair::from_seed(&[0x01; 32]);
        let (_envelope, _pubkey) = make_test_envelope(&sender_kp);

        let wrong_pubkey = [0xFF; 32];
        let peer_id = libp2p::PeerId::random();
        let result = handler
            .on_message_received(peer_id, _envelope, &wrong_pubkey)
            .await;

        assert_eq!(result.ack, Ack::InvalidSignature);
    }

    #[tokio::test]
    async fn replay_nonce_returns_invalid_nonce() {
        let (handler, _rx) = setup_handler();
        let sender_kp = Keypair::from_seed(&[0x01; 32]);
        let (envelope, pubkey) = make_test_envelope(&sender_kp);

        let peer_id = libp2p::PeerId::random();
        let r1 = handler
            .on_message_received(peer_id, envelope.clone(), &pubkey)
            .await;
        assert_eq!(r1.ack, Ack::Ok);

        // Replay same envelope.
        let r2 = handler
            .on_message_received(peer_id, envelope, &pubkey)
            .await;
        assert_eq!(r2.ack, Ack::InvalidNonce);
    }
}