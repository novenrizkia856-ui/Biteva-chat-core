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
//! 3. Validate timestamp skew (asymmetric: strict for future, lenient for past).
//! 4. Validate nonce (replay detection).
//! 5. Emit [`NetworkEvent::MessageReceived`].
//! 6. Return [`Ack::Ok`].
//!
//! # Relay forwarding
//!
//! Public/VPS nodes that forward messages on behalf of NAT-ed clients
//! use [`MessageHandler::validate_signature_only`] which only checks
//! steps 1–2 (pubkey binding + signature). Timestamp and nonce
//! validation are delegated to the final recipient, because relay
//! latency and pending-queue retries can cause legitimate skew.

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

/// Default maximum allowed clock skew for FUTURE timestamps (10 minutes).
///
/// A message claiming to be from the future is suspicious — strict limit.
pub const DEFAULT_MAX_FUTURE_SKEW_SECS: u64 = 600;

/// Default maximum allowed clock skew for PAST timestamps (30 minutes).
///
/// Messages can legitimately arrive late due to:
/// - Relay circuit establishment latency
/// - Pending queue retries
/// - NTP drift between NAT-ed clients
/// - Store-and-forward delays on VPS nodes
///
/// The lenient past tolerance accommodates these real-world delays.
pub const DEFAULT_MAX_PAST_SKEW_SECS: u64 = 1800;

/// Legacy constant kept for backward compatibility.
/// New code should use the asymmetric constants above.
pub const DEFAULT_MAX_TIMESTAMP_SKEW_SECS: u64 = DEFAULT_MAX_FUTURE_SKEW_SECS;

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

    /// Maximum allowed clock skew for FUTURE timestamps (seconds).
    max_future_skew_secs: u64,

    /// Maximum allowed clock skew for PAST timestamps (seconds).
    /// Lenient to accommodate relay delays, pending retries, NTP drift.
    max_past_skew_secs: u64,

    /// Channel for emitting validated network events.
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
}

impl MessageHandler {
    /// Creates a new handler with default asymmetric timestamp tolerance.
    ///
    /// - Future skew: 10 minutes (strict — prevents clock-ahead attacks)
    /// - Past skew: 30 minutes (lenient — accommodates relay + retry delays)
    ///
    /// # Parameters
    ///
    /// - `nonce_cache` — shared nonce cache (same instance across
    ///   all handler invocations).
    /// - `event_sender` — channel for emitting `NetworkEvent`s.
    pub fn new(
        nonce_cache: Arc<Mutex<NonceCache>>,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
    ) -> Self {
        Self {
            nonce_cache,
            max_future_skew_secs: DEFAULT_MAX_FUTURE_SKEW_SECS,
            max_past_skew_secs: DEFAULT_MAX_PAST_SKEW_SECS,
            event_sender,
        }
    }

    /// Creates a new handler with custom asymmetric timestamp tolerances.
    ///
    /// # Parameters
    ///
    /// - `nonce_cache` — shared nonce cache.
    /// - `max_future_skew_secs` — maximum allowed future timestamp skew.
    /// - `max_past_skew_secs` — maximum allowed past timestamp skew.
    /// - `event_sender` — channel for emitting `NetworkEvent`s.
    pub fn with_asymmetric_skew(
        nonce_cache: Arc<Mutex<NonceCache>>,
        max_future_skew_secs: u64,
        max_past_skew_secs: u64,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
    ) -> Self {
        Self {
            nonce_cache,
            max_future_skew_secs,
            max_past_skew_secs,
            event_sender,
        }
    }

    /// Processes an inbound message through the full validation pipeline.
    ///
    /// # Validation steps
    ///
    /// 1. Verify `SHA3-256(sender_pubkey) == envelope.message.sender`.
    /// 2. Verify the Ed25519 signature over the canonical CBOR bytes.
    /// 3. Validate timestamp skew (asymmetric: strict future, lenient past).
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

        // Step 3: Asymmetric timestamp validation.
        //
        // diff_millis = now - msg_timestamp
        //   positive → message is in the PAST  → check against max_past_skew
        //   negative → message is in the FUTURE → check against max_future_skew
        //
        // This allows lenient tolerance for delayed delivery (relay circuits,
        // pending retries) while still being strict about future timestamps.
        let now = Timestamp::now();
        let now_millis = now.as_datetime().timestamp_millis();
        let msg_millis = envelope.message.timestamp.as_datetime().timestamp_millis();
        let diff_millis = now_millis - msg_millis;

        let allowed = if diff_millis >= 0 {
            // Message is in the past — lenient tolerance.
            (self.max_past_skew_secs as i64).saturating_mul(1000)
        } else {
            // Message is in the future — strict tolerance.
            (self.max_future_skew_secs as i64).saturating_mul(1000)
        };

        if diff_millis.abs() > allowed {
            tracing::warn!(
                diff_ms = diff_millis,
                allowed_ms = allowed,
                direction = if diff_millis >= 0 { "past" } else { "future" },
                "timestamp outside allowed skew window"
            );
            return HandlerResult {
                ack: Ack::InvalidTimestamp,
            };
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
        let _ = self
            .event_sender
            .send(NetworkEvent::MessageReceived(envelope));

        // Step 6: ACK success.
        HandlerResult { ack: Ack::Ok }
    }

    /// Validates only the sender's identity and signature.
    ///
    /// Used by VPS/relay nodes when forwarding messages to the actual
    /// recipient. Skips timestamp and nonce checks — those are the
    /// final recipient's responsibility.
    ///
    /// This prevents spam and invalid messages from being forwarded,
    /// while avoiding false rejections caused by relay latency.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — signature is valid, safe to forward.
    /// - `Err(Ack)` — invalid identity or signature.
    pub fn validate_signature_only(
        &self,
        envelope: &MessageEnvelope,
        sender_pubkey: &[u8; 32],
    ) -> Result<(), Ack> {
        // Step 1: Verify pubkey → address binding.
        let pubkey = PublicKey::from_bytes(*sender_pubkey);
        let derived_address = pubkey_to_address(&pubkey);
        if derived_address.as_bytes() != envelope.message.sender.as_bytes() {
            tracing::warn!("relay: sender pubkey does not match sender address");
            return Err(Ack::InvalidSignature);
        }

        // Step 2: Verify Ed25519 signature.
        let canonical_bytes = match to_canonical_cbor(&envelope.message) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(%e, "relay: failed to produce canonical CBOR");
                return Err(Ack::InvalidSignature);
            }
        };

        let signature = Signature::from_bytes(*envelope.signature.as_bytes());
        if verify(&pubkey, &canonical_bytes, &signature).is_err() {
            tracing::warn!("relay: invalid signature, refusing to forward");
            return Err(Ack::InvalidSignature);
        }

        Ok(())
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
        let handler = MessageHandler::new(cache, tx);
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

    #[tokio::test]
    async fn validate_signature_only_accepts_valid() {
        let (handler, _rx) = setup_handler();
        let sender_kp = Keypair::from_seed(&[0x01; 32]);
        let (envelope, pubkey) = make_test_envelope(&sender_kp);

        assert!(handler.validate_signature_only(&envelope, &pubkey).is_ok());
    }

    #[tokio::test]
    async fn validate_signature_only_rejects_wrong_pubkey() {
        let (handler, _rx) = setup_handler();
        let sender_kp = Keypair::from_seed(&[0x01; 32]);
        let (envelope, _pubkey) = make_test_envelope(&sender_kp);

        let wrong_pubkey = [0xFF; 32];
        assert_eq!(
            handler.validate_signature_only(&envelope, &wrong_pubkey),
            Err(Ack::InvalidSignature)
        );
    }
}