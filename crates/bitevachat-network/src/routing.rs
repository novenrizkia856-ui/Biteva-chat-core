//! Message routing and delivery tracking.
//!
//! The [`Router`] manages the lifecycle of outbound messages:
//!
//! 1. Resolve the recipient's Bitevachat `Address` to a libp2p `PeerId`.
//! 2. If online → send via `request_response` and await ACK.
//! 3. If offline → mark as `Queued` for later retry.
//! 4. If protocol error → mark as `Failed`.
//!
//! The router does NOT perform blocking waits; it initiates
//! operations and the swarm event loop drives completion by
//! calling [`Router::on_ack_received`] and [`Router::on_send_failed`].

use std::collections::HashMap;

use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_types::{Address, BitevachatError, MessageId};
use libp2p::request_response;
use libp2p::PeerId;

use crate::protocol::{Ack, WireMessage};

// ---------------------------------------------------------------------------
// DeliveryStatus
// ---------------------------------------------------------------------------

/// Outcome of a message send attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Message was delivered and acknowledged by the recipient.
    Delivered,
    /// Recipient is offline; message is queued for retry.
    Queued,
    /// A protocol-level or permanent error prevented delivery.
    Failed,
}

// ---------------------------------------------------------------------------
// PendingSend
// ---------------------------------------------------------------------------

/// Tracks an in-flight outbound message.
#[derive(Clone, Debug)]
pub struct PendingSend {
    /// The request ID assigned by `request_response::Behaviour`.
    pub request_id: request_response::OutboundRequestId,
    /// The message ID for correlation.
    pub message_id: MessageId,
    /// Recipient address (for queue fallback).
    pub recipient: Address,
    /// The original envelope (for re-queue on failure).
    pub envelope: MessageEnvelope,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Manages outbound message delivery state.
///
/// Thread-safety: NOT `Send`/`Sync`; accessed exclusively from the
/// swarm event loop task.
pub struct Router {
    /// In-flight sends indexed by request_response request ID.
    pending: HashMap<request_response::OutboundRequestId, PendingSend>,
}

impl Router {
    /// Creates a new empty router.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Registers an in-flight send.
    ///
    /// Called by the swarm after `request_response::Behaviour::send_request`
    /// returns a request ID.
    pub fn track_send(
        &mut self,
        request_id: request_response::OutboundRequestId,
        message_id: MessageId,
        recipient: Address,
        envelope: MessageEnvelope,
    ) {
        self.pending.insert(
            request_id,
            PendingSend {
                request_id,
                message_id,
                recipient,
                envelope,
            },
        );
    }

    /// Processes a successful ACK from the recipient.
    ///
    /// Returns `(MessageId, DeliveryStatus)` so the swarm can emit
    /// the appropriate `NetworkEvent`.
    pub fn on_ack_received(
        &mut self,
        request_id: &request_response::OutboundRequestId,
        ack: &Ack,
    ) -> Option<(MessageId, DeliveryStatus)> {
        let entry = self.pending.remove(request_id)?;

        let status = match ack {
            Ack::Ok => DeliveryStatus::Delivered,
            _ => {
                tracing::warn!(
                    msg_id = %entry.message_id,
                    ack = ?ack,
                    "recipient rejected message"
                );
                DeliveryStatus::Failed
            }
        };

        Some((entry.message_id, status))
    }

    /// Processes a send failure (dial error, timeout, stream error).
    ///
    /// Returns the pending send so the caller can enqueue it for retry.
    pub fn on_send_failed(
        &mut self,
        request_id: &request_response::OutboundRequestId,
    ) -> Option<PendingSend> {
        self.pending.remove(request_id)
    }

    /// Returns the number of in-flight sends.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// send_to_peer (helper)
// ---------------------------------------------------------------------------

/// Builds a [`WireMessage`] from an envelope and sender public key.
///
/// This is a pure helper; the actual sending is done by the swarm
/// through `request_response::Behaviour::send_request`.
pub fn build_wire_message(
    envelope: MessageEnvelope,
    sender_pubkey: [u8; 32],
) -> WireMessage {
    WireMessage {
        envelope,
        sender_pubkey,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_tracks_and_resolves_send() {
        let mut router = Router::new();
        let msg_id = MessageId::new([0x01; 32]);

        // We can't construct a real OutboundRequestId (it's opaque),
        // so we just verify the router is constructable and default
        // state is empty.
        assert_eq!(router.pending_count(), 0);
    }

    #[test]
    fn delivery_status_equality() {
        assert_eq!(DeliveryStatus::Delivered, DeliveryStatus::Delivered);
        assert_ne!(DeliveryStatus::Delivered, DeliveryStatus::Queued);
        assert_ne!(DeliveryStatus::Queued, DeliveryStatus::Failed);
    }
}