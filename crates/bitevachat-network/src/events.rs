//! Network events emitted by the Bitevachat swarm.
//!
//! [`NetworkEvent`] is the unified event type that consumers receive
//! from the swarm event loop. All libp2p-specific events are mapped
//! into this enum before being delivered to higher layers.

use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_types::MessageId;
use libp2p::PeerId;

// ---------------------------------------------------------------------------
// NetworkEvent
// ---------------------------------------------------------------------------

/// Events emitted by the Bitevachat network layer.
///
/// Higher layers (node core, RPC, CLI) subscribe to these events
/// to react to network activity without coupling to libp2p internals.
#[derive(Clone, Debug)]
pub enum NetworkEvent {
    /// A verified message was received from a remote peer.
    ///
    /// At this point the Ed25519 signature has been verified, the
    /// timestamp is within the allowed skew window, and the nonce
    /// is not a replay.
    MessageReceived(MessageEnvelope),

    /// A remote peer connected to this node.
    PeerConnected(PeerId),

    /// A remote peer disconnected from this node.
    PeerDisconnected(PeerId),

    /// An ACK was received for a message we sent.
    DeliveryAck(MessageId),

    /// Delivery of a message we sent failed after ACK timeout.
    DeliveryFailed(MessageId),

    /// A gossip message was received on a topic.
    GossipMessage {
        /// PeerId of the peer that propagated this message.
        source: PeerId,
        /// Topic string the message was published on.
        topic: String,
        /// Raw payload bytes.
        data: Vec<u8>,
    },
}