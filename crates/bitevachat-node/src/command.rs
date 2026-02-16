//! Commands and status types for external → node communication.
//!
//! [`NodeCommand`] is the bounded-channel message type that RPC
//! handlers, CLI, and tests use to drive the node. Each command
//! that produces a result carries a `tokio::sync::oneshot::Sender`
//! for the reply.
//!
//! All commands are processed sequentially inside the event loop,
//! eliminating race conditions between concurrent RPC calls.

use bitevachat_types::{Address, MessageId, NodeId, PayloadType};
use tokio::sync::oneshot;

use crate::node::NodeState;

/// Convenience alias to avoid shadowing `std::result::Result`.
type BResult<T> = std::result::Result<T, bitevachat_types::BitevachatError>;

// ---------------------------------------------------------------------------
// NodeCommand
// ---------------------------------------------------------------------------

/// Commands accepted by the node event loop.
///
/// Sent through a bounded `mpsc::Sender<NodeCommand>` channel.
/// The event loop processes one command per iteration, ensuring
/// serial access to all mutable state.
pub enum NodeCommand {
    /// Send an encrypted message to a recipient.
    ///
    /// The node will encrypt, sign, route, and (on failure) enqueue
    /// the message for pending retry.
    SendMessage {
        /// Intended recipient address.
        recipient: Address,
        /// Plaintext payload bytes.
        plaintext: Vec<u8>,
        /// Classification of the payload.
        payload_type: PayloadType,
        /// Pre-derived shared session key for E2E encryption.
        /// Derived externally via ECDH (see `bitevachat-protocol::e2e`).
        shared_key: [u8; 32],
        /// Reply channel. Returns the deterministic `MessageId` on
        /// success, or a `BitevachatError` on failure.
        reply: oneshot::Sender<BResult<MessageId>>,
    },

    /// Query the current node status.
    GetStatus {
        /// Reply channel for the status snapshot.
        reply: oneshot::Sender<NodeStatus>,
    },

    /// Initiate graceful shutdown.
    ///
    /// The event loop will finish in-flight work, flush storage,
    /// and exit. No reply channel — shutdown is fire-and-forget
    /// from the caller's perspective; await the `JoinHandle`
    /// returned by [`Node::start`] to confirm completion.
    Shutdown,
}

// Manual Debug because oneshot::Sender does not implement Debug.
impl std::fmt::Debug for NodeCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendMessage { recipient, payload_type, .. } => {
                f.debug_struct("SendMessage")
                    .field("recipient", recipient)
                    .field("payload_type", payload_type)
                    .finish_non_exhaustive()
            }
            Self::GetStatus { .. } => f.write_str("GetStatus"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

// ---------------------------------------------------------------------------
// NodeStatus
// ---------------------------------------------------------------------------

/// Snapshot of the node's current state.
///
/// Returned by [`NodeCommand::GetStatus`]. All fields are cloned
/// from the runtime so the reply is self-contained.
#[derive(Clone, Debug)]
pub struct NodeStatus {
    /// Current state machine state.
    pub state: NodeState,
    /// Wallet address of this node.
    pub address: Address,
    /// libp2p `PeerId` as a string.
    pub peer_id: String,
    /// Node identifier (public key bytes).
    pub node_id: NodeId,
    /// Addresses this node is currently listening on.
    pub listeners: Vec<String>,
    /// Number of messages in the pending delivery queue.
    pub pending_count: usize,
}