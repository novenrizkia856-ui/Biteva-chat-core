//! Commands and status types for external → node communication.
//!
//! [`NodeCommand`] is the bounded-channel message type that RPC
//! handlers, CLI, and tests use to drive the node. Each command
//! that produces a result carries a `tokio::sync::oneshot::Sender`
//! for the reply.
//!
//! All commands are processed sequentially inside the event loop,
//! eliminating race conditions between concurrent RPC calls.

use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_types::{
    Address, ConvoId, MessageId, NodeId, PayloadType, Timestamp,
};
use tokio::sync::oneshot;

use crate::node::NodeState;

/// Convenience alias to avoid shadowing `std::result::Result`.
type BResult<T> = std::result::Result<T, bitevachat_types::BitevachatError>;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Lightweight message metadata returned by query commands.
///
/// Does **not** contain decrypted payload — only ciphertext and
/// metadata. Decryption is the consumer's responsibility.
#[derive(Clone, Debug)]
pub struct MessageInfo {
    /// Deterministic message identifier.
    pub message_id: MessageId,
    /// Sender address.
    pub sender: Address,
    /// Recipient address.
    pub recipient: Address,
    /// Message creation timestamp (ISO 8601).
    pub timestamp: Timestamp,
    /// Payload classification.
    pub payload_type: PayloadType,
    /// E2E encrypted payload (still ciphertext).
    pub payload_ciphertext: Vec<u8>,
}

/// Contact entry returned by contact query commands.
#[derive(Clone, Debug)]
pub struct ContactInfo {
    /// Contact address.
    pub address: Address,
    /// Human-readable alias (empty string if unset).
    pub alias: String,
    /// Whether this contact is blocked.
    pub blocked: bool,
}

/// Connected peer information returned by peer query commands.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// libp2p PeerId as a string.
    pub peer_id: String,
    /// Bitevachat NodeId (SHA3-256 of PeerId bytes).
    pub node_id: NodeId,
}

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

// ---------------------------------------------------------------------------
// NodeCommand
// ---------------------------------------------------------------------------

/// Commands accepted by the node event loop.
///
/// Sent through a bounded `mpsc::Sender<NodeCommand>` channel.
/// The event loop processes one command per iteration, ensuring
/// serial access to all mutable state.
pub enum NodeCommand {
    // ----- Messaging ------------------------------------------------------

    /// Send an encrypted message to a recipient.
    SendMessage {
        /// Intended recipient address.
        recipient: Address,
        /// Plaintext payload bytes.
        plaintext: Vec<u8>,
        /// Classification of the payload.
        payload_type: PayloadType,
        /// Pre-derived shared session key for E2E encryption.
        shared_key: [u8; 32],
        /// Reply channel.
        reply: oneshot::Sender<BResult<MessageId>>,
    },

    /// List messages in a conversation.
    ListMessages {
        /// Conversation identifier.
        convo_id: ConvoId,
        /// Maximum number of messages to return.
        limit: u64,
        /// Offset for pagination (0-based).
        offset: u64,
        /// Reply channel.
        reply: oneshot::Sender<BResult<Vec<MessageInfo>>>,
    },

    /// Retrieve a single message by ID.
    GetMessage {
        /// Message identifier.
        message_id: MessageId,
        /// Reply channel.
        reply: oneshot::Sender<BResult<Option<MessageInfo>>>,
    },

    // ----- Contacts -------------------------------------------------------

    /// Add or update a contact alias.
    AddContact {
        /// Contact address.
        address: Address,
        /// Human-readable alias.
        alias: String,
        /// Reply channel.
        reply: oneshot::Sender<BResult<()>>,
    },

    /// Block a contact address.
    BlockContact {
        /// Address to block.
        address: Address,
        /// Reply channel.
        reply: oneshot::Sender<BResult<()>>,
    },

    /// Unblock a previously blocked contact address.
    UnblockContact {
        /// Address to unblock.
        address: Address,
        /// Reply channel.
        reply: oneshot::Sender<BResult<()>>,
    },

    /// List all contacts.
    ListContacts {
        /// Reply channel.
        reply: oneshot::Sender<BResult<Vec<ContactInfo>>>,
    },

    // ----- Node operations ------------------------------------------------

    /// Query the current node status.
    GetStatus {
        /// Reply channel for the status snapshot.
        reply: oneshot::Sender<NodeStatus>,
    },

    /// List currently connected peers.
    ListPeers {
        /// Reply channel.
        reply: oneshot::Sender<BResult<Vec<PeerInfo>>>,
    },

    /// Inject an externally signed message into the node.
    ///
    /// The RPC layer MUST have verified the signature, timestamp,
    /// and sender pubkey → address binding BEFORE sending this
    /// command. The event loop trusts the envelope is valid and
    /// proceeds directly to storage and event emission.
    InjectMessage {
        /// Verified message envelope.
        envelope: MessageEnvelope,
        /// Reply channel.
        reply: oneshot::Sender<BResult<MessageId>>,
    },

    /// Initiate graceful shutdown.
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
            Self::ListMessages { convo_id, limit, offset, .. } => {
                f.debug_struct("ListMessages")
                    .field("convo_id", convo_id)
                    .field("limit", limit)
                    .field("offset", offset)
                    .finish_non_exhaustive()
            }
            Self::GetMessage { message_id, .. } => {
                f.debug_struct("GetMessage")
                    .field("message_id", message_id)
                    .finish_non_exhaustive()
            }
            Self::AddContact { address, alias, .. } => {
                f.debug_struct("AddContact")
                    .field("address", address)
                    .field("alias", alias)
                    .finish_non_exhaustive()
            }
            Self::BlockContact { address, .. } => {
                f.debug_struct("BlockContact")
                    .field("address", address)
                    .finish_non_exhaustive()
            }
            Self::UnblockContact { address, .. } => {
                f.debug_struct("UnblockContact")
                    .field("address", address)
                    .finish_non_exhaustive()
            }
            Self::ListContacts { .. } => f.write_str("ListContacts"),
            Self::GetStatus { .. } => f.write_str("GetStatus"),
            Self::ListPeers { .. } => f.write_str("ListPeers"),
            Self::InjectMessage { .. } => f.write_str("InjectMessage"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}