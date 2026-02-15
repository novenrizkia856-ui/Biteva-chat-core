//! Core shared types for the Bitevachat decentralized chat system.
//!
//! This crate defines all fundamental types used across the workspace.
//! No other crate should define shared types — everything lives here.

pub mod config;

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// Cryptographic address derived from SHA3-256(public_key) + checksum.
///
/// This is the primary identity of a node and wallet in the Bitevachat network.
/// Represented as a 32-byte hash of the Ed25519 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Address([u8; 32]);

impl Address {
    /// The fixed byte length of an address.
    pub const LEN: usize = 32;

    /// Creates a new `Address` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Address {
    type Err = BitevachatError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| BitevachatError::InvalidAddress {
            reason: "invalid hex encoding".into(),
        })?;
        if bytes.len() != 32 {
            return Err(BitevachatError::InvalidAddress {
                reason: format!("expected 32 bytes, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// MessageId
// ---------------------------------------------------------------------------

/// Deterministic message identifier: SHA3-256(sender || timestamp || nonce).
///
/// Uniquely identifies every message in the network. Computed deterministically
/// from the sender address, timestamp, and per-message nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// The fixed byte length of a message ID.
    pub const LEN: usize = 32;

    /// Creates a new `MessageId` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for MessageId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for MessageId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for MessageId {
    type Err = BitevachatError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| BitevachatError::InvalidMessage {
            reason: "invalid hex encoding for message id".into(),
        })?;
        if bytes.len() != 32 {
            return Err(BitevachatError::InvalidMessage {
                reason: format!("expected 32 bytes for message id, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// NodeId
// ---------------------------------------------------------------------------

/// Unique identifier for a node in the P2P network.
///
/// Derived from the node's Ed25519 public key, identical in structure to
/// an `Address` but semantically represents a network node rather than a wallet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// The fixed byte length of a node ID.
    pub const LEN: usize = 32;

    /// Creates a new `NodeId` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for NodeId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for NodeId {
    type Err = BitevachatError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| BitevachatError::NetworkError {
            reason: "invalid hex encoding for node id".into(),
        })?;
        if bytes.len() != 32 {
            return Err(BitevachatError::NetworkError {
                reason: format!("expected 32 bytes for node id, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// UTC timestamp in ISO 8601 format.
///
/// All timestamps in Bitevachat use UTC to ensure deterministic ordering
/// across nodes regardless of timezone. Nodes verify timestamp skew
/// (default ±5 minutes) to mitigate replay attacks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    /// Creates a `Timestamp` representing the current UTC time.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Creates a `Timestamp` from a `DateTime<Utc>`.
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    /// Returns the inner `DateTime<Utc>`.
    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }

    /// Returns the timestamp as an ISO 8601 string.
    pub fn as_str(&self) -> String {
        self.0.to_rfc3339()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

impl FromStr for Timestamp {
    type Err = BitevachatError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let dt = DateTime::parse_from_rfc3339(s)
            .map_err(|e| BitevachatError::ConfigError {
                reason: format!("invalid ISO 8601 timestamp: {e}"),
            })?
            .with_timezone(&Utc);
        Ok(Self(dt))
    }
}

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

/// 96-bit (12-byte) random nonce for AEAD encryption.
///
/// Each nonce must be unique per sender to prevent replay attacks.
/// Generated from a cryptographically secure random source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// The fixed byte length of a nonce.
    pub const LEN: usize = 12;

    /// Creates a new `Nonce` from raw bytes.
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl From<[u8; 12]> for Nonce {
    fn from(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// PayloadType
// ---------------------------------------------------------------------------

/// Classifies the type of content carried in a message payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PayloadType {
    /// Plain text message.
    Text,
    /// File transfer payload.
    File,
    /// System / control message (e.g., key rotation, profile update).
    System,
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::File => write!(f, "file"),
            Self::System => write!(f, "system"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConvoId
// ---------------------------------------------------------------------------

/// Unique identifier for a conversation (direct or group).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ConvoId([u8; 32]);

impl ConvoId {
    /// Creates a new `ConvoId` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ConvoId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for ConvoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// GroupId
// ---------------------------------------------------------------------------

/// Unique identifier for a group chat.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct GroupId([u8; 32]);

impl GroupId {
    /// Creates a new `GroupId` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for GroupId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// ConvoSummary
// ---------------------------------------------------------------------------

/// Summary metadata for a conversation, used in listing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoSummary {
    /// Conversation identifier.
    pub convo_id: ConvoId,
    /// Address of the peer in this conversation (for direct chats).
    pub peer_address: Address,
    /// Display alias for the peer, if set.
    pub alias: Option<String>,
    /// Timestamp of the last message in this conversation.
    pub last_message_at: Option<Timestamp>,
    /// Total number of messages stored locally.
    pub message_count: u64,
}

// ---------------------------------------------------------------------------
// WalletStatus
// ---------------------------------------------------------------------------

/// Represents the current state of the local wallet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WalletStatus {
    /// Wallet file does not exist; needs creation or import.
    Uninitialized,
    /// Wallet file exists but private key is not decrypted in memory.
    Locked,
    /// Wallet is decrypted and ready for signing operations.
    Unlocked,
}

impl fmt::Display for WalletStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => write!(f, "uninitialized"),
            Self::Locked => write!(f, "locked"),
            Self::Unlocked => write!(f, "unlocked"),
        }
    }
}

// ---------------------------------------------------------------------------
// NodeEvent
// ---------------------------------------------------------------------------

/// Events emitted by the node core to the UI / RPC layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeEvent {
    /// A new message was received and verified.
    MessageReceived {
        /// Conversation the message belongs to.
        convo_id: ConvoId,
        /// The message identifier.
        message_id: MessageId,
        /// Sender address.
        sender: Address,
    },
    /// A previously sent message was acknowledged by the recipient.
    DeliveryAcknowledged {
        /// The acknowledged message identifier.
        message_id: MessageId,
    },
    /// A peer connected to the network.
    PeerConnected {
        /// Node ID of the connected peer.
        node_id: NodeId,
    },
    /// A peer disconnected from the network.
    PeerDisconnected {
        /// Node ID of the disconnected peer.
        node_id: NodeId,
    },
    /// A profile update was received from a peer.
    ProfileUpdated {
        /// Address of the peer whose profile changed.
        address: Address,
    },
}

// ---------------------------------------------------------------------------
// BitevachatError
// ---------------------------------------------------------------------------

/// Central error type for the Bitevachat system.
///
/// All crates in the workspace convert their internal errors into variants
/// of this enum, ensuring a unified error handling surface.
#[derive(Debug, Error)]
pub enum BitevachatError {
    /// The provided address is malformed or fails checksum validation.
    #[error("invalid address: {reason}")]
    InvalidAddress {
        /// Human-readable description of why the address is invalid.
        reason: String,
    },

    /// A message is malformed, missing required fields, or fails validation.
    #[error("invalid message: {reason}")]
    InvalidMessage {
        /// Human-readable description of the message validation failure.
        reason: String,
    },

    /// A cryptographic operation failed (signing, verification, encryption, decryption).
    #[error("crypto error: {reason}")]
    CryptoError {
        /// Human-readable description of the cryptographic failure.
        reason: String,
    },

    /// A storage or database operation failed.
    #[error("storage error: {reason}")]
    StorageError {
        /// Human-readable description of the storage failure.
        reason: String,
    },

    /// A networking or transport operation failed.
    #[error("network error: {reason}")]
    NetworkError {
        /// Human-readable description of the network failure.
        reason: String,
    },

    /// A protocol-level error (serialization, schema, canonical form).
    #[error("protocol error: {reason}")]
    ProtocolError {
        /// Human-readable description of the protocol failure.
        reason: String,
    },

    /// The sender has exceeded the allowed message rate.
    #[error("rate limit exceeded: {reason}")]
    RateLimitExceeded {
        /// Human-readable description including the limit and window.
        reason: String,
    },

    /// A nonce has already been seen, indicating a replay attempt.
    #[error("nonce replay detected: {reason}")]
    NonceReplay {
        /// Human-readable description of the replay detection.
        reason: String,
    },

    /// A configuration value is invalid or missing.
    #[error("config error: {reason}")]
    ConfigError {
        /// Human-readable description of the configuration problem.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Signable / Verifiable traits
// ---------------------------------------------------------------------------

/// Trait for types that can produce canonical bytes for Ed25519 signing.
///
/// Implementors define how their data is serialized into a byte sequence
/// that will be signed. The crypto crate performs the actual signing;
/// this trait lives in `bitevachat-types` so both the protocol and
/// crypto crates can reference it without circular dependencies.
pub trait Signable {
    /// Returns the canonical byte representation to be signed.
    fn signable_bytes(&self) -> Vec<u8>;
}

/// Trait for types that carry an embedded signature and can be verified.
///
/// Implementors provide access to the signed bytes, the signature, and
/// the signer's address. The crypto crate performs the actual
/// verification.
pub trait Verifiable {
    /// Returns the canonical bytes that were signed.
    fn signed_bytes(&self) -> Vec<u8>;
    /// Returns the raw 64-byte Ed25519 signature.
    fn signature_bytes(&self) -> &[u8];
    /// Returns the address (public key hash) of the signer.
    fn signer_address(&self) -> &Address;
}

// ---------------------------------------------------------------------------
// Result alias
// ---------------------------------------------------------------------------

/// Convenience result type using [`BitevachatError`].
pub type Result<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip_hex() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = [0xABu8; 32];
        let addr = Address::new(bytes);
        let hex_str = addr.to_string();
        let parsed: Address = hex_str.parse()?;
        assert_eq!(addr, parsed);
        Ok(())
    }

    #[test]
    fn address_invalid_hex_length() {
        let result: std::result::Result<Address, _> = "abcd".parse();
        assert!(result.is_err());
    }

    #[test]
    fn address_invalid_hex_chars() {
        let result: std::result::Result<Address, _> = "zzzz".parse();
        assert!(result.is_err());
    }

    #[test]
    fn message_id_roundtrip_hex() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = [0x42u8; 32];
        let mid = MessageId::new(bytes);
        let hex_str = mid.to_string();
        let parsed: MessageId = hex_str.parse()?;
        assert_eq!(mid, parsed);
        Ok(())
    }

    #[test]
    fn node_id_roundtrip_hex() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = [0x01u8; 32];
        let nid = NodeId::new(bytes);
        let hex_str = nid.to_string();
        let parsed: NodeId = hex_str.parse()?;
        assert_eq!(nid, parsed);
        Ok(())
    }

    #[test]
    fn timestamp_now_parses_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ts = Timestamp::now();
        let s = ts.as_str();
        let parsed: Timestamp = s.parse()?;
        assert_eq!(ts.as_datetime(), parsed.as_datetime());
        Ok(())
    }

    #[test]
    fn timestamp_display_iso8601() {
        let ts = Timestamp::now();
        let displayed = ts.to_string();
        assert!(displayed.contains('T'), "ISO 8601 must contain 'T' separator");
    }

    #[test]
    fn payload_type_display() {
        assert_eq!(PayloadType::Text.to_string(), "text");
        assert_eq!(PayloadType::File.to_string(), "file");
        assert_eq!(PayloadType::System.to_string(), "system");
    }

    #[test]
    fn wallet_status_display() {
        assert_eq!(WalletStatus::Locked.to_string(), "locked");
        assert_eq!(WalletStatus::Unlocked.to_string(), "unlocked");
        assert_eq!(WalletStatus::Uninitialized.to_string(), "uninitialized");
    }

    #[test]
    fn nonce_from_bytes() {
        let bytes = [0xFFu8; 12];
        let nonce = Nonce::new(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn address_serde_json_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let addr = Address::new([0x11u8; 32]);
        let json = serde_json::to_string(&addr)?;
        let parsed: Address = serde_json::from_str(&json)?;
        assert_eq!(addr, parsed);
        Ok(())
    }

    #[test]
    fn error_display() {
        let err = BitevachatError::InvalidAddress {
            reason: "too short".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("too short"));
    }
}
