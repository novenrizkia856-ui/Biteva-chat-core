//! Core message types for the Bitevachat protocol.
//!
//! A [`Message`] carries all required fields for end-to-end delivery.
//! A [`MessageEnvelope`] pairs a message with its Ed25519 signature.
//! A [`VerifiedMessage`] is the output of successful signature and
//! validation checks, serving as proof that the message is authentic.

use bitevachat_crypto::signing::{PublicKey, Signature};
use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType, Timestamp};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// Protocol-level message with all required fields.
///
/// Every field is mandatory — there are no optional fields. The
/// `message_id` is deterministically computed as
/// `SHA3-256(sender || timestamp || nonce)` and must be verified
/// by the recipient.
///
/// **Canonical serialization** is performed exclusively through
/// [`crate::canonical::to_canonical_cbor`], not via serde. The serde
/// derives are provided for non-canonical contexts (e.g. storage).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    /// Address of the message sender.
    pub sender: Address,
    /// Address of the intended recipient.
    pub recipient: Address,
    /// Classification of the payload content.
    pub payload_type: PayloadType,
    /// Encrypted payload bytes (XChaCha20-Poly1305 ciphertext + tag).
    pub payload_ciphertext: Vec<u8>,
    /// Node ID of the originating node.
    pub node_id: NodeId,
    /// 96-bit per-message nonce for replay detection.
    pub nonce: Nonce,
    /// UTC timestamp of message creation.
    pub timestamp: Timestamp,
    /// Deterministic message identifier: SHA3-256(sender || timestamp || nonce).
    pub message_id: MessageId,
}

// ---------------------------------------------------------------------------
// MessageEnvelope
// ---------------------------------------------------------------------------

/// A [`Message`] paired with an Ed25519 signature over its canonical
/// CBOR encoding.
///
/// The signature covers the deterministic CBOR bytes produced by
/// [`crate::canonical::to_canonical_cbor`], ensuring that any
/// modification to the message (including field reordering) is
/// detectable.
pub struct MessageEnvelope {
    /// The signed message.
    pub message: Message,
    /// Ed25519 signature over the canonical CBOR encoding of `message`.
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// VerifiedMessage
// ---------------------------------------------------------------------------

/// Output of successful envelope verification.
///
/// A `VerifiedMessage` is proof that:
/// 1. The Ed25519 signature is valid for the sender's public key.
/// 2. The `message_id` matches the recomputed hash.
/// 3. The `timestamp` is within the allowed skew window.
///
/// Consumers should accept only `VerifiedMessage` instances to
/// guarantee authenticity.
pub struct VerifiedMessage {
    /// The authenticated message.
    pub message: Message,
    /// The public key that produced the valid signature.
    pub sender_public_key: PublicKey,
}