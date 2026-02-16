//! Message protocol types for libp2p `request_response`.
//!
//! Defines [`WireMessage`] (request) and [`Ack`] (response) which
//! are serialized/deserialized automatically by the built-in CBOR
//! codec from `libp2p-request-response` (feature `cbor`).
//!
//! # Protocol ID
//!
//! `/bitevachat/msg/1.0.0`

use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

use bitevachat_protocol::message::MessageEnvelope;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Protocol identifier for Bitevachat direct messaging.
pub const MSG_PROTOCOL: StreamProtocol = StreamProtocol::new("/bitevachat/msg/1.0.0");

// ---------------------------------------------------------------------------
// WireMessage
// ---------------------------------------------------------------------------

/// Wire-level message sent from sender to recipient.
///
/// Wraps a [`MessageEnvelope`] together with the sender's Ed25519
/// public key so the recipient can verify the signature without
/// needing a separate key lookup.
///
/// The recipient MUST verify that `SHA3-256(sender_pubkey)` equals
/// `envelope.message.sender` before trusting the public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireMessage {
    /// The signed message envelope.
    pub envelope: MessageEnvelope,
    /// Sender's Ed25519 public key (32 bytes).
    pub sender_pubkey: [u8; 32],
}

// ---------------------------------------------------------------------------
// Ack
// ---------------------------------------------------------------------------

/// Acknowledgement returned by the recipient after processing.
///
/// Each variant maps to a specific validation stage failure.
/// `Ok` means the message was accepted and stored.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ack {
    /// Message accepted.
    Ok,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Nonce was already seen (replay attempt).
    InvalidNonce,
    /// Timestamp is outside the allowed skew window.
    InvalidTimestamp,
    /// AEAD decryption failed (wrong key, tampered ciphertext).
    DecryptionFailed,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_cbor_roundtrip() {
        let variants = [
            Ack::Ok,
            Ack::InvalidSignature,
            Ack::InvalidNonce,
            Ack::InvalidTimestamp,
            Ack::DecryptionFailed,
        ];
        for ack in &variants {
            let mut bytes = Vec::new();
            ciborium::into_writer(ack, &mut bytes).unwrap();
            let decoded: Ack = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(&decoded, ack);
        }
    }

    #[test]
    fn ack_deterministic_serialization() {
        let mut bytes1 = Vec::new();
        ciborium::into_writer(&Ack::Ok, &mut bytes1).unwrap();
        let mut bytes2 = Vec::new();
        ciborium::into_writer(&Ack::Ok, &mut bytes2).unwrap();
        assert_eq!(bytes1, bytes2);
    }
}