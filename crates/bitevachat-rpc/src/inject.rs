//! External message injection with mandatory re-verification.
//!
//! When a message arrives via a non-network path (e.g. bridge, relay,
//! or admin injection), it MUST be re-verified before entering the
//! node. This module performs the full security pipeline:
//!
//! 1. Validate sender pubkey length (32 bytes).
//! 2. Validate signature length (64 bytes).
//! 3. Verify pubkey → address binding (SHA3-256).
//! 4. Verify Ed25519 signature over the canonical CBOR bytes.
//! 5. Deserialize canonical CBOR → `Message`.
//! 6. Validate timestamp skew (±5 minutes).
//! 7. Reconstruct `MessageEnvelope`.
//!
//! Only after ALL checks pass does the envelope enter the node via
//! `NodeCommand::InjectMessage`. The node event loop trusts the
//! envelope at that point.
//!
//! # Nonce replay detection
//!
//! The nonce cache lives inside the network handler and is not
//! directly accessible here. Replay detection for injected messages
//! relies on message-ID deduplication at the storage layer.
//!
//! TODO: Share `NonceCache` between the network handler and the node
//! event loop to enable full nonce replay detection for inject.

use bitevachat_crypto::signing::{pubkey_to_address, verify, PublicKey, Signature};
use bitevachat_protocol::canonical::from_canonical_cbor;
use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_types::{BitevachatError, Timestamp};

/// Maximum allowed clock skew in seconds (matching network handler).
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

/// Verifies and reconstructs a `MessageEnvelope` from raw components.
///
/// # Parameters
///
/// - `canonical_message` — canonical CBOR bytes of the `Message`.
/// - `signature_bytes` — 64-byte Ed25519 signature.
/// - `sender_pubkey_bytes` — 32-byte Ed25519 public key.
///
/// # Returns
///
/// A verified `MessageEnvelope` on success.
///
/// # Errors
///
/// - `BitevachatError::CryptoError` — invalid pubkey/signature length,
///   pubkey ↔ address mismatch, or signature verification failure.
/// - `BitevachatError::ProtocolError` — CBOR deserialization failure
///   or invalid message structure.
/// - `BitevachatError::InvalidMessage` — timestamp outside allowed
///   skew window.
pub fn verify_and_reconstruct(
    canonical_message: &[u8],
    signature_bytes: &[u8],
    sender_pubkey_bytes: &[u8],
) -> BResult<MessageEnvelope> {
    // 1. Validate pubkey length.
    if sender_pubkey_bytes.len() != 32 {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "sender pubkey must be 32 bytes, got {}",
                sender_pubkey_bytes.len(),
            ),
        });
    }
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(sender_pubkey_bytes);
    let pubkey = PublicKey::from_bytes(pk_array);

    // 2. Validate signature length.
    if signature_bytes.len() != 64 {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "signature must be 64 bytes, got {}",
                signature_bytes.len(),
            ),
        });
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(sig_array);

    // 3. Verify pubkey → address binding.
    //
    // Derive address from pubkey and compare to the sender field
    // in the deserialized message (step 5). We deserialize first
    // to get the sender address, then compare.

    // 4–5. Verify signature, then deserialize.
    //
    // Verify BEFORE deserializing untrusted CBOR to minimize the
    // attack surface. A forged canonical payload with a valid
    // signature structure but wrong content will be caught here.
    verify(&pubkey, canonical_message, &signature).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("Ed25519 signature verification failed: {e}"),
        }
    })?;

    // Now safe to deserialize (signature is valid for this data).
    let message = from_canonical_cbor(canonical_message)?;

    // 3 (continued). Verify pubkey → sender address.
    let derived_address = pubkey_to_address(&pubkey);
    if derived_address.as_bytes() != message.sender.as_bytes() {
        return Err(BitevachatError::CryptoError {
            reason: "sender pubkey does not derive to the message sender address".into(),
        });
    }

    // 6. Validate timestamp skew.
    let now = Timestamp::now();
    let now_millis = now.as_datetime().timestamp_millis();
    let msg_millis = message.timestamp.as_datetime().timestamp_millis();
    let diff = (now_millis - msg_millis).abs();
    let max_millis = MAX_TIMESTAMP_SKEW_SECS.saturating_mul(1000);

    if diff > max_millis {
        return Err(BitevachatError::InvalidMessage {
            reason: format!(
                "timestamp skew {}ms exceeds allowed {}ms",
                diff, max_millis,
            ),
        });
    }

    // 7. Reconstruct envelope.
    Ok(MessageEnvelope { message, signature })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitevachat_crypto::signing::Keypair;
    use bitevachat_protocol::canonical::to_canonical_cbor;
    use bitevachat_protocol::message::Message;
    use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType, Timestamp};

    fn make_signed_message(kp: &Keypair) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let sender_pk = kp.public_key();
        let sender_addr = pubkey_to_address(&sender_pk);

        let msg = Message {
            sender: sender_addr,
            recipient: Address::new([0xBB; 32]),
            payload_type: PayloadType::Text,
            payload_ciphertext: b"test-data".to_vec(),
            node_id: NodeId::new([0x01; 32]),
            nonce: Nonce::new([0xAA; 12]),
            timestamp: Timestamp::now(),
            message_id: MessageId::new([0xCC; 32]),
        };

        let canonical = to_canonical_cbor(&msg).expect("canonical CBOR");
        let sig = kp.sign(&canonical);

        (canonical, sig.as_bytes().to_vec(), sender_pk.as_bytes().to_vec())
    }

    #[test]
    fn valid_injection_succeeds() {
        let kp = Keypair::from_seed(&[0x42; 32]);
        let (canonical, sig, pk) = make_signed_message(&kp);
        let result = verify_and_reconstruct(&canonical, &sig, &pk);
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let kp = Keypair::from_seed(&[0x42; 32]);
        let (canonical, sig, _pk) = make_signed_message(&kp);
        let wrong_pk = vec![0xFF; 32];
        let result = verify_and_reconstruct(&canonical, &sig, &wrong_pk);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_signature_rejected() {
        let kp = Keypair::from_seed(&[0x42; 32]);
        let (canonical, _sig, pk) = make_signed_message(&kp);
        let wrong_sig = vec![0x00; 64];
        let result = verify_and_reconstruct(&canonical, &wrong_sig, &pk);
        assert!(result.is_err());
    }

    #[test]
    fn short_pubkey_rejected() {
        let result = verify_and_reconstruct(b"data", &[0; 64], &[0; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn short_signature_rejected() {
        let result = verify_and_reconstruct(b"data", &[0; 32], &[0; 32]);
        assert!(result.is_err());
    }
}