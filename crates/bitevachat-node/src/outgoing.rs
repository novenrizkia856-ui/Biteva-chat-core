//! Outbound message construction.
//!
//! Builds a signed [`MessageEnvelope`] from plaintext:
//!
//! 1. Generate random 12-byte message nonce.
//! 2. Generate random 24-byte AEAD nonce.
//! 3. Encrypt plaintext with XChaCha20-Poly1305 using the shared
//!    session key.
//! 4. Build [`Message`] struct with all required fields.
//! 5. Compute deterministic `message_id = SHA3-256(sender || ts || nonce)`.
//! 6. Serialize to canonical CBOR (RFC 8949 §4.2).
//! 7. Sign the canonical bytes with the wallet's Ed25519 keypair.
//! 8. Return [`MessageEnvelope`] + [`MessageId`].
//!
//! The caller (event loop) is responsible for routing the envelope
//! to the network layer and enqueuing for pending delivery on failure.
//!
//! # Payload format
//!
//! The `payload_ciphertext` field stores:
//! `[24-byte AEAD nonce] || [ciphertext + 16-byte Poly1305 tag]`
//!
//! The recipient splits on the 24-byte boundary to recover the nonce
//! and ciphertext for decryption.

use bitevachat_crypto::aead::{encrypt_xchacha20, generate_aead_nonce};
use bitevachat_crypto::hash::compute_message_id;
use bitevachat_crypto::signing::pubkey_to_address;
use bitevachat_protocol::canonical::to_canonical_cbor;
use bitevachat_protocol::message::{Message, MessageEnvelope};
use bitevachat_types::{
    Address, BitevachatError, MessageId, NodeId, Nonce, PayloadType, Timestamp,
};
use bitevachat_wallet::wallet::Wallet;
use rand::rngs::OsRng;
use rand::RngCore;

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Builds a signed, encrypted message envelope.
///
/// # Parameters
///
/// - `wallet` — unlocked wallet (provides sender identity + signing key).
/// - `recipient` — destination address.
/// - `plaintext` — cleartext payload bytes.
/// - `payload_type` — classification (Text, File, System).
/// - `shared_key` — 32-byte session key for E2E encryption (derived
///   externally via ECDH).
/// - `node_id` — this node's identifier.
///
/// # Returns
///
/// `(envelope, message_id)` on success.
///
/// # Errors
///
/// - `BitevachatError::CryptoError` if the wallet is locked, nonce
///   generation fails, or encryption/signing fails.
/// - `BitevachatError::ProtocolError` if canonical CBOR serialization
///   fails.
pub fn build_outgoing_envelope(
    wallet: &Wallet,
    recipient: Address,
    plaintext: &[u8],
    payload_type: PayloadType,
    shared_key: &[u8; 32],
    node_id: NodeId,
) -> BResult<(MessageEnvelope, MessageId)> {
    // Obtain signing keypair (fails if wallet is locked).
    let keypair = wallet.get_keypair()?;
    let sender_pk = keypair.public_key();
    let sender = pubkey_to_address(&sender_pk);

    // 1. Generate 12-byte message nonce (for replay detection).
    let mut nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("failed to generate message nonce: {e}"),
        }
    })?;
    let nonce = Nonce::new(nonce_bytes);

    // 2–3. Generate AEAD nonce and encrypt payload.
    let aead_nonce = generate_aead_nonce();
    let encrypted = encrypt_xchacha20(shared_key, &aead_nonce, plaintext, &[])?;

    // Combine [aead_nonce (24B)] || [ciphertext + tag].
    let mut payload_ciphertext =
        Vec::with_capacity(24 + encrypted.ciphertext.len());
    payload_ciphertext.extend_from_slice(aead_nonce.as_bytes());
    payload_ciphertext.extend(encrypted.ciphertext);

    // 4–5. Build Message with deterministic message_id.
    let timestamp = Timestamp::now();
    let message_id = compute_message_id(&sender, &timestamp, &nonce);

    let message = Message {
        sender,
        recipient,
        payload_type,
        payload_ciphertext,
        node_id,
        nonce,
        timestamp,
        message_id,
    };

    // 6. Serialize to canonical CBOR.
    let canonical_bytes = to_canonical_cbor(&message)?;

    // 7. Sign the canonical bytes.
    let signature = keypair.sign(&canonical_bytes);

    // 8. Build envelope.
    let envelope = MessageEnvelope { message, signature };

    Ok((envelope, message_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitevachat_crypto::signing::{verify, Keypair, PublicKey, Signature};
    use bitevachat_protocol::canonical::to_canonical_cbor;

    /// Creates a test wallet (unlocked) with a deterministic seed.
    fn test_wallet() -> Wallet {
        let mnemonic = "abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon art";
        let passphrase = "test-passphrase";
        let mut wallet = Wallet::create_wallet(mnemonic, passphrase)
            .expect("wallet creation");
        wallet.unlock(passphrase).expect("wallet unlock");
        wallet
    }

    #[test]
    fn build_envelope_produces_valid_signature() {
        let wallet = test_wallet();
        let recipient = Address::new([0xBB; 32]);
        let shared_key = [0xCC; 32];
        let node_id = NodeId::new(*wallet.public_key());

        let (envelope, msg_id) = build_outgoing_envelope(
            &wallet,
            recipient,
            b"hello world",
            PayloadType::Text,
            &shared_key,
            node_id,
        )
        .expect("build envelope");

        // Verify the signature.
        let canonical = to_canonical_cbor(&envelope.message)
            .expect("canonical CBOR");
        let pubkey = PublicKey::from_bytes(*wallet.public_key());
        let sig = Signature::from_bytes(*envelope.signature.as_bytes());
        assert!(verify(&pubkey, &canonical, &sig).is_ok());

        // Verify message_id matches.
        assert_eq!(envelope.message.message_id, msg_id);
    }

    #[test]
    fn build_envelope_payload_contains_nonce_prefix() {
        let wallet = test_wallet();
        let recipient = Address::new([0xBB; 32]);
        let shared_key = [0xCC; 32];
        let node_id = NodeId::new(*wallet.public_key());

        let (envelope, _) = build_outgoing_envelope(
            &wallet,
            recipient,
            b"test",
            PayloadType::Text,
            &shared_key,
            node_id,
        )
        .expect("build envelope");

        // payload_ciphertext = [24B nonce] + [ciphertext + 16B tag]
        // plaintext "test" = 4 bytes → ciphertext = 4 + 16 = 20 bytes
        assert_eq!(
            envelope.message.payload_ciphertext.len(),
            24 + 4 + 16,
            "payload must be 24 (nonce) + plaintext_len + 16 (tag)"
        );
    }

    #[test]
    fn locked_wallet_fails() {
        let mnemonic = "abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon art";
        let passphrase = "test-passphrase";
        let wallet = Wallet::create_wallet(mnemonic, passphrase)
            .expect("wallet creation");
        // Wallet is locked (not unlocked).

        let result = build_outgoing_envelope(
            &wallet,
            Address::new([0xBB; 32]),
            b"hello",
            PayloadType::Text,
            &[0xCC; 32],
            NodeId::new([0x00; 32]),
        );

        assert!(result.is_err());
    }
}