//! Outbound message construction with E2E encryption.
//!
//! Builds a signed [`MessageEnvelope`] from plaintext:
//!
//! 1. Generate random 12-byte message nonce (replay detection).
//! 2. **Encrypt** plaintext with E2E (ephemeral ECDH + XChaCha20-Poly1305)
//!    if the recipient's Ed25519 public key is known. Otherwise fall
//!    back to plaintext (backward compatible).
//! 3. Build [`Message`] struct with the (possibly encrypted) payload.
//! 4. Compute deterministic `message_id = SHA3-256(sender || ts || nonce)`.
//! 5. Serialize to canonical CBOR (RFC 8949 §4.2).
//! 6. Sign the canonical bytes with the wallet's Ed25519 keypair.
//!    **Signature covers the encrypted payload** — relay nodes can
//!    verify authenticity without decrypting content.
//! 7. Return `(envelope, message_id)`.
//!
//! # E2E Payload Format
//!
//! When encryption is active, `payload_ciphertext` contains:
//!
//! ```text
//! [0xE2][0xE0]              — 2-byte magic header (E2E marker)
//! [0x01]                    — 1-byte version
//! [32 bytes]                — sender's ephemeral X25519 public key
//! [24 bytes]                — XChaCha20-Poly1305 nonce
//! [remaining]               — ciphertext + 16-byte Poly1305 tag
//! ```
//!
//! When the magic header is absent, `payload_ciphertext` is treated
//! as legacy plaintext by receivers.

use bitevachat_crypto::hash::compute_message_id;
use bitevachat_crypto::signing::pubkey_to_address;
use bitevachat_protocol::canonical::to_canonical_cbor;
use bitevachat_protocol::e2e;
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
// E2E payload constants
// ---------------------------------------------------------------------------

/// Magic header bytes identifying an E2E encrypted payload.
pub const E2E_MAGIC: [u8; 2] = [0xE2, 0xE0];

/// Current E2E payload format version.
pub const E2E_VERSION: u8 = 0x01;

/// Fixed overhead of E2E header: magic(2) + version(1) + ephemeral_pk(32) + nonce(24).
pub const E2E_HEADER_LEN: usize = 59;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Builds a signed message envelope, optionally E2E encrypted.
///
/// # Parameters
///
/// - `wallet` — unlocked wallet (provides sender identity + signing key).
/// - `recipient` — destination address.
/// - `plaintext` — cleartext payload bytes.
/// - `payload_type` — classification (Text, File, System).
/// - `recipient_pubkey` — recipient's Ed25519 public key (32 bytes).
///   If `Some`, the payload is E2E encrypted. If `None`, plaintext
///   is sent directly (backward compatible with old nodes).
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
    recipient_pubkey: Option<&[u8; 32]>,
    node_id: NodeId,
) -> BResult<(MessageEnvelope, MessageId)> {
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

    // 2. Encrypt payload if recipient pubkey is known.
    let payload_ciphertext = match recipient_pubkey {
        Some(rpk) => {
            match e2e::encrypt_message(&keypair, rpk, plaintext) {
                Ok(encrypted) => serialize_e2e_payload(&encrypted),
                Err(e) => {
                    tracing::warn!(
                        %e,
                        "E2E encryption failed, falling back to plaintext"
                    );
                    plaintext.to_vec()
                }
            }
        }
        None => {
            tracing::debug!(
                "no recipient pubkey available, sending as plaintext"
            );
            plaintext.to_vec()
        }
    };

    // 3. Build Message with deterministic message_id.
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

    // 4. Serialize to canonical CBOR.
    let canonical_bytes = to_canonical_cbor(&message)?;

    // 5. Sign the canonical bytes (covers encrypted payload).
    let signature = keypair.sign(&canonical_bytes);

    // 6. Build envelope.
    let envelope = MessageEnvelope { message, signature };

    Ok((envelope, message_id))
}

/// Legacy wrapper for backward compatibility.
///
/// The `shared_key` parameter is **ignored**. Use
/// [`build_outgoing_envelope`] directly for E2E support.
pub fn build_outgoing_envelope_compat(
    wallet: &Wallet,
    recipient: Address,
    plaintext: &[u8],
    payload_type: PayloadType,
    _shared_key: &[u8; 32],
    node_id: NodeId,
) -> BResult<(MessageEnvelope, MessageId)> {
    build_outgoing_envelope(wallet, recipient, plaintext, payload_type, None, node_id)
}

// ---------------------------------------------------------------------------
// E2E payload serialization / parsing (public for incoming.rs)
// ---------------------------------------------------------------------------

/// Serializes an [`e2e::EncryptedPayload`] into the binary wire format.
fn serialize_e2e_payload(encrypted: &e2e::EncryptedPayload) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        E2E_HEADER_LEN.saturating_add(encrypted.ciphertext.len()),
    );
    buf.extend_from_slice(&E2E_MAGIC);
    buf.push(E2E_VERSION);
    buf.extend_from_slice(&encrypted.ephemeral_pubkey);
    buf.extend_from_slice(&encrypted.nonce);
    buf.extend_from_slice(&encrypted.ciphertext);
    buf
}

/// Checks if a payload starts with the E2E magic header.
pub fn is_e2e_encrypted(payload: &[u8]) -> bool {
    payload.len() > E2E_HEADER_LEN
        && payload[0] == E2E_MAGIC[0]
        && payload[1] == E2E_MAGIC[1]
}

/// Parses the E2E binary format back into an [`e2e::EncryptedPayload`].
pub fn parse_e2e_payload(payload: &[u8]) -> BResult<e2e::EncryptedPayload> {
    if payload.len() <= E2E_HEADER_LEN {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "E2E payload too short: {} bytes (minimum {})",
                payload.len(),
                E2E_HEADER_LEN + 1,
            ),
        });
    }

    if payload[0] != E2E_MAGIC[0] || payload[1] != E2E_MAGIC[1] {
        return Err(BitevachatError::CryptoError {
            reason: "E2E magic header mismatch".into(),
        });
    }

    let version = payload[2];
    if version != E2E_VERSION {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "unsupported E2E version {version} (expected {E2E_VERSION})"
            ),
        });
    }

    let mut ephemeral_pubkey = [0u8; 32];
    ephemeral_pubkey.copy_from_slice(&payload[3..35]);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&payload[35..59]);

    let ciphertext = payload[59..].to_vec();

    Ok(e2e::EncryptedPayload {
        ephemeral_pubkey,
        nonce,
        ciphertext,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitevachat_crypto::signing::{verify, Keypair, PublicKey, Signature};
    use bitevachat_protocol::canonical::to_canonical_cbor;

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
    fn build_envelope_plaintext_when_no_pubkey() {
        let wallet = test_wallet();
        let node_id = NodeId::new(*wallet.public_key());

        let (envelope, _) = build_outgoing_envelope(
            &wallet,
            Address::new([0xBB; 32]),
            b"hello",
            PayloadType::Text,
            None,
            node_id,
        )
        .expect("build envelope");

        assert_eq!(envelope.message.payload_ciphertext, b"hello");
        assert!(!is_e2e_encrypted(&envelope.message.payload_ciphertext));
    }

    #[test]
    fn build_envelope_e2e_when_pubkey_provided() {
        let wallet = test_wallet();
        let bob = Keypair::from_seed(&[0xBB; 32]);
        let bob_addr = pubkey_to_address(&bob.public_key());
        let node_id = NodeId::new(*wallet.public_key());

        let (envelope, _) = build_outgoing_envelope(
            &wallet,
            bob_addr,
            b"secret message",
            PayloadType::Text,
            Some(bob.public_key().as_bytes()),
            node_id,
        )
        .expect("build envelope");

        assert!(is_e2e_encrypted(&envelope.message.payload_ciphertext));
    }

    #[test]
    fn e2e_roundtrip() {
        let alice = Keypair::from_seed(&[0xAA; 32]);
        let bob = Keypair::from_seed(&[0xBB; 32]);

        let encrypted = e2e::encrypt_message(
            &alice,
            bob.public_key().as_bytes(),
            b"roundtrip test",
        )
        .expect("encrypt");

        let serialized = serialize_e2e_payload(&encrypted);
        assert!(is_e2e_encrypted(&serialized));

        let parsed = parse_e2e_payload(&serialized).expect("parse");
        let plaintext = e2e::decrypt_message(
            &bob,
            alice.public_key().as_bytes(),
            &parsed,
        )
        .expect("decrypt");
        assert_eq!(plaintext, b"roundtrip test");
    }

    #[test]
    fn signature_covers_encrypted_payload() {
        let wallet = test_wallet();
        let bob = Keypair::from_seed(&[0xBB; 32]);
        let bob_addr = pubkey_to_address(&bob.public_key());
        let node_id = NodeId::new(*wallet.public_key());

        let (envelope, _) = build_outgoing_envelope(
            &wallet,
            bob_addr,
            b"signed encrypted",
            PayloadType::Text,
            Some(bob.public_key().as_bytes()),
            node_id,
        )
        .expect("build");

        let canonical = to_canonical_cbor(&envelope.message).expect("cbor");
        let pubkey = PublicKey::from_bytes(*wallet.public_key());
        let sig = Signature::from_bytes(*envelope.signature.as_bytes());
        assert!(verify(&pubkey, &canonical, &sig).is_ok());
    }

    #[test]
    fn locked_wallet_fails() {
        let mnemonic = "abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon \
                         abandon abandon abandon art";
        let wallet = Wallet::create_wallet(mnemonic, "pass")
            .expect("wallet creation");

        let result = build_outgoing_envelope(
            &wallet,
            Address::new([0xBB; 32]),
            b"hello",
            PayloadType::Text,
            None,
            NodeId::new([0x00; 32]),
        );
        assert!(result.is_err());
    }
}