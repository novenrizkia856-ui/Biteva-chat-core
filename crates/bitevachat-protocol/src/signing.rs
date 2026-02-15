//! Message signing and envelope verification.
//!
//! All signatures are computed over the canonical CBOR encoding of a
//! [`Message`], never over a raw struct or serde-derived encoding.
//! Verification reconstructs the canonical bytes and checks the
//! Ed25519 signature, then validates the message ID and timestamp.

use bitevachat_crypto::signing::{verify, Keypair, PublicKey, Signature};
use bitevachat_types::{BitevachatError, Result};

use crate::canonical::to_canonical_cbor;
use crate::message::{Message, MessageEnvelope, VerifiedMessage};
use crate::validation::{validate_message_id, validate_timestamp};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum allowed timestamp skew (±5 minutes).
const DEFAULT_MAX_SKEW_SECONDS: i64 = 300;

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Signs a [`Message`] and wraps it in a [`MessageEnvelope`].
///
/// # Process
///
/// 1. Serialize the message to canonical CBOR.
/// 2. Sign the canonical bytes with the Ed25519 keypair.
/// 3. Return the envelope containing message + signature.
///
/// The message struct is **not** modified. The signature covers the
/// exact canonical CBOR byte sequence.
///
/// # Errors
///
/// Returns [`BitevachatError::ProtocolError`] if canonical CBOR
/// serialization fails.
pub fn sign_message(keypair: &Keypair, message: Message) -> Result<MessageEnvelope> {
    let canonical_bytes = to_canonical_cbor(&message)?;
    let signature = keypair.sign(&canonical_bytes);

    Ok(MessageEnvelope { message, signature })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verifies a [`MessageEnvelope`] and returns a [`VerifiedMessage`].
///
/// # Process
///
/// 1. Serialize the enclosed message to canonical CBOR.
/// 2. Verify the Ed25519 signature against `sender_public_key`.
/// 3. Validate the `message_id` (recompute and compare).
/// 4. Validate the `timestamp` (within ±5 minutes of now).
/// 5. Return a [`VerifiedMessage`] on success.
///
/// Decryption of the payload must happen **after** this function
/// succeeds, never before.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if the signature is invalid.
/// - [`BitevachatError::ProtocolError`] if message ID or timestamp
///   validation fails, or if canonical encoding fails.
pub fn verify_envelope(
    envelope: &MessageEnvelope,
    sender_public_key: &PublicKey,
) -> Result<VerifiedMessage> {
    // 1. Canonical encoding.
    let canonical_bytes = to_canonical_cbor(&envelope.message)?;

    // 2. Signature verification.
    verify(sender_public_key, &canonical_bytes, &envelope.signature)?;

    // 3. Message ID validation.
    validate_message_id(&envelope.message)?;

    // 4. Timestamp validation.
    let max_skew = chrono::Duration::seconds(DEFAULT_MAX_SKEW_SECONDS);
    validate_timestamp(&envelope.message.timestamp, max_skew)?;

    // 5. Success.
    Ok(VerifiedMessage {
        message: envelope.message.clone(),
        sender_public_key: *sender_public_key,
    })
}

/// Verifies a [`MessageEnvelope`] with a custom timestamp skew.
///
/// Identical to [`verify_envelope`] but allows the caller to specify
/// the maximum acceptable timestamp deviation from the current UTC
/// time. Useful for testing and for nodes with relaxed time
/// synchronization requirements.
///
/// # Errors
///
/// Same as [`verify_envelope`].
pub fn verify_envelope_with_skew(
    envelope: &MessageEnvelope,
    sender_public_key: &PublicKey,
    max_skew: chrono::Duration,
) -> Result<VerifiedMessage> {
    let canonical_bytes = to_canonical_cbor(&envelope.message)?;

    verify(sender_public_key, &canonical_bytes, &envelope.signature)?;

    validate_message_id(&envelope.message)?;

    validate_timestamp(&envelope.message.timestamp, max_skew)?;

    Ok(VerifiedMessage {
        message: envelope.message.clone(),
        sender_public_key: *sender_public_key,
    })
}