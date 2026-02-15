//! Canonical CBOR serialization per RFC 8949 §4.2 (Core Deterministic Encoding).
//!
//! All messages are signed over their canonical CBOR representation to
//! ensure signature validity across nodes regardless of implementation
//! details. The encoding guarantees:
//!
//! - **Sorted keys**: map keys ordered by their CBOR-encoded byte form
//!   (shortest first, then bytewise lexicographic).
//! - **Definite-length**: all maps and byte/text strings use
//!   definite-length encoding.
//! - **Preferred integers**: integers use the shortest encoding.
//! - **No duplicate keys**.
//!
//! The canonical key order for a [`Message`] map (8 entries) is:
//!
//! | # | Key                  | CBOR type | Encoded key prefix |
//! |---|----------------------|-----------|--------------------|
//! | 1 | `"nonce"`            | Bytes     | `0x65`             |
//! | 2 | `"sender"`           | Bytes     | `0x66`             |
//! | 3 | `"node_id"`          | Bytes     | `0x67`             |
//! | 4 | `"recipient"`        | Bytes     | `0x69`             |
//! | 5 | `"timestamp"`        | Text      | `0x69`             |
//! | 6 | `"message_id"`       | Bytes     | `0x6A`             |
//! | 7 | `"payload_type"`     | Text      | `0x6C`             |
//! | 8 | `"payload_ciphertext"` | Bytes   | `0x72`             |

use bitevachat_types::{
    Address, BitevachatError, MessageId, NodeId, Nonce, PayloadType, Result, Timestamp,
};
use ciborium::Value;
use std::str::FromStr;

use crate::message::Message;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of fields in the canonical Message map.
const FIELD_COUNT: usize = 8;

/// Key names in RFC 8949 canonical sort order (sorted by CBOR-encoded
/// key bytes).
///
/// Precomputed: each key's CBOR text encoding starts with `0x60 + len`,
/// so shorter keys sort first; ties broken by UTF-8 byte comparison.
const CANONICAL_KEYS: [&str; FIELD_COUNT] = [
    "nonce",              // 0x65 (len 5)
    "sender",             // 0x66 (len 6)
    "node_id",            // 0x67 (len 7)
    "recipient",          // 0x69 (len 9, 'r')
    "timestamp",          // 0x69 (len 9, 't')
    "message_id",         // 0x6A (len 10)
    "payload_type",       // 0x6C (len 12)
    "payload_ciphertext", // 0x72 (len 18)
];

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Serializes a [`Message`] to canonical CBOR (RFC 8949 §4.2).
///
/// Builds a CBOR map with exactly 8 key-value pairs in the
/// deterministic sort order. All keys are CBOR text strings; values
/// are CBOR byte strings, text strings, or integers depending on the
/// field.
///
/// The output bytes are the canonical representation over which
/// Ed25519 signatures are computed.
///
/// # Errors
///
/// Returns [`BitevachatError::ProtocolError`] if CBOR serialization
/// fails (should not happen for well-formed messages).
pub fn to_canonical_cbor(message: &Message) -> Result<Vec<u8>> {
    let payload_type_str = match message.payload_type {
        PayloadType::Text => "text",
        PayloadType::File => "file",
        PayloadType::System => "system",
    };

    // Build entries in pre-computed canonical order.
    let entries: Vec<(Value, Value)> = vec![
        // 1. "nonce" → Bytes
        (
            Value::Text("nonce".into()),
            Value::Bytes(message.nonce.as_ref().to_vec()),
        ),
        // 2. "sender" → Bytes
        (
            Value::Text("sender".into()),
            Value::Bytes(message.sender.as_ref().to_vec()),
        ),
        // 3. "node_id" → Bytes
        (
            Value::Text("node_id".into()),
            Value::Bytes(message.node_id.as_ref().to_vec()),
        ),
        // 4. "recipient" → Bytes
        (
            Value::Text("recipient".into()),
            Value::Bytes(message.recipient.as_ref().to_vec()),
        ),
        // 5. "timestamp" → Text (ISO 8601)
        (
            Value::Text("timestamp".into()),
            Value::Text(message.timestamp.as_str()),
        ),
        // 6. "message_id" → Bytes
        (
            Value::Text("message_id".into()),
            Value::Bytes(message.message_id.as_ref().to_vec()),
        ),
        // 7. "payload_type" → Text
        (
            Value::Text("payload_type".into()),
            Value::Text(payload_type_str.into()),
        ),
        // 8. "payload_ciphertext" → Bytes
        (
            Value::Text("payload_ciphertext".into()),
            Value::Bytes(message.payload_ciphertext.clone()),
        ),
    ];

    let map = Value::Map(entries);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).map_err(|e| BitevachatError::ProtocolError {
        reason: format!("CBOR serialization failed: {e}"),
    })?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Deserializes a [`Message`] from canonical CBOR bytes.
///
/// # Validation
///
/// - Top-level value must be a CBOR map.
/// - Exactly [`FIELD_COUNT`] (8) entries required.
/// - No duplicate keys allowed.
/// - All 8 expected keys must be present.
/// - Value types must match the schema.
///
/// # Errors
///
/// Returns [`BitevachatError::ProtocolError`] on any structural or
/// type mismatch.
pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Message> {
    let value: Value =
        ciborium::from_reader(bytes).map_err(|e| BitevachatError::ProtocolError {
            reason: format!("CBOR deserialization failed: {e}"),
        })?;

    let entries = match value {
        Value::Map(entries) => entries,
        _ => {
            return Err(BitevachatError::ProtocolError {
                reason: "top-level CBOR value must be a map".into(),
            });
        }
    };

    // Check entry count.
    if entries.len() != FIELD_COUNT {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "expected {FIELD_COUNT} map entries, got {}",
                entries.len()
            ),
        });
    }

    // Check for duplicate keys.
    let mut seen_keys = std::collections::HashSet::with_capacity(FIELD_COUNT);
    for (k, _) in &entries {
        let key_str = extract_text_key(k)?;
        if !seen_keys.insert(key_str) {
            return Err(BitevachatError::ProtocolError {
                reason: format!("duplicate CBOR map key: '{key_str}'"),
            });
        }
    }

    // Build a lookup for extraction.
    let mut lookup = std::collections::HashMap::with_capacity(FIELD_COUNT);
    for (k, v) in entries {
        let key_str = extract_text_key(&k)?;
        lookup.insert(key_str.to_string(), v);
    }

    // Check all expected keys present.
    for key in &CANONICAL_KEYS {
        if !lookup.contains_key(*key) {
            return Err(BitevachatError::ProtocolError {
                reason: format!("missing required CBOR map key: '{key}'"),
            });
        }
    }

    // Extract and validate each field.
    let sender = extract_fixed_bytes(&lookup, "sender", Address::LEN)
        .map(|b| Address::new(to_array_32(&b)))?;

    let recipient = extract_fixed_bytes(&lookup, "recipient", Address::LEN)
        .map(|b| Address::new(to_array_32(&b)))?;

    let node_id = extract_fixed_bytes(&lookup, "node_id", NodeId::LEN)
        .map(|b| NodeId::new(to_array_32(&b)))?;

    let message_id = extract_fixed_bytes(&lookup, "message_id", MessageId::LEN)
        .map(|b| MessageId::new(to_array_32(&b)))?;

    let nonce = extract_fixed_bytes(&lookup, "nonce", Nonce::LEN)
        .map(|b| Nonce::new(to_array_12(&b)))?;

    let payload_ciphertext = extract_bytes_value(&lookup, "payload_ciphertext")?;

    let payload_type = {
        let s = extract_text_value(&lookup, "payload_type")?;
        match s.as_str() {
            "text" => PayloadType::Text,
            "file" => PayloadType::File,
            "system" => PayloadType::System,
            other => {
                return Err(BitevachatError::ProtocolError {
                    reason: format!("invalid payload_type: '{other}'"),
                });
            }
        }
    };

    let timestamp = {
        let s = extract_text_value(&lookup, "timestamp")?;
        Timestamp::from_str(&s).map_err(|e| BitevachatError::ProtocolError {
            reason: format!("invalid timestamp: {e}"),
        })?
    };

    Ok(Message {
        sender,
        recipient,
        payload_type,
        payload_ciphertext,
        node_id,
        nonce,
        timestamp,
        message_id,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extracts a text string from a CBOR key Value.
fn extract_text_key(v: &Value) -> Result<&str> {
    match v {
        Value::Text(s) => Ok(s.as_str()),
        _ => Err(BitevachatError::ProtocolError {
            reason: "CBOR map key must be a text string".into(),
        }),
    }
}

/// Extracts a byte-string value from the lookup map, validating exact length.
fn extract_fixed_bytes(
    lookup: &std::collections::HashMap<String, Value>,
    key: &str,
    expected_len: usize,
) -> Result<Vec<u8>> {
    let bytes = extract_bytes_value(lookup, key)?;
    if bytes.len() != expected_len {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "field '{key}': expected {expected_len} bytes, got {}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

/// Extracts a raw byte-string value from the lookup map.
fn extract_bytes_value(
    lookup: &std::collections::HashMap<String, Value>,
    key: &str,
) -> Result<Vec<u8>> {
    match lookup.get(key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(BitevachatError::ProtocolError {
            reason: format!("field '{key}': expected CBOR byte string"),
        }),
        None => Err(BitevachatError::ProtocolError {
            reason: format!("missing field '{key}'"),
        }),
    }
}

/// Extracts a text-string value from the lookup map.
fn extract_text_value(
    lookup: &std::collections::HashMap<String, Value>,
    key: &str,
) -> Result<String> {
    match lookup.get(key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        Some(_) => Err(BitevachatError::ProtocolError {
            reason: format!("field '{key}': expected CBOR text string"),
        }),
        None => Err(BitevachatError::ProtocolError {
            reason: format!("missing field '{key}'"),
        }),
    }
}

/// Converts a 32-byte `Vec<u8>` to `[u8; 32]`.
///
/// Caller must guarantee `v.len() == 32` (enforced by [`extract_fixed_bytes`]).
fn to_array_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(v);
    arr
}

/// Converts a 12-byte `Vec<u8>` to `[u8; 12]`.
///
/// Caller must guarantee `v.len() == 12` (enforced by [`extract_fixed_bytes`]).
fn to_array_12(v: &[u8]) -> [u8; 12] {
    let mut arr = [0u8; 12];
    arr.copy_from_slice(v);
    arr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitevachat_crypto::hash::compute_message_id;
    use chrono::TimeZone;

    /// Builds a deterministic test message with fixed values.
    fn test_message() -> Message {
        let sender = Address::new([0x01; 32]);
        let recipient = Address::new([0x02; 32]);
        let node_id = NodeId::new([0x03; 32]);
        let nonce = Nonce::new([0xAA; 12]);
        let dt = chrono::Utc
            .with_ymd_and_hms(2025, 6, 15, 12, 0, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now);
        let timestamp = Timestamp::from_datetime(dt);
        let message_id = compute_message_id(&sender, &timestamp, &nonce);

        Message {
            sender,
            recipient,
            payload_type: PayloadType::Text,
            payload_ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            node_id,
            nonce,
            timestamp,
            message_id,
        }
    }

    #[test]
    fn canonical_roundtrip_produces_identical_bytes() -> std::result::Result<(), BitevachatError> {
        let msg = test_message();
        let bytes1 = to_canonical_cbor(&msg)?;
        let decoded = from_canonical_cbor(&bytes1)?;
        let bytes2 = to_canonical_cbor(&decoded)?;
        assert_eq!(bytes1, bytes2, "canonical roundtrip must produce identical bytes");
        Ok(())
    }

    #[test]
    fn canonical_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let msg = test_message();
        let bytes1 = to_canonical_cbor(&msg)?;
        let bytes2 = to_canonical_cbor(&msg)?;
        assert_eq!(bytes1, bytes2);
        Ok(())
    }

    #[test]
    fn decode_rejects_non_map() {
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&Value::Text("not a map".into()), &mut buf);
        let result = from_canonical_cbor(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_missing_field() {
        // Map with only 7 entries (missing payload_ciphertext).
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text("nonce".into()), Value::Bytes(vec![0xAA; 12])),
            (Value::Text("sender".into()), Value::Bytes(vec![0x01; 32])),
            (Value::Text("node_id".into()), Value::Bytes(vec![0x03; 32])),
            (Value::Text("recipient".into()), Value::Bytes(vec![0x02; 32])),
            (Value::Text("timestamp".into()), Value::Text("2025-06-15T12:00:00+00:00".into())),
            (Value::Text("message_id".into()), Value::Bytes(vec![0x00; 32])),
            (Value::Text("payload_type".into()), Value::Text("text".into())),
        ];
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&Value::Map(entries), &mut buf);
        let result = from_canonical_cbor(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_wrong_value_type() {
        // "sender" as text instead of bytes.
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text("nonce".into()), Value::Bytes(vec![0xAA; 12])),
            (Value::Text("sender".into()), Value::Text("not bytes".into())),
            (Value::Text("node_id".into()), Value::Bytes(vec![0x03; 32])),
            (Value::Text("recipient".into()), Value::Bytes(vec![0x02; 32])),
            (Value::Text("timestamp".into()), Value::Text("2025-06-15T12:00:00+00:00".into())),
            (Value::Text("message_id".into()), Value::Bytes(vec![0x00; 32])),
            (Value::Text("payload_type".into()), Value::Text("text".into())),
            (Value::Text("payload_ciphertext".into()), Value::Bytes(vec![0xDE])),
        ];
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&Value::Map(entries), &mut buf);
        let result = from_canonical_cbor(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_wrong_byte_length() {
        // "sender" with 16 bytes instead of 32.
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text("nonce".into()), Value::Bytes(vec![0xAA; 12])),
            (Value::Text("sender".into()), Value::Bytes(vec![0x01; 16])),
            (Value::Text("node_id".into()), Value::Bytes(vec![0x03; 32])),
            (Value::Text("recipient".into()), Value::Bytes(vec![0x02; 32])),
            (Value::Text("timestamp".into()), Value::Text("2025-06-15T12:00:00+00:00".into())),
            (Value::Text("message_id".into()), Value::Bytes(vec![0x00; 32])),
            (Value::Text("payload_type".into()), Value::Text("text".into())),
            (Value::Text("payload_ciphertext".into()), Value::Bytes(vec![0xDE])),
        ];
        let mut buf = Vec::new();
        let _ = ciborium::into_writer(&Value::Map(entries), &mut buf);
        let result = from_canonical_cbor(&buf);
        assert!(result.is_err());
    }
}