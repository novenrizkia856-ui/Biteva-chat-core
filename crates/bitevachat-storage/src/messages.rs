//! Per-conversation encrypted message store with retention pruning.
//!
//! Messages are keyed as `convo_id(32) || timestamp_millis_be(8) || message_id(32)`
//! to enable efficient prefix scanning per conversation and natural
//! timestamp-ascending ordering within sled's lexicographic iterator.
//!
//! Pinned messages are tracked in a separate `pins` tree and are
//! exempt from retention pruning.

use bitevachat_types::{BitevachatError, ConvoId, MessageId, Result, Timestamp};
use serde::{Deserialize, Serialize};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

// ---------------------------------------------------------------------------
// StoredMessage
// ---------------------------------------------------------------------------

/// A message stored in the encrypted database.
///
/// This struct wraps the serializable parts of a message envelope
/// for storage. The original protocol-level `MessageEnvelope` fields
/// are mapped into this structure before persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Sender address (32 bytes, hex-decodable).
    pub sender: [u8; 32],
    /// Recipient address.
    pub recipient: [u8; 32],
    /// Message identifier.
    pub message_id: [u8; 32],
    /// Conversation identifier.
    pub convo_id: [u8; 32],
    /// Timestamp as milliseconds since epoch (UTC).
    pub timestamp_millis: i64,
    /// Payload type tag (0 = Text, 1 = File, 2 = System).
    pub payload_type: u8,
    /// Encrypted payload ciphertext.
    pub payload_ciphertext: Vec<u8>,
    /// Nonce used for the message-level encryption.
    pub nonce: [u8; 12],
    /// Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// PinEntry
// ---------------------------------------------------------------------------

/// Marker entry for a pinned/starred message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinEntry {
    /// When the message was pinned (millis since epoch).
    pub pinned_at_millis: i64,
}

// ---------------------------------------------------------------------------
// MessageStore
// ---------------------------------------------------------------------------

/// Encrypted per-conversation message store.
pub struct MessageStore<'a> {
    messages: EncryptedTree<'a, StoredMessage>,
    pins: EncryptedTree<'a, PinEntry>,
}

impl<'a> MessageStore<'a> {
    /// Creates a new `MessageStore` backed by the engine.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let msg_tree = engine.open_tree("messages")?;
        let pin_tree = engine.open_tree("pins")?;
        Ok(Self {
            messages: EncryptedTree::new(msg_tree, engine.keys()),
            pins: EncryptedTree::new(pin_tree, engine.keys()),
        })
    }

    /// Stores a message.
    ///
    /// The key is `convo_id || timestamp_millis_be || message_id`
    /// (72 bytes total).
    pub fn store_message(&self, msg: &StoredMessage) -> Result<()> {
        let key = build_message_key(
            &msg.convo_id,
            msg.timestamp_millis,
            &msg.message_id,
        );
        self.messages.insert(&key, msg)
    }

    /// Retrieves messages for a conversation, sorted by timestamp
    /// ascending, with limit and offset.
    pub fn get_messages(
        &self,
        convo_id: &ConvoId,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredMessage>> {
        let entries = self.messages.scan_prefix(convo_id.as_bytes())?;
        // entries are already in lexicographic order (timestamp asc)
        let result: Vec<StoredMessage> = entries
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(_, msg)| msg)
            .collect();
        Ok(result)
    }

    /// Returns the total message count for a conversation.
    pub fn message_count(&self, convo_id: &ConvoId) -> Result<u64> {
        let keys = self.messages.keys_by_prefix(convo_id.as_bytes())?;
        Ok(keys.len() as u64)
    }

    /// Prunes oldest non-pinned messages until at most `retention_limit`
    /// messages remain for the given conversation.
    ///
    /// Pinned messages are never deleted.
    pub fn prune_old(&self, convo_id: &ConvoId, retention_limit: usize) -> Result<u64> {
        let keys = self.messages.keys_by_prefix(convo_id.as_bytes())?;
        let total = keys.len();

        if total <= retention_limit {
            return Ok(0);
        }

        let to_remove = total - retention_limit;
        let mut removed = 0u64;

        // Keys are in timestamp-ascending order; delete oldest first.
        for key in keys.iter().take(total) {
            if removed as usize >= to_remove {
                break;
            }

            // Check if pinned.
            if self.is_pinned_key(key)? {
                continue;
            }

            self.messages.delete(key)?;
            removed += 1;
        }

        Ok(removed)
    }

    /// Pins (stars) a message.
    pub fn pin_message(
        &self,
        convo_id: &ConvoId,
        timestamp_millis: i64,
        message_id: &MessageId,
    ) -> Result<()> {
        let key = build_message_key(convo_id.as_bytes(), timestamp_millis, message_id.as_bytes());
        let entry = PinEntry {
            pinned_at_millis: chrono::Utc::now().timestamp_millis(),
        };
        self.pins.insert(&key, &entry)
    }

    /// Unpins a message.
    pub fn unpin_message(
        &self,
        convo_id: &ConvoId,
        timestamp_millis: i64,
        message_id: &MessageId,
    ) -> Result<()> {
        let key = build_message_key(convo_id.as_bytes(), timestamp_millis, message_id.as_bytes());
        self.pins.delete(&key)?;
        Ok(())
    }

    /// Checks if a message (identified by its full key) is pinned.
    pub fn is_pinned(
        &self,
        convo_id: &ConvoId,
        timestamp_millis: i64,
        message_id: &MessageId,
    ) -> Result<bool> {
        let key = build_message_key(convo_id.as_bytes(), timestamp_millis, message_id.as_bytes());
        self.is_pinned_key(&key)
    }

    /// Internal: checks pin by raw key.
    fn is_pinned_key(&self, key: &[u8]) -> Result<bool> {
        let entry: Option<PinEntry> = self.pins.get(key)?;
        Ok(entry.is_some())
    }

    /// Returns the timestamp of the most recent message in a conversation.
    pub fn last_message_timestamp(&self, convo_id: &ConvoId) -> Result<Option<Timestamp>> {
        // Scan all keys with this prefix; the last one has the highest timestamp.
        let keys = self.messages.keys_by_prefix(convo_id.as_bytes())?;
        match keys.last() {
            None => Ok(None),
            Some(key) => {
                // Extract timestamp from key bytes [32..40] (big-endian i64).
                if key.len() < 40 {
                    return Err(BitevachatError::StorageError {
                        reason: "message key too short to extract timestamp".into(),
                    });
                }
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&key[32..40]);
                let millis = i64::from_be_bytes(ts_bytes);
                let dt = chrono::DateTime::from_timestamp_millis(millis)
                    .ok_or_else(|| BitevachatError::StorageError {
                        reason: format!("invalid timestamp millis: {millis}"),
                    })?;
                Ok(Some(Timestamp::from_datetime(dt)))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key construction
// ---------------------------------------------------------------------------

/// Builds a 72-byte message key:
/// `convo_id(32) || timestamp_millis_be(8) || message_id(32)`.
fn build_message_key(
    convo_id: &[u8],
    timestamp_millis: i64,
    message_id: &[u8],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(72);
    key.extend_from_slice(&convo_id[..32]);
    key.extend_from_slice(&timestamp_millis.to_be_bytes());
    key.extend_from_slice(&message_id[..32]);
    key
}