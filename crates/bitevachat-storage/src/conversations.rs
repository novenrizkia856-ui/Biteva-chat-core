//! Conversation index: creation, listing, and summary queries.
//!
//! A conversation ID is deterministically computed as
//! `SHA3-256(sorted(self_address || peer_address))`.
//! This guarantees both participants derive the same `ConvoId`
//! regardless of who initiates the conversation.

use bitevachat_crypto::hash::sha3_256;
use bitevachat_types::{Address, BitevachatError, ConvoId, ConvoSummary, Result};
use serde::{Deserialize, Serialize};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

// ---------------------------------------------------------------------------
// ConversationRecord
// ---------------------------------------------------------------------------

/// Internal serializable record for a conversation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationRecord {
    /// The self address that owns this conversation.
    pub self_address: [u8; 32],
    /// The peer address.
    pub peer_address: [u8; 32],
    /// Optional display alias for the peer.
    pub alias: Option<String>,
}

// ---------------------------------------------------------------------------
// ConversationIndex
// ---------------------------------------------------------------------------

/// Encrypted conversation index.
pub struct ConversationIndex<'a> {
    tree: EncryptedTree<'a, ConversationRecord>,
    engine: &'a StorageEngine,
}

impl<'a> ConversationIndex<'a> {
    /// Creates a new `ConversationIndex`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("conversations")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
            engine,
        })
    }

    /// Computes a deterministic `ConvoId` from two addresses.
    ///
    /// `ConvoId = SHA3-256(min(a, b) || max(a, b))`
    ///
    /// This ensures both participants derive the same ID.
    pub fn compute_convo_id(a: &Address, b: &Address) -> ConvoId {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();

        let mut input = [0u8; 64];
        if a_bytes <= b_bytes {
            input[..32].copy_from_slice(a_bytes);
            input[32..].copy_from_slice(b_bytes);
        } else {
            input[..32].copy_from_slice(b_bytes);
            input[32..].copy_from_slice(a_bytes);
        }

        let hash = sha3_256(&input);
        ConvoId::new(hash)
    }

    /// Creates or retrieves a conversation with a peer.
    ///
    /// If the conversation already exists, this is a no-op.
    /// Returns the `ConvoId`.
    pub fn create_conversation(
        &self,
        self_address: &Address,
        peer_address: &Address,
    ) -> Result<ConvoId> {
        let convo_id = Self::compute_convo_id(self_address, peer_address);

        // Check if it already exists.
        let existing: Option<ConversationRecord> = self.tree.get(convo_id.as_bytes())?;
        if existing.is_some() {
            return Ok(convo_id);
        }

        let record = ConversationRecord {
            self_address: *self_address.as_bytes(),
            peer_address: *peer_address.as_bytes(),
            alias: None,
        };

        self.tree.insert(convo_id.as_bytes(), &record)?;
        Ok(convo_id)
    }

    /// Lists all conversations with summary metadata.
    pub fn list_conversations(&self) -> Result<Vec<ConvoSummary>> {
        let entries = self.tree.iter()?;
        let msg_store = self.engine.messages()?;

        let mut summaries = Vec::with_capacity(entries.len());
        for (key, record) in &entries {
            if key.len() != 32 {
                continue;
            }
            let mut id_bytes = [0u8; 32];
            id_bytes.copy_from_slice(key);
            let convo_id = ConvoId::new(id_bytes);

            let message_count = msg_store.message_count(&convo_id)?;
            let last_message_at = msg_store.last_message_timestamp(&convo_id)?;

            summaries.push(ConvoSummary {
                convo_id,
                peer_address: Address::new(record.peer_address),
                alias: record.alias.clone(),
                last_message_at,
                message_count,
            });
        }

        Ok(summaries)
    }

    /// Sets a display alias for a conversation's peer.
    pub fn set_alias(&self, convo_id: &ConvoId, alias: Option<String>) -> Result<()> {
        let mut record: ConversationRecord = self
            .tree
            .get(convo_id.as_bytes())?
            .ok_or_else(|| BitevachatError::StorageError {
                reason: "conversation not found".into(),
            })?;

        record.alias = alias;
        self.tree.insert(convo_id.as_bytes(), &record)
    }
}