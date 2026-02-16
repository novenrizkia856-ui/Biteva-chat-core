//! Persistent trust data store.
//!
//! Stores per-address interaction counts in an encrypted sled tree.
//! The node-layer [`TrustScorer`] reads from and writes to this store
//! to compute trust levels that survive restarts.

use bitevachat_types::{Address, Result};
use serde::{Deserialize, Serialize};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

// ---------------------------------------------------------------------------
// TrustRecord
// ---------------------------------------------------------------------------

/// Persistent trust data for a single address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRecord {
    /// Number of successful message exchanges with this address.
    pub interaction_count: u32,
}

// ---------------------------------------------------------------------------
// TrustStore
// ---------------------------------------------------------------------------

/// Encrypted trust data store backed by sled.
pub struct TrustStore<'a> {
    tree: EncryptedTree<'a, TrustRecord>,
}

impl<'a> TrustStore<'a> {
    /// Creates a new `TrustStore`.
    ///
    /// Caller should add a `trust_store()` accessor to `StorageEngine`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("trust")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
        })
    }

    /// Returns the interaction count for an address (0 if unknown).
    pub fn get_interaction_count(&self, address: &Address) -> Result<u32> {
        match self.tree.get(address.as_bytes())? {
            Some(record) => Ok(record.interaction_count),
            None => Ok(0),
        }
    }

    /// Increments the interaction count for an address by 1.
    ///
    /// Uses saturating arithmetic to prevent overflow.
    pub fn increment_interaction(&self, address: &Address) -> Result<()> {
        let count = self.get_interaction_count(address)?;
        let new_count = count.saturating_add(1);
        self.tree.insert(
            address.as_bytes(),
            &TrustRecord {
                interaction_count: new_count,
            },
        )
    }

    /// Sets the interaction count for an address directly.
    ///
    /// Used for bulk loading or administrative correction.
    pub fn set_interaction_count(
        &self,
        address: &Address,
        count: u32,
    ) -> Result<()> {
        self.tree.insert(
            address.as_bytes(),
            &TrustRecord {
                interaction_count: count,
            },
        )
    }

    /// Returns all trust records as (address, count) pairs.
    ///
    /// Used by [`TrustScorer::load_from_storage`] at startup.
    pub fn list_all(&self) -> Result<Vec<(Address, u32)>> {
        let entries = self.tree.iter()?;
        let mut result = Vec::new();
        for (key, record) in entries {
            if key.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key);
                result.push((Address::new(bytes), record.interaction_count));
            }
        }
        Ok(result)
    }
}