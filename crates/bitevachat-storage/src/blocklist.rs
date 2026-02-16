//! System-level blocklist and whitelist store.
//!
//! Separate from [`crate::contacts::ContactStore`] (user-level blocking).
//! This store is used by the anti-spam system for automated block/allow
//! decisions.
//!
//! **Whitelist overrides blocklist**: an address that is both blocked
//! AND whitelisted is treated as NOT blocked.

use bitevachat_types::{Address, Result};
use serde::{Deserialize, Serialize};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

// ---------------------------------------------------------------------------
// BlocklistEntry
// ---------------------------------------------------------------------------

/// A single entry in the blocklist store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Whether this address is on the blocklist.
    pub blocked: bool,
    /// Whether this address is on the whitelist (overrides blocked).
    pub whitelisted: bool,
}

// ---------------------------------------------------------------------------
// BlocklistStore
// ---------------------------------------------------------------------------

/// Encrypted blocklist + whitelist store backed by sled.
pub struct BlocklistStore<'a> {
    tree: EncryptedTree<'a, BlocklistEntry>,
}

impl<'a> BlocklistStore<'a> {
    /// Creates a new `BlocklistStore`.
    ///
    /// Caller should add a `blocklist()` accessor to `StorageEngine`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("blocklist")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
        })
    }

    /// Adds an address to the blocklist.
    pub fn add(&self, address: &Address) -> Result<()> {
        let mut entry = self.get_or_default(address)?;
        entry.blocked = true;
        self.tree.insert(address.as_bytes(), &entry)
    }

    /// Removes an address from the blocklist.
    pub fn remove(&self, address: &Address) -> Result<()> {
        let mut entry = self.get_or_default(address)?;
        entry.blocked = false;
        // If neither blocked nor whitelisted, remove entirely.
        if !entry.whitelisted {
            self.tree.delete(address.as_bytes())?;
            return Ok(());
        }
        self.tree.insert(address.as_bytes(), &entry)
    }

    /// Returns `true` if the address is **effectively** blocked.
    ///
    /// An address is effectively blocked if it is on the blocklist
    /// AND **not** on the whitelist.
    pub fn contains(&self, address: &Address) -> Result<bool> {
        match self.tree.get(address.as_bytes())? {
            Some(entry) => Ok(entry.blocked && !entry.whitelisted),
            None => Ok(false),
        }
    }

    /// Adds an address to the whitelist.
    ///
    /// Whitelisted addresses bypass the blocklist check even if
    /// they are also on the blocklist.
    pub fn whitelist_add(&self, address: &Address) -> Result<()> {
        let mut entry = self.get_or_default(address)?;
        entry.whitelisted = true;
        self.tree.insert(address.as_bytes(), &entry)
    }

    /// Removes an address from the whitelist.
    pub fn whitelist_remove(&self, address: &Address) -> Result<()> {
        let mut entry = self.get_or_default(address)?;
        entry.whitelisted = false;
        // If neither blocked nor whitelisted, remove entirely.
        if !entry.blocked {
            self.tree.delete(address.as_bytes())?;
            return Ok(());
        }
        self.tree.insert(address.as_bytes(), &entry)
    }

    /// Returns `true` if the address is whitelisted.
    pub fn is_whitelisted(&self, address: &Address) -> Result<bool> {
        match self.tree.get(address.as_bytes())? {
            Some(entry) => Ok(entry.whitelisted),
            None => Ok(false),
        }
    }

    /// Lists all effectively blocked addresses.
    pub fn list_blocked(&self) -> Result<Vec<Address>> {
        let entries = self.tree.iter()?;
        let mut blocked = Vec::new();
        for (key, entry) in &entries {
            if entry.blocked && !entry.whitelisted && key.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(key);
                blocked.push(Address::new(bytes));
            }
        }
        Ok(blocked)
    }

    /// Lists all whitelisted addresses.
    pub fn list_whitelisted(&self) -> Result<Vec<Address>> {
        let entries = self.tree.iter()?;
        let mut whitelisted = Vec::new();
        for (key, entry) in &entries {
            if entry.whitelisted && key.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(key);
                whitelisted.push(Address::new(bytes));
            }
        }
        Ok(whitelisted)
    }

    /// Gets existing entry or creates a default one.
    fn get_or_default(&self, address: &Address) -> Result<BlocklistEntry> {
        match self.tree.get(address.as_bytes())? {
            Some(entry) => Ok(entry),
            None => Ok(BlocklistEntry {
                blocked: false,
                whitelisted: false,
            }),
        }
    }
}