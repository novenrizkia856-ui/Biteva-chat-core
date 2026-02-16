//! Contact store: address-to-alias mapping and encrypted blocklist.
//!
//! All contact data (aliases, blocklist entries) is stored encrypted.

use bitevachat_types::{Address, Result};
use serde::{Deserialize, Serialize};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

// ---------------------------------------------------------------------------
// ContactRecord
// ---------------------------------------------------------------------------

/// A contact entry in the encrypted store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactRecord {
    /// Display alias for this contact.
    pub alias: Option<String>,
    /// Whether this contact is blocked.
    pub blocked: bool,
}

// ---------------------------------------------------------------------------
// ContactStore
// ---------------------------------------------------------------------------

/// Encrypted contact store.
pub struct ContactStore<'a> {
    tree: EncryptedTree<'a, ContactRecord>,
}

impl<'a> ContactStore<'a> {
    /// Creates a new `ContactStore`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("contacts")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
        })
    }

    /// Sets or updates the alias for a contact.
    pub fn set_alias(&self, address: &Address, alias: Option<String>) -> Result<()> {
        let mut record = self.get_or_default(address)?;
        record.alias = alias;
        self.tree.insert(address.as_bytes(), &record)
    }

    /// Returns the alias for a contact, if set.
    pub fn get_alias(&self, address: &Address) -> Result<Option<String>> {
        match self.tree.get(address.as_bytes())? {
            Some(record) => Ok(record.alias),
            None => Ok(None),
        }
    }

    /// Returns the full contact record for an address, if it exists.
    ///
    /// Returns `Ok(None)` if the address has never been added as a
    /// contact. Returns `Ok(Some(record))` if any contact data
    /// (alias or block status) has been stored for this address.
    pub fn get_contact(&self, address: &Address) -> Result<Option<ContactRecord>> {
        self.tree.get(address.as_bytes())
    }

    /// Blocks a contact.
    pub fn block(&self, address: &Address) -> Result<()> {
        let mut record = self.get_or_default(address)?;
        record.blocked = true;
        self.tree.insert(address.as_bytes(), &record)
    }

    /// Unblocks a contact.
    pub fn unblock(&self, address: &Address) -> Result<()> {
        let mut record = self.get_or_default(address)?;
        record.blocked = false;
        self.tree.insert(address.as_bytes(), &record)
    }

    /// Returns `true` if the address is blocked.
    pub fn is_blocked(&self, address: &Address) -> Result<bool> {
        match self.tree.get(address.as_bytes())? {
            Some(record) => Ok(record.blocked),
            None => Ok(false),
        }
    }

    /// Lists all blocked addresses.
    pub fn list_blocked(&self) -> Result<Vec<Address>> {
        let entries = self.tree.iter()?;
        let mut blocked = Vec::new();
        for (key, record) in &entries {
            if record.blocked && key.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(key);
                blocked.push(Address::new(bytes));
            }
        }
        Ok(blocked)
    }

    /// Lists all contacts with aliases.
    pub fn list_contacts(&self) -> Result<Vec<(Address, ContactRecord)>> {
        let entries = self.tree.iter()?;
        let mut contacts = Vec::new();
        for (key, record) in entries {
            if key.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key);
                contacts.push((Address::new(bytes), record));
            }
        }
        Ok(contacts)
    }

    /// Gets existing record or creates a default one.
    fn get_or_default(&self, address: &Address) -> Result<ContactRecord> {
        match self.tree.get(address.as_bytes())? {
            Some(record) => Ok(record),
            None => Ok(ContactRecord {
                alias: None,
                blocked: false,
            }),
        }
    }
}