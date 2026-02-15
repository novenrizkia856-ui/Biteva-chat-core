//! Encrypted key-value settings store.
//!
//! Stores application configuration as encrypted key-value pairs.
//! Default retention limit is 1500 messages per conversation.

use bitevachat_types::Result;
use serde::{Deserialize, Serialize};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default message retention limit per conversation.
pub const DEFAULT_RETENTION_LIMIT: u64 = 1500;

/// Key used to store the retention limit setting.
const KEY_RETENTION_LIMIT: &[u8] = b"retention_limit";

// ---------------------------------------------------------------------------
// SettingValue
// ---------------------------------------------------------------------------

/// Wrapper for a stored setting value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettingValue {
    /// The setting value as a string.
    pub value: String,
}

// ---------------------------------------------------------------------------
// SettingsStore
// ---------------------------------------------------------------------------

/// Encrypted key-value settings store.
pub struct SettingsStore<'a> {
    tree: EncryptedTree<'a, SettingValue>,
}

impl<'a> SettingsStore<'a> {
    /// Creates a new `SettingsStore`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("settings")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
        })
    }

    /// Sets a string setting.
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.tree.insert(
            key.as_bytes(),
            &SettingValue {
                value: value.to_string(),
            },
        )
    }

    /// Gets a string setting.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        match self.tree.get(key.as_bytes())? {
            Some(sv) => Ok(Some(sv.value)),
            None => Ok(None),
        }
    }

    /// Removes a setting.
    pub fn remove(&self, key: &str) -> Result<bool> {
        self.tree.delete(key.as_bytes())
    }

    /// Returns the configured retention limit, or the default (1500).
    pub fn retention_limit(&self) -> Result<u64> {
        match self.get("retention_limit")? {
            Some(s) => s.parse::<u64>().map_err(|e| {
                bitevachat_types::BitevachatError::ConfigError {
                    reason: format!("invalid retention_limit setting: {e}"),
                }
            }),
            None => Ok(DEFAULT_RETENTION_LIMIT),
        }
    }

    /// Sets the retention limit.
    pub fn set_retention_limit(&self, limit: u64) -> Result<()> {
        self.set(
            std::str::from_utf8(KEY_RETENTION_LIMIT).map_err(|_| {
                bitevachat_types::BitevachatError::ConfigError {
                    reason: "retention_limit key is not valid UTF-8".into(),
                }
            })?,
            &limit.to_string(),
        )
    }
}