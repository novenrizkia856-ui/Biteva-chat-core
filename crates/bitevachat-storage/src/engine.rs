//! Core storage engine: database lifecycle, key management, and tree access.
//!
//! The [`StorageEngine`] owns the sled database and the encryption key.
//! On [`open`](StorageEngine::open) it validates the key length, opens
//! the database, and creates all required trees. The encryption key
//! is zeroized on drop.

use std::path::Path;

use bitevachat_crypto::hkdf::hkdf_sha256;
use bitevachat_types::{BitevachatError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::contacts::ContactStore;
use crate::conversations::ConversationIndex;
use crate::encrypted_tree::EncryptedTree;
use crate::messages::MessageStore;
use crate::settings::SettingsStore;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Required encryption key length in bytes.
const KEY_LEN: usize = 32;

/// HKDF salt for deriving sub-keys from the master key.
const HKDF_SALT: &[u8] = b"Bitevachat-Storage";

/// HKDF info for the encryption sub-key.
const HKDF_INFO_ENC: &[u8] = b"encryption";

/// HKDF info for the HMAC sub-key.
const HKDF_INFO_HMAC: &[u8] = b"hmac";

// ---------------------------------------------------------------------------
// DerivedKeys
// ---------------------------------------------------------------------------

/// Pair of domain-separated keys derived from the master key via HKDF.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DerivedKeys {
    /// 32-byte key for XChaCha20-Poly1305 encryption.
    pub enc_key: [u8; 32],
    /// 32-byte key for HMAC-SHA256 authentication.
    pub hmac_key: [u8; 32],
}

impl DerivedKeys {
    /// Derives encryption and HMAC keys from a master key using HKDF-SHA256.
    fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let enc_output = hkdf_sha256(master_key, HKDF_SALT, HKDF_INFO_ENC, 32)?;
        let hmac_output = hkdf_sha256(master_key, HKDF_SALT, HKDF_INFO_HMAC, 32)?;

        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(enc_output.as_bytes());

        let mut hmac_key = [0u8; 32];
        hmac_key.copy_from_slice(hmac_output.as_bytes());

        Ok(Self { enc_key, hmac_key })
    }
}

// ---------------------------------------------------------------------------
// StorageEngine
// ---------------------------------------------------------------------------

/// Encrypted storage engine backed by sled.
///
/// All values stored through this engine are encrypted with
/// XChaCha20-Poly1305 and authenticated with HMAC-SHA256 (Encrypt-
/// then-MAC). The encryption key is derived externally and passed
/// to [`open`](Self::open); the engine never generates keys itself.
///
/// # Trees
///
/// - `messages` — per-conversation message store
/// - `conversations` — conversation index
/// - `contacts` — address-to-alias and blocklist
/// - `settings` — key-value configuration
/// - `pins` — message pin/star index
pub struct StorageEngine {
    db: sled::Db,
    keys: DerivedKeys,
}

impl StorageEngine {
    /// Opens (or creates) the storage engine at `path`.
    ///
    /// # Parameters
    ///
    /// - `path` — directory for the sled database.
    /// - `encryption_key` — 32-byte master key. Must be derived
    ///   externally (e.g. from wallet passphrase via Argon2id).
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::ConfigError`] if `encryption_key` is not
    ///   exactly 32 bytes.
    /// - [`BitevachatError::StorageError`] if the database cannot be
    ///   opened.
    pub fn open(path: &Path, encryption_key: &[u8]) -> Result<Self> {
        // Validate key length.
        if encryption_key.len() != KEY_LEN {
            return Err(BitevachatError::ConfigError {
                reason: format!(
                    "encryption key must be {KEY_LEN} bytes, got {}",
                    encryption_key.len()
                ),
            });
        }

        let mut master = [0u8; 32];
        master.copy_from_slice(encryption_key);
        let keys = DerivedKeys::derive(&master)?;
        master.zeroize();

        // Open sled database.
        let db = sled::open(path).map_err(|e| BitevachatError::StorageError {
            reason: format!("failed to open sled database: {e}"),
        })?;

        // Pre-create all trees so they exist for later access.
        for name in &["messages", "conversations", "contacts", "settings", "pins"] {
            db.open_tree(name).map_err(|e| BitevachatError::StorageError {
                reason: format!("failed to open tree '{name}': {e}"),
            })?;
        }

        Ok(Self { db, keys })
    }

    /// Flushes all pending writes to disk.
    ///
    /// # Errors
    ///
    /// Returns [`BitevachatError::StorageError`] if the flush fails.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().map_err(|e| BitevachatError::StorageError {
            reason: format!("failed to flush database: {e}"),
        })?;
        Ok(())
    }

    /// Returns a reference to the derived keys (crate-internal).
    pub(crate) fn keys(&self) -> &DerivedKeys {
        &self.keys
    }

    /// Opens a named sled tree.
    pub(crate) fn open_tree(&self, name: &str) -> Result<sled::Tree> {
        self.db.open_tree(name).map_err(|e| BitevachatError::StorageError {
            reason: format!("failed to open tree '{name}': {e}"),
        })
    }

    /// Returns a [`MessageStore`] for this engine.
    pub fn messages(&self) -> Result<MessageStore<'_>> {
        MessageStore::new(self)
    }

    /// Returns a [`ConversationIndex`] for this engine.
    pub fn conversations(&self) -> Result<ConversationIndex<'_>> {
        ConversationIndex::new(self)
    }

    /// Returns a [`ContactStore`] for this engine.
    pub fn contacts(&self) -> Result<ContactStore<'_>> {
        ContactStore::new(self)
    }

    /// Returns a [`SettingsStore`] for this engine.
    pub fn settings(&self) -> Result<SettingsStore<'_>> {
        SettingsStore::new(self)
    }
}