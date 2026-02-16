//! Encrypted profile and avatar storage.
//!
//! [`ProfileStore`] persists [`SignedProfile`] data per address.
//! [`AvatarStore`] persists raw avatar blobs keyed by [`Cid`].
//!
//! All data is encrypted at rest via [`EncryptedTree`].
//!
//! # CID validation
//!
//! On both store and retrieve, the avatar CID is validated against
//! the SHA3-256 hash of the blob. A mismatch on store is rejected;
//! a mismatch on retrieve indicates storage corruption and returns
//! an error.

use bitevachat_crypto::hash::sha3_256;
use bitevachat_protocol::cid::Cid;
use bitevachat_protocol::profiles::SignedProfile;
use bitevachat_types::{Address, BitevachatError, Result};

use crate::encrypted_tree::EncryptedTree;
use crate::engine::StorageEngine;

/// Maximum avatar blob size (1 MiB).
const MAX_AVATAR_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// ProfileStore
// ---------------------------------------------------------------------------

/// Encrypted per-address profile store.
pub struct ProfileStore<'a> {
    tree: EncryptedTree<'a, SignedProfile>,
}

impl<'a> ProfileStore<'a> {
    /// Creates a new `ProfileStore`.
    ///
    /// Caller should add a `profiles()` accessor to `StorageEngine`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("profiles")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
        })
    }

    /// Saves a signed profile for an address.
    ///
    /// Overwrites any existing profile for this address.
    pub fn save_profile(
        &self,
        address: &Address,
        signed: &SignedProfile,
    ) -> Result<()> {
        self.tree.insert(address.as_bytes(), signed)
    }

    /// Retrieves the signed profile for an address.
    ///
    /// Returns `None` if no profile is stored.
    pub fn get_profile(
        &self,
        address: &Address,
    ) -> Result<Option<SignedProfile>> {
        self.tree.get(address.as_bytes())
    }

    /// Removes the profile for an address.
    ///
    /// Used when processing a [`ProfileRevocation`].
    pub fn remove_profile(&self, address: &Address) -> Result<()> {
        self.tree.delete(address.as_bytes())?;
        Ok(())
    }

    /// Lists all stored profiles.
    pub fn list_profiles(&self) -> Result<Vec<(Address, SignedProfile)>> {
        let entries = self.tree.iter()?;
        let mut profiles = Vec::new();
        for (key, signed) in entries {
            if key.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key);
                profiles.push((Address::new(bytes), signed));
            }
        }
        Ok(profiles)
    }
}

// ---------------------------------------------------------------------------
// AvatarStore
// ---------------------------------------------------------------------------

/// Encrypted avatar blob store keyed by CID.
pub struct AvatarStore<'a> {
    tree: EncryptedTree<'a, Vec<u8>>,
}

impl<'a> AvatarStore<'a> {
    /// Creates a new `AvatarStore`.
    ///
    /// Caller should add an `avatars()` accessor to `StorageEngine`.
    pub(crate) fn new(engine: &'a StorageEngine) -> Result<Self> {
        let sled_tree = engine.open_tree("avatars")?;
        Ok(Self {
            tree: EncryptedTree::new(sled_tree, engine.keys()),
        })
    }

    /// Saves an avatar blob.
    ///
    /// # Validation
    ///
    /// The CID must match `SHA3-256(bytes)`. If it does not, the
    /// operation is rejected with `ProtocolError`.
    ///
    /// The blob must not exceed [`MAX_AVATAR_SIZE`].
    ///
    /// # Errors
    ///
    /// - `ProtocolError` if CID does not match hash.
    /// - `ProtocolError` if blob exceeds size limit.
    /// - `StorageError` on database failure.
    pub fn save_avatar(&self, cid: &Cid, bytes: &[u8]) -> Result<()> {
        // Size check.
        if bytes.len() > MAX_AVATAR_SIZE {
            return Err(BitevachatError::ProtocolError {
                reason: format!(
                    "avatar size {} exceeds maximum {}",
                    bytes.len(),
                    MAX_AVATAR_SIZE,
                ),
            });
        }

        // CID validation.
        let computed = sha3_256(bytes);
        if !constant_time_eq(&computed, cid.as_bytes()) {
            return Err(BitevachatError::ProtocolError {
                reason: "avatar CID does not match SHA3-256 of blob".into(),
            });
        }

        self.tree.insert(cid.as_bytes(), &bytes.to_vec())
    }

    /// Retrieves an avatar blob by CID.
    ///
    /// After retrieval, the CID is re-validated against the blob
    /// hash. A mismatch indicates storage corruption.
    ///
    /// # Errors
    ///
    /// - `StorageError` if the hash does not match (corruption).
    /// - `StorageError` on database failure.
    pub fn get_avatar(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        let blob = self.tree.get(cid.as_bytes())?;

        if let Some(ref data) = blob {
            // Re-validate CID on retrieval.
            let computed = sha3_256(data);
            if !constant_time_eq(&computed, cid.as_bytes()) {
                return Err(BitevachatError::StorageError {
                    reason: "avatar blob hash does not match CID (storage corruption)".into(),
                });
            }
        }

        Ok(blob)
    }

    /// Removes an avatar blob by CID.
    pub fn remove_avatar(&self, cid: &Cid) -> Result<()> {
        self.tree.delete(cid.as_bytes())?;
        Ok(())
    }
}

/// Constant-time comparison of two 32-byte arrays.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}