//! Generic encrypted sled tree wrapper.
//!
//! [`EncryptedTree<T>`] transparently encrypts values on write and
//! decrypts on read. Every stored value follows the Encrypt-then-MAC
//! pattern:
//!
//! ```text
//! [nonce 24B] [ciphertext variable] [hmac 32B]
//! ```
//!
//! On read, the HMAC is verified **before** any decryption attempt.

use bitevachat_crypto::aead::{
    decrypt_xchacha20, encrypt_xchacha20, generate_aead_nonce, AeadNonce,
};
use bitevachat_crypto::mac::{hmac_sha256, verify_hmac_sha256};
use bitevachat_types::{BitevachatError, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::engine::DerivedKeys;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the XChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 24;

/// Size of the HMAC-SHA256 tag.
const HMAC_LEN: usize = 32;

/// Minimum stored value size: nonce + AEAD tag (16) + HMAC.
const MIN_VALUE_LEN: usize = NONCE_LEN + 16 + HMAC_LEN;

// ---------------------------------------------------------------------------
// EncryptedTree
// ---------------------------------------------------------------------------

/// A sled tree where every value is encrypted and HMAC-authenticated.
///
/// `T` must implement `Serialize` and `DeserializeOwned` for bincode
/// serialization.
pub struct EncryptedTree<'a, T> {
    tree: sled::Tree,
    keys: &'a DerivedKeys,
    _marker: std::marker::PhantomData<T>,
}

impl<'a, T> EncryptedTree<'a, T>
where
    T: Serialize + DeserializeOwned,
{
    /// Creates a new `EncryptedTree` wrapping the given sled tree.
    pub(crate) fn new(tree: sled::Tree, keys: &'a DerivedKeys) -> Self {
        Self {
            tree,
            keys,
            _marker: std::marker::PhantomData,
        }
    }

    /// Retrieves and decrypts a value by key.
    ///
    /// Returns `Ok(None)` if the key does not exist.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::StorageError`] if the stored value is
    ///   malformed, HMAC verification fails, or decryption fails.
    pub fn get(&self, key: &[u8]) -> Result<Option<T>> {
        let raw = self.tree.get(key).map_err(|e| BitevachatError::StorageError {
            reason: format!("sled get failed: {e}"),
        })?;

        match raw {
            None => Ok(None),
            Some(bytes) => {
                let value = self.decrypt_value(&bytes)?;
                Ok(Some(value))
            }
        }
    }

    /// Serializes, encrypts, and inserts a value.
    ///
    /// A fresh 24-byte nonce is generated for each write.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::StorageError`] if serialization or the
    ///   sled insert fails.
    /// - [`BitevachatError::CryptoError`] if encryption fails.
    pub fn insert(&self, key: &[u8], value: &T) -> Result<()> {
        let encrypted = self.encrypt_value(value)?;

        self.tree
            .insert(key, encrypted)
            .map_err(|e| BitevachatError::StorageError {
                reason: format!("sled insert failed: {e}"),
            })?;

        Ok(())
    }

    /// Removes a key from the tree.
    ///
    /// Returns `Ok(true)` if the key existed, `Ok(false)` if it did not.
    pub fn delete(&self, key: &[u8]) -> Result<bool> {
        let prev = self.tree.remove(key).map_err(|e| BitevachatError::StorageError {
            reason: format!("sled remove failed: {e}"),
        })?;
        Ok(prev.is_some())
    }

    /// Iterates all entries, decrypting each value.
    ///
    /// Returns a `Vec` of `(key_bytes, value)` pairs. If any entry
    /// fails HMAC verification or decryption, an error is returned.
    pub fn iter(&self) -> Result<Vec<(Vec<u8>, T)>> {
        let mut results = Vec::new();
        for item in self.tree.iter() {
            let (key, value) = item.map_err(|e| BitevachatError::StorageError {
                reason: format!("sled iter failed: {e}"),
            })?;
            let decrypted = self.decrypt_value(&value)?;
            results.push((key.to_vec(), decrypted));
        }
        Ok(results)
    }

    /// Iterates entries by key prefix, decrypting each value.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, T)>> {
        let mut results = Vec::new();
        for item in self.tree.scan_prefix(prefix) {
            let (key, value) = item.map_err(|e| BitevachatError::StorageError {
                reason: format!("sled scan_prefix failed: {e}"),
            })?;
            let decrypted = self.decrypt_value(&value)?;
            results.push((key.to_vec(), decrypted));
        }
        Ok(results)
    }

    /// Returns raw key bytes for entries matching a prefix, without
    /// decrypting values.
    pub fn keys_by_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        for item in self.tree.scan_prefix(prefix) {
            let (key, _) = item.map_err(|e| BitevachatError::StorageError {
                reason: format!("sled scan_prefix failed: {e}"),
            })?;
            keys.push(key.to_vec());
        }
        Ok(keys)
    }

    // -- Internal --------------------------------------------------------

    /// Encrypts a value: serialize → encrypt → HMAC → pack.
    ///
    /// Output format: `[nonce 24B] [ciphertext variable] [hmac 32B]`
    fn encrypt_value(&self, value: &T) -> Result<Vec<u8>> {
        // 1. Serialize with bincode.
        let plaintext =
            bincode::serialize(value).map_err(|e| BitevachatError::StorageError {
                reason: format!("bincode serialization failed: {e}"),
            })?;

        // 2. Generate fresh nonce.
        let nonce = generate_aead_nonce();

        // 3. Encrypt with XChaCha20-Poly1305.
        let encrypted = encrypt_xchacha20(
            &self.keys.enc_key,
            &nonce,
            &plaintext,
            &[], // AAD empty — identity binding is in HMAC context
        )?;

        // 4. Compute HMAC-SHA256 over nonce || ciphertext.
        let mut hmac_input = Vec::with_capacity(NONCE_LEN + encrypted.ciphertext.len());
        hmac_input.extend_from_slice(nonce.as_bytes());
        hmac_input.extend_from_slice(&encrypted.ciphertext);
        let hmac_tag = hmac_sha256(&self.keys.hmac_key, &hmac_input)?;

        // 5. Pack: nonce || ciphertext || hmac.
        let mut output = Vec::with_capacity(NONCE_LEN + encrypted.ciphertext.len() + HMAC_LEN);
        output.extend_from_slice(nonce.as_bytes());
        output.extend_from_slice(&encrypted.ciphertext);
        output.extend_from_slice(&hmac_tag);

        Ok(output)
    }

    /// Decrypts a value: unpack → HMAC verify → decrypt → deserialize.
    fn decrypt_value(&self, raw: &[u8]) -> Result<T> {
        // Validate minimum length.
        if raw.len() < MIN_VALUE_LEN {
            return Err(BitevachatError::StorageError {
                reason: format!(
                    "stored value too short: expected at least {MIN_VALUE_LEN} bytes, got {}",
                    raw.len()
                ),
            });
        }

        // 1. Parse nonce (first 24 bytes).
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&raw[..NONCE_LEN]);
        let nonce = AeadNonce::from_bytes(nonce_bytes);

        // 2. Parse HMAC tag (last 32 bytes).
        let hmac_start = raw.len() - HMAC_LEN;
        let mut hmac_expected = [0u8; HMAC_LEN];
        hmac_expected.copy_from_slice(&raw[hmac_start..]);

        // 3. Parse ciphertext (between nonce and HMAC).
        let ciphertext = &raw[NONCE_LEN..hmac_start];

        // 4. Verify HMAC **before** decryption.
        let mut hmac_input = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        hmac_input.extend_from_slice(&nonce_bytes);
        hmac_input.extend_from_slice(ciphertext);

        verify_hmac_sha256(&self.keys.hmac_key, &hmac_input, &hmac_expected).map_err(|_| {
            BitevachatError::StorageError {
                reason: "HMAC verification failed: stored value may be tampered".into(),
            }
        })?;

        // 5. Decrypt.
        let plaintext = decrypt_xchacha20(&self.keys.enc_key, &nonce, ciphertext, &[])?;

        // 6. Deserialize.
        bincode::deserialize(&plaintext).map_err(|e| BitevachatError::StorageError {
            reason: format!("bincode deserialization failed: {e}"),
        })
    }
}