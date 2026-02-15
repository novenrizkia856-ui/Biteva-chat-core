//! Encrypted file persistence for the pending message queue.
//!
//! The pending queue is stored as a single encrypted file (`pending.dat`).
//! All writes are atomic: serialize → encrypt → write tmp → fsync → rename.
//!
//! # File Format
//!
//! ```text
//! [nonce 24B][ciphertext (XChaCha20-Poly1305 of bincode-serialized Vec<PendingEntry>)]
//! ```
//!
//! The entire entry list is encrypted as a single blob. AEAD provides
//! both confidentiality and integrity — no separate HMAC is needed.
//!
//! # AAD
//!
//! Additional authenticated data: `b"btvc-pending-v1"`, binding the
//! ciphertext to this file format.

use std::fs;
use std::io::Write;
use std::path::Path;

use bitevachat_crypto::aead::{
    decrypt_xchacha20, encrypt_xchacha20, generate_aead_nonce, AeadNonce,
};
use bitevachat_types::{BitevachatError, Result};

use crate::pending::PendingEntry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Additional authenticated data for the pending file AEAD.
const PENDING_AAD: &[u8] = b"btvc-pending-v1";

/// Nonce length in bytes (XChaCha20-Poly1305).
const NONCE_LEN: usize = 24;

// ---------------------------------------------------------------------------
// PendingFile
// ---------------------------------------------------------------------------

/// Encrypted file I/O for `Vec<PendingEntry>`.
pub struct PendingFile;

impl PendingFile {
    /// Loads pending entries from an encrypted file.
    ///
    /// If the file does not exist, returns an empty `Vec`.
    /// If the file exists but cannot be decrypted or deserialized,
    /// returns an error.
    ///
    /// # Parameters
    ///
    /// - `path` — path to `pending.dat`.
    /// - `key` — 32-byte encryption key.
    pub fn load(path: &Path, key: &[u8; 32]) -> Result<Vec<PendingEntry>> {
        // If file does not exist → empty queue.
        if !path.exists() {
            return Ok(Vec::new());
        }

        let raw = fs::read(path).map_err(|e| BitevachatError::StorageError {
            reason: format!("failed to read pending file: {e}"),
        })?;

        // Empty file → empty queue (graceful handling).
        if raw.is_empty() {
            return Ok(Vec::new());
        }

        // Minimum: 24 bytes nonce + at least 1 byte ciphertext + 16 bytes tag.
        if raw.len() < NONCE_LEN + 17 {
            return Err(BitevachatError::StorageError {
                reason: format!(
                    "pending file too short: expected at least {} bytes, got {}",
                    NONCE_LEN + 17,
                    raw.len(),
                ),
            });
        }

        // Parse nonce (first 24 bytes).
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&raw[..NONCE_LEN]);
        let nonce = AeadNonce::from_bytes(nonce_bytes);

        // Ciphertext is everything after nonce.
        let ciphertext = &raw[NONCE_LEN..];

        // Decrypt.
        let plaintext = decrypt_xchacha20(key, &nonce, ciphertext, PENDING_AAD)?;

        // Deserialize.
        let entries: Vec<PendingEntry> =
            bincode::deserialize(&plaintext).map_err(|e| BitevachatError::StorageError {
                reason: format!("failed to deserialize pending entries: {e}"),
            })?;

        Ok(entries)
    }

    /// Saves pending entries to an encrypted file atomically.
    ///
    /// # Atomic Write Flow
    ///
    /// 1. Serialize entries via bincode.
    /// 2. Generate fresh AEAD nonce.
    /// 3. Encrypt with XChaCha20-Poly1305.
    /// 4. Write `[nonce || ciphertext]` to a temporary file.
    /// 5. `fsync` the temporary file.
    /// 6. Rename temporary file to `pending.dat`.
    ///
    /// If any step fails, the original file is untouched.
    ///
    /// # Parameters
    ///
    /// - `path` — path to `pending.dat`.
    /// - `key` — 32-byte encryption key.
    /// - `entries` — the entries to persist.
    pub fn save(path: &Path, key: &[u8; 32], entries: &[PendingEntry]) -> Result<()> {
        // 1. Serialize.
        let plaintext =
            bincode::serialize(entries).map_err(|e| BitevachatError::StorageError {
                reason: format!("failed to serialize pending entries: {e}"),
            })?;

        // 2. Generate fresh nonce.
        let nonce = generate_aead_nonce();

        // 3. Encrypt.
        let encrypted = encrypt_xchacha20(key, &nonce, &plaintext, PENDING_AAD)?;

        // 4. Build output: nonce || ciphertext.
        let mut output = Vec::with_capacity(NONCE_LEN + encrypted.ciphertext.len());
        output.extend_from_slice(nonce.as_bytes());
        output.extend_from_slice(&encrypted.ciphertext);

        // 5. Determine temporary file path (same directory).
        let tmp_path = Self::tmp_path(path)?;

        // 6. Write to temporary file + fsync.
        {
            let mut file =
                fs::File::create(&tmp_path).map_err(|e| BitevachatError::StorageError {
                    reason: format!("failed to create temp pending file: {e}"),
                })?;

            file.write_all(&output)
                .map_err(|e| BitevachatError::StorageError {
                    reason: format!("failed to write temp pending file: {e}"),
                })?;

            file.sync_all()
                .map_err(|e| BitevachatError::StorageError {
                    reason: format!("failed to fsync temp pending file: {e}"),
                })?;
        }

        // 7. Atomic rename.
        fs::rename(&tmp_path, path).map_err(|e| {
            // Best-effort cleanup of temp file.
            let _ = fs::remove_file(&tmp_path);
            BitevachatError::StorageError {
                reason: format!("failed to rename temp pending file: {e}"),
            }
        })?;

        Ok(())
    }

    /// Generates a temporary file path in the same directory as `path`.
    fn tmp_path(path: &Path) -> Result<std::path::PathBuf> {
        let parent = path.parent().ok_or_else(|| BitevachatError::StorageError {
            reason: "pending file path has no parent directory".into(),
        })?;

        // Ensure parent directory exists.
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| BitevachatError::StorageError {
                reason: format!("failed to create pending file directory: {e}"),
            })?;
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("pending.dat");

        Ok(parent.join(format!(".{}.tmp", file_name)))
    }
}