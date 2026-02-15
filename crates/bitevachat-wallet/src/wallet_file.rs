//! Binary wallet file format: header validation, read, and write.
//!
//! # File layout
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//!   0       4   Magic bytes: b"BTVC"
//!   4       1   Version: 0x01
//!   5     100   Header body (bincode-serialized):
//!                 m_cost   : u32 (4B)
//!                 t_cost   : u32 (4B)
//!                 p_cost   : u32 (4B)
//!                 salt     : [u8; 32]
//!                 nonce    : [u8; 24]
//!                 public_key: [u8; 32]
//! 105     var   Encrypted payload (XChaCha20-Poly1305 ciphertext + tag)
//! ```
//!
//! Magic and version are verified **before** any deserialization to
//! prevent feeding malformed data to bincode.

use bitevachat_crypto::kdf::Argon2Params;
use bitevachat_types::{BitevachatError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a Bitevachat wallet file.
pub const WALLET_MAGIC: [u8; 4] = *b"BTVC";

/// Current wallet file format version.
pub const WALLET_FILE_VERSION: u8 = 1;

/// Bincode-serialized size of [`HeaderBody`]:
/// 3 × u32 (12) + [u8; 32] (32) + [u8; 24] (24) + [u8; 32] (32) = 100.
const HEADER_BODY_SIZE: usize = 12 + 32 + 24 + 32;

/// Total header size: magic (4) + version (1) + body (100) = 105.
const TOTAL_HEADER_SIZE: usize = 4 + 1 + HEADER_BODY_SIZE;

/// Minimum encrypted payload size in bytes.
///
/// An XChaCha20-Poly1305 ciphertext is at least 16 bytes (the tag
/// alone for an empty plaintext). A valid mnemonic produces at least
/// ~150 bytes of ciphertext. We use 32 as a generous lower bound to
/// catch obviously truncated files.
const MIN_PAYLOAD_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// WalletFileHeader
// ---------------------------------------------------------------------------

/// Parsed header of a Bitevachat wallet file.
///
/// Represents the validated, in-memory form of the file header. The
/// magic and version fields are constants and are verified during
/// [`read_wallet_file`] rather than stored in this struct.
pub struct WalletFileHeader {
    /// Argon2id parameters used for key derivation.
    pub argon2_params: Argon2Params,
    /// 32-byte random salt for Argon2id.
    pub salt: [u8; 32],
    /// 24-byte nonce for XChaCha20-Poly1305.
    pub nonce: [u8; 24],
    /// Ed25519 public key of the wallet owner.
    pub public_key: [u8; 32],
}

/// Internal bincode-serializable representation of the header body.
#[derive(Serialize, Deserialize)]
struct HeaderBody {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; 32],
    nonce: [u8; 24],
    public_key: [u8; 32],
}

impl From<&WalletFileHeader> for HeaderBody {
    fn from(h: &WalletFileHeader) -> Self {
        Self {
            m_cost: h.argon2_params.m_cost,
            t_cost: h.argon2_params.t_cost,
            p_cost: h.argon2_params.p_cost,
            salt: h.salt,
            nonce: h.nonce,
            public_key: h.public_key,
        }
    }
}

impl HeaderBody {
    /// Converts to the public [`WalletFileHeader`].
    fn into_header(self) -> WalletFileHeader {
        WalletFileHeader {
            argon2_params: Argon2Params {
                m_cost: self.m_cost,
                t_cost: self.t_cost,
                p_cost: self.p_cost,
            },
            salt: self.salt,
            nonce: self.nonce,
            public_key: self.public_key,
        }
    }
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Writes a wallet file to disk.
///
/// # File structure
///
/// 1. Magic bytes `b"BTVC"` (4 bytes).
/// 2. Version byte `0x01` (1 byte).
/// 3. Header body serialized via `bincode` (100 bytes).
/// 4. Encrypted payload (variable length).
///
/// # Errors
///
/// Returns [`BitevachatError::StorageError`] if the file cannot be
/// created or written.
pub fn write_wallet_file(
    path: &Path,
    header: &WalletFileHeader,
    encrypted_payload: &[u8],
) -> Result<()> {
    let body = HeaderBody::from(header);

    let body_bytes = bincode::serialize(&body).map_err(|e| {
        BitevachatError::StorageError {
            reason: format!("failed to serialize wallet header: {e}"),
        }
    })?;

    let mut data = Vec::with_capacity(TOTAL_HEADER_SIZE + encrypted_payload.len());
    data.extend_from_slice(&WALLET_MAGIC);
    data.push(WALLET_FILE_VERSION);
    data.extend_from_slice(&body_bytes);
    data.extend_from_slice(encrypted_payload);

    std::fs::write(path, &data).map_err(|e| BitevachatError::StorageError {
        reason: format!("failed to write wallet file: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// Reads and validates a wallet file from disk.
///
/// # Validation order
///
/// 1. File size ≥ minimum header + minimum payload.
/// 2. Magic bytes match `b"BTVC"`.
/// 3. Version byte matches current version (`0x01`).
/// 4. Header body deserialized via `bincode`.
/// 5. Payload length ≥ [`MIN_PAYLOAD_SIZE`].
///
/// # Returns
///
/// A tuple of the validated [`WalletFileHeader`] and the raw
/// encrypted payload bytes.
///
/// # Errors
///
/// - [`BitevachatError::StorageError`] for I/O failures, truncated
///   files, magic mismatch, version mismatch, or payload too small.
pub fn read_wallet_file(path: &Path) -> Result<(WalletFileHeader, Vec<u8>)> {
    let data = std::fs::read(path).map_err(|e| BitevachatError::StorageError {
        reason: format!("failed to read wallet file: {e}"),
    })?;

    // 1. Minimum size check (header + smallest valid payload).
    let min_file_size = TOTAL_HEADER_SIZE + MIN_PAYLOAD_SIZE;
    if data.len() < min_file_size {
        return Err(BitevachatError::StorageError {
            reason: format!(
                "wallet file truncated: expected at least {min_file_size} bytes, got {}",
                data.len()
            ),
        });
    }

    // 2. Magic bytes.
    let magic = &data[0..4];
    if magic != WALLET_MAGIC {
        return Err(BitevachatError::StorageError {
            reason: format!(
                "wallet file magic mismatch: expected {:?}, got {:?}",
                &WALLET_MAGIC, magic
            ),
        });
    }

    // 3. Version byte.
    let version = data[4];
    if version != WALLET_FILE_VERSION {
        return Err(BitevachatError::StorageError {
            reason: format!(
                "wallet file version mismatch: expected {WALLET_FILE_VERSION}, got {version}"
            ),
        });
    }

    // 4. Deserialize header body.
    let body_slice = &data[5..5 + HEADER_BODY_SIZE];
    let body: HeaderBody =
        bincode::deserialize(body_slice).map_err(|e| BitevachatError::StorageError {
            reason: format!("failed to deserialize wallet header body: {e}"),
        })?;

    // 5. Extract and validate payload.
    let payload = data[TOTAL_HEADER_SIZE..].to_vec();
    if payload.len() < MIN_PAYLOAD_SIZE {
        return Err(BitevachatError::StorageError {
            reason: format!(
                "encrypted payload too small: expected at least {MIN_PAYLOAD_SIZE} bytes, got {}",
                payload.len()
            ),
        });
    }

    Ok((body.into_header(), payload))
}