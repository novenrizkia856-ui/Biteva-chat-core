//! Wallet file persistence for the daemon.
//!
//! Uses the same JSON format as the GUI's `wallet_persistence` module
//! so wallet files are interchangeable between daemon and GUI.
//!
//! # File format (v1)
//!
//! ```json
//! {
//!   "version": 1,
//!   "public_key": "<hex 32 bytes>",
//!   "encrypted_private_key": "<hex variable>",
//!   "salt": "<hex 32 bytes>",
//!   "nonce": "<hex 24 bytes>"
//! }
//! ```
//!
//! No plaintext secret material is written to disk.

use std::path::Path;

use bitevachat_crypto::kdf::Argon2Params;
use bitevachat_wallet::wallet::Wallet;
use serde::{Deserialize, Serialize};

const CURRENT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct WalletFileData {
    version: u32,
    public_key: String,
    encrypted_private_key: String,
    salt: String,
    nonce: String,
}

/// Saves a wallet to a JSON file (GUI-compatible format).
pub fn save_wallet(path: &Path, wallet: &Wallet) -> Result<(), String> {
    let data = WalletFileData {
        version: CURRENT_VERSION,
        public_key: hex::encode(wallet.public_key()),
        encrypted_private_key: hex::encode(wallet.encrypted_private_key()),
        salt: hex::encode(wallet.salt()),
        nonce: hex::encode(wallet.nonce()),
    };

    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;

    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json.as_bytes())
        .map_err(|e| format!("failed to write wallet file: {e}"))?;

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("failed to rename wallet file: {e}")
    })?;

    tracing::info!(path = %path.display(), "wallet saved");
    Ok(())
}

/// Loads a wallet from a JSON file (GUI-compatible format).
///
/// Returns a **locked** wallet. Call `wallet.unlock(passphrase)`
/// after loading.
pub fn load_wallet(path: &Path) -> Result<Wallet, String> {
    if !path.exists() {
        return Err(format!("wallet file not found: {}", path.display()));
    }

    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read wallet file: {e}"))?;

    let data: WalletFileData = serde_json::from_str(&json)
        .map_err(|e| format!("failed to parse wallet file: {e}"))?;

    if data.version != CURRENT_VERSION {
        return Err(format!(
            "unsupported wallet version {} (expected {CURRENT_VERSION})",
            data.version,
        ));
    }

    let public_key = hex_decode_fixed::<32>(&data.public_key, "public_key")?;
    let encrypted_private_key = hex::decode(&data.encrypted_private_key)
        .map_err(|e| format!("invalid encrypted_private_key hex: {e}"))?;
    let salt = hex_decode_fixed::<32>(&data.salt, "salt")?;
    let nonce = hex_decode_fixed::<24>(&data.nonce, "nonce")?;

    let params = Argon2Params::default();

    Ok(Wallet::from_parts(
        public_key,
        encrypted_private_key,
        salt,
        nonce,
        params,
    ))
}

fn hex_decode_fixed<const N: usize>(hex_str: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("invalid {field} hex: {e}"))?;
    if bytes.len() != N {
        return Err(format!("{field} must be {N} bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}