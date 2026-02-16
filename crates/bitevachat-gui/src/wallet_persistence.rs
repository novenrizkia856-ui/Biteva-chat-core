//! Wallet file persistence.
//!
//! Saves and loads wallet data as JSON using the `Wallet` accessors
//! and `Wallet::from_parts` constructor. Argon2id parameters are
//! stored as `default` because `Wallet::create_wallet` always uses
//! the default tuning.
//!
//! When the official `bitevachat-wallet::wallet_file` module is
//! ready, this module should be replaced with that.

use std::path::Path;

use bitevachat_crypto::kdf::Argon2Params;
use bitevachat_wallet::wallet::Wallet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// File format (JSON)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WalletFileData {
    /// Format version.
    version: u32,
    /// 32-byte Ed25519 public key, hex encoded.
    public_key: String,
    /// XChaCha20-Poly1305 ciphertext of BIP39 mnemonic, hex encoded.
    encrypted_private_key: String,
    /// 32-byte Argon2id salt, hex encoded.
    salt: String,
    /// 24-byte AEAD nonce, hex encoded.
    nonce: String,
}

const CURRENT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Saves a wallet to a JSON file.
///
/// The file contains the public key, encrypted mnemonic, salt, and
/// nonce. No plaintext secret material is written.
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

    // Write atomically: write to tmp, then rename.
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json.as_bytes())
        .map_err(|e| format!("failed to write wallet file: {e}"))?;

    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("failed to rename wallet file: {e}"))?;

    Ok(())
}

/// Loads a wallet from a JSON file.
///
/// Returns a **locked** wallet. Call `wallet.unlock(passphrase)` to
/// decrypt the keypair.
pub fn load_wallet(path: &Path) -> Result<Wallet, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read wallet file: {e}"))?;

    let data: WalletFileData = serde_json::from_str(&contents)
        .map_err(|e| format!("failed to parse wallet file: {e}"))?;

    if data.version != CURRENT_VERSION {
        return Err(format!(
            "unsupported wallet file version {} (expected {CURRENT_VERSION})",
            data.version,
        ));
    }

    let public_key = hex_decode_fixed::<32>(&data.public_key, "public_key")?;
    let encrypted_private_key = hex::decode(&data.encrypted_private_key)
        .map_err(|e| format!("invalid encrypted_private_key hex: {e}"))?;
    let salt = hex_decode_fixed::<32>(&data.salt, "salt")?;
    let nonce = hex_decode_fixed::<24>(&data.nonce, "nonce")?;

    // Use default Argon2 params — matches Wallet::create_wallet().
    let params = Argon2Params::default();

    Ok(Wallet::from_parts(
        public_key,
        encrypted_private_key,
        salt,
        nonce,
        params,
    ))
}

/// Returns `true` if a wallet file exists at the given path.
pub fn wallet_exists(path: &Path) -> bool {
    path.is_file()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_decode_fixed<const N: usize>(hex_str: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("invalid {field} hex: {e}"))?;

    if bytes.len() != N {
        return Err(format!(
            "{field} must be {N} bytes, got {}",
            bytes.len(),
        ));
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}