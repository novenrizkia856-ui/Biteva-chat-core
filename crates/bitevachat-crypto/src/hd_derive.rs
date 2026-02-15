//! SLIP-0010 Ed25519 hierarchical deterministic key derivation.
//!
//! Implements deterministic key derivation from a BIP39 seed using
//! the SLIP-0010 specification (Ed25519 curve). Only hardened
//! derivation is supported, as required by the SLIP-0010 Ed25519 spec.
//!
//! # Derivation path format
//!
//! Paths follow BIP-44 convention with hardened indices (denoted by `'`):
//!
//! ```text
//! m/44'/0'/0'/0'/0'
//! ```
//!
//! Non-hardened derivation is explicitly rejected because Ed25519 does
//! not support public-key-only child derivation (SLIP-0010 §3).
//!
//! Reference: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>

use bitevachat_types::{BitevachatError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::ecdh::{ed25519_to_x25519, X25519PublicKey, X25519StaticSecret};
use crate::mnemonic::Seed;
use crate::signing::Keypair;

/// HMAC-SHA512 type alias used throughout SLIP-0010.
type HmacSha512 = Hmac<Sha512>;

/// The hardened index offset (0x80000000) per BIP-32/SLIP-0010.
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// HMAC key for master key generation per SLIP-0010 §2.
const MASTER_HMAC_KEY: &[u8] = b"ed25519 seed";

// ---------------------------------------------------------------------------
// X25519Keypair
// ---------------------------------------------------------------------------

/// X25519 key pair derived from an Ed25519 keypair.
///
/// Contains both the static secret and the corresponding public key,
/// ready for Diffie-Hellman key agreement.
pub struct X25519Keypair {
    /// X25519 static secret (zeroized on drop by x25519-dalek).
    pub secret: X25519StaticSecret,
    /// X25519 public key.
    pub public: X25519PublicKey,
}

// X25519Keypair does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derives an Ed25519 keypair from a BIP39 seed using SLIP-0010.
///
/// # Parameters
///
/// - `seed` — 64-byte BIP39 seed (from [`crate::mnemonic::mnemonic_to_seed`]).
/// - `path` — BIP-32-style derivation path. Must start with `m/` and
///   contain only hardened indices (e.g., `m/44'/0'/0'/0'/0'`).
///
/// # Process (SLIP-0010 §2–§3)
///
/// 1. Master key: `HMAC-SHA512(key="ed25519 seed", data=seed)`.
///    - Left 32 bytes → master private key.
///    - Right 32 bytes → master chain code.
/// 2. For each hardened child index `i` in the path:
///    `HMAC-SHA512(key=chain_code, data=0x00 || private_key || ser32(i | 0x80000000))`.
///    - Left 32 bytes → child private key.
///    - Right 32 bytes → child chain code.
/// 3. Final private key is used as the Ed25519 seed → [`Keypair`].
///
/// # Errors
///
/// - [`BitevachatError::ConfigError`] if the path is malformed or
///   contains non-hardened indices.
/// - [`BitevachatError::CryptoError`] if HMAC computation fails.
pub fn derive_ed25519_keypair(seed: &Seed, path: &str) -> Result<Keypair> {
    let indices = parse_derivation_path(path)?;

    // Step 1: master key generation.
    let (mut key, mut chain_code) = master_key_from_seed(seed.as_bytes())?;

    // Step 2: child derivation (hardened only).
    for &index in &indices {
        let (child_key, child_chain) = derive_hardened_child(&key, &chain_code, index)?;
        key.zeroize();
        chain_code.zeroize();
        key = child_key;
        chain_code = child_chain;
    }

    // Step 3: construct Ed25519 keypair from derived key.
    let keypair = Keypair::from_seed(&key);

    key.zeroize();
    chain_code.zeroize();

    Ok(keypair)
}

/// Converts an Ed25519 keypair to an X25519 keypair for
/// Diffie-Hellman key agreement.
///
/// Uses the RFC 7748 / RFC 8032 compatible conversion:
/// `SHA-512(ed25519_seed)` → first 32 bytes (clamped) → X25519 secret.
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if the conversion fails.
pub fn derive_x25519_keypair(ed25519_keypair: &Keypair) -> Result<X25519Keypair> {
    let (secret, public) = ed25519_to_x25519(ed25519_keypair)?;
    Ok(X25519Keypair { secret, public })
}

// ---------------------------------------------------------------------------
// Internal: master key
// ---------------------------------------------------------------------------

/// Generates the master private key and chain code from a raw seed.
///
/// `I = HMAC-SHA512(key="ed25519 seed", data=seed)`
/// `IL = I[0..32]` = master key, `IR = I[32..64]` = chain code.
fn master_key_from_seed(seed: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let i = hmac_sha512(MASTER_HMAC_KEY, seed)?;

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);

    Ok((key, chain_code))
}

// ---------------------------------------------------------------------------
// Internal: child derivation
// ---------------------------------------------------------------------------

/// Derives a hardened child key from a parent key and chain code.
///
/// `I = HMAC-SHA512(key=chain_code, data=0x00 || parent_key || ser32(index | 0x80000000))`
/// `IL = I[0..32]` = child key, `IR = I[32..64]` = child chain code.
fn derive_hardened_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32])> {
    // data = 0x00 || parent_key (32 bytes) || index_be (4 bytes) = 37 bytes
    let mut data = [0u8; 37];
    data[0] = 0x00;
    data[1..33].copy_from_slice(parent_key);
    data[33..37].copy_from_slice(&(index | HARDENED_OFFSET).to_be_bytes());

    let i = hmac_sha512(parent_chain_code, &data)?;
    data.zeroize();

    let mut child_key = [0u8; 32];
    let mut child_chain = [0u8; 32];
    child_key.copy_from_slice(&i[..32]);
    child_chain.copy_from_slice(&i[32..]);

    Ok((child_key, child_chain))
}

// ---------------------------------------------------------------------------
// Internal: HMAC-SHA512
// ---------------------------------------------------------------------------

/// Computes HMAC-SHA512 and returns the 64-byte output.
fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("HMAC-SHA512 key init failed: {e}"),
        }
    })?;
    mac.update(data);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    Ok(output)
}

// ---------------------------------------------------------------------------
// Internal: path parsing
// ---------------------------------------------------------------------------

/// Parses a BIP-32-style derivation path into a vector of child indices.
///
/// Accepts paths of the form `m/44'/0'/0'/0'/0'`. Every component
/// **must** be hardened (suffixed with `'` or `h`). Returns raw indices
/// (without the hardened offset applied — that is added during
/// derivation).
///
/// # Errors
///
/// - [`BitevachatError::ConfigError`] if the path does not start with
///   `m/`, contains non-hardened indices, or has invalid numbers.
fn parse_derivation_path(path: &str) -> Result<Vec<u32>> {
    let trimmed = path.trim();

    if !trimmed.starts_with("m/") {
        return Err(BitevachatError::ConfigError {
            reason: format!(
                "derivation path must start with 'm/', got '{trimmed}'"
            ),
        });
    }

    let components = &trimmed[2..]; // skip "m/"

    if components.is_empty() {
        return Err(BitevachatError::ConfigError {
            reason: "derivation path must have at least one component".into(),
        });
    }

    let mut indices = Vec::new();

    for part in components.split('/') {
        let part = part.trim();

        if part.is_empty() {
            return Err(BitevachatError::ConfigError {
                reason: "empty component in derivation path".into(),
            });
        }

        // Must end with ' or h (hardened).
        let (num_str, is_hardened) = if part.ends_with('\'') {
            (&part[..part.len() - 1], true)
        } else if part.ends_with('h') {
            (&part[..part.len() - 1], true)
        } else {
            (part, false)
        };

        if !is_hardened {
            return Err(BitevachatError::ConfigError {
                reason: format!(
                    "SLIP-0010 Ed25519 requires hardened derivation only, \
                     got non-hardened index '{part}'"
                ),
            });
        }

        let index: u32 = num_str.parse().map_err(|e| BitevachatError::ConfigError {
            reason: format!("invalid index '{num_str}' in path: {e}"),
        })?;

        if index >= HARDENED_OFFSET {
            return Err(BitevachatError::ConfigError {
                reason: format!(
                    "index {index} exceeds maximum ({})",
                    HARDENED_OFFSET - 1
                ),
            });
        }

        indices.push(index);
    }

    Ok(indices)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Path parsing ---

    #[test]
    fn parse_valid_path() -> std::result::Result<(), BitevachatError> {
        let indices = parse_derivation_path("m/44'/0'/0'/0'/0'")?;
        assert_eq!(indices, vec![44, 0, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn parse_path_with_h_suffix() -> std::result::Result<(), BitevachatError> {
        let indices = parse_derivation_path("m/44h/0h/0h")?;
        assert_eq!(indices, vec![44, 0, 0]);
        Ok(())
    }

    #[test]
    fn parse_rejects_non_hardened() {
        let result = parse_derivation_path("m/44'/0'/0'/0/0'");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_no_prefix() {
        let result = parse_derivation_path("44'/0'/0'");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_empty_path() {
        let result = parse_derivation_path("m/");
        assert!(result.is_err());
    }

    // --- SLIP-0010 test vector 1 ---
    //
    // Seed (hex): 000102030405060708090a0b0c0d0e0f
    // From: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
    //
    // Chain m:
    //   private: 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
    //   chain:   90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb

    #[test]
    fn slip0010_master_key_vector1() -> std::result::Result<(), BitevachatError> {
        let seed = hex_to_32plus(
            "000102030405060708090a0b0c0d0e0f",
        );
        let (key, chain) = master_key_from_seed(&seed)?;

        assert_eq!(
            to_hex(&key),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            to_hex(&chain),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
        Ok(())
    }

    // Chain m/0':
    //   private: 68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3
    //   chain:   8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69
    #[test]
    fn slip0010_child_m0h_vector1() -> std::result::Result<(), BitevachatError> {
        let seed = hex_to_32plus(
            "000102030405060708090a0b0c0d0e0f",
        );
        let (master_key, master_chain) = master_key_from_seed(&seed)?;
        let (child_key, child_chain) = derive_hardened_child(&master_key, &master_chain, 0)?;

        assert_eq!(
            to_hex(&child_key),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            to_hex(&child_chain),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
        Ok(())
    }

    // --- SLIP-0010 test vector 2 ---
    //
    // Seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    //
    // Chain m:
    //   private: 171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012
    //   chain:   ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b

    #[test]
    fn slip0010_master_key_vector2() -> std::result::Result<(), BitevachatError> {
        let seed_hex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let seed = hex_to_bytes_vec(seed_hex);
        let (key, chain) = master_key_from_seed(&seed)?;

        assert_eq!(
            to_hex(&key),
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
        );
        assert_eq!(
            to_hex(&chain),
            "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"
        );
        Ok(())
    }

    // --- Derivation consistency ---

    #[test]
    fn derivation_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let seed = Seed::from_bytes([0x42; 64]);
        let kp1 = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/0'")?;
        let kp2 = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/0'")?;
        assert_eq!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
        Ok(())
    }

    #[test]
    fn different_paths_different_keys() -> std::result::Result<(), BitevachatError> {
        let seed = Seed::from_bytes([0x42; 64]);
        let kp1 = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/0'")?;
        let kp2 = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/1'")?;
        assert_ne!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
        Ok(())
    }

    #[test]
    fn x25519_conversion_works() -> std::result::Result<(), BitevachatError> {
        let seed = Seed::from_bytes([0x42; 64]);
        let ed_kp = derive_ed25519_keypair(&seed, "m/44'/0'/0'/0'/0'")?;
        let x_kp = derive_x25519_keypair(&ed_kp)?;

        // Public key derived from secret should match.
        assert_eq!(
            x_kp.secret.public_key().as_bytes(),
            x_kp.public.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn x25519_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let seed = Seed::from_bytes([0x42; 64]);
        let ed1 = derive_ed25519_keypair(&seed, "m/44'/0'/0'")?;
        let ed2 = derive_ed25519_keypair(&seed, "m/44'/0'/0'")?;
        let x1 = derive_x25519_keypair(&ed1)?;
        let x2 = derive_x25519_keypair(&ed2)?;
        assert_eq!(x1.public.as_bytes(), x2.public.as_bytes());
        Ok(())
    }

    // --- Test utilities ---

    fn hex_to_32plus(hex: &str) -> Vec<u8> {
        hex_to_bytes_vec(hex)
    }

    fn hex_to_bytes_vec(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let mut i = 0;
        let chars: Vec<char> = hex.chars().collect();
        while i < chars.len() {
            let high = chars[i].to_digit(16).unwrap_or(0) as u8;
            let low = chars[i + 1].to_digit(16).unwrap_or(0) as u8;
            bytes.push((high << 4) | low);
            i += 2;
        }
        bytes
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}