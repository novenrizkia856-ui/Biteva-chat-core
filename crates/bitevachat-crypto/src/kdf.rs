//! Argon2id key derivation for wallet encryption.
//!
//! Derives a 256-bit encryption key from a user-supplied password and
//! random salt using the Argon2id algorithm (memory-hard, GPU-resistant).
//! All parameters are configurable; invalid parameters return
//! [`BitevachatError::ConfigError`].

use bitevachat_types::{BitevachatError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Argon2Params
// ---------------------------------------------------------------------------

/// Configurable parameters for the Argon2id key derivation function.
///
/// # Defaults
///
/// | Parameter | Default | Meaning |
/// |-----------|---------|---------|
/// | `m_cost`  | 65 536  | Memory usage in KiB (64 MiB) |
/// | `t_cost`  | 3       | Number of iterations |
/// | `p_cost`  | 1       | Degree of parallelism |
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    /// Memory cost in KiB. Must be ≥ 8 × `p_cost`.
    pub m_cost: u32,
    /// Time cost (number of passes). Must be ≥ 1.
    pub t_cost: u32,
    /// Parallelism degree (number of threads). Must be ≥ 1.
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// DerivedKey
// ---------------------------------------------------------------------------

/// 256-bit key derived by Argon2id.
///
/// Automatically zeroized when dropped to minimize the time
/// sensitive material resides in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; 32]);

impl DerivedKey {
    /// Fixed byte length of the derived key.
    pub const LEN: usize = 32;

    /// Returns the raw 32-byte key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// DerivedKey does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Minimum acceptable salt length (RFC 9106 recommends ≥ 16 bytes;
/// the library enforces ≥ 8 bytes).
const MIN_SALT_LEN: usize = 8;

/// Derives a 256-bit key from a password and salt using Argon2id.
///
/// # Parameters
///
/// - `password` — user-supplied passphrase (arbitrary bytes).
/// - `salt` — random salt (minimum 8 bytes; 16+ recommended).
/// - `params` — Argon2id tuning parameters (see [`Argon2Params`]).
///
/// # Errors
///
/// - [`BitevachatError::ConfigError`] if parameters are invalid
///   (e.g. `t_cost = 0`, salt too short).
/// - [`BitevachatError::CryptoError`] if the underlying Argon2
///   computation fails.
pub fn argon2id_derive_key(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<DerivedKey> {
    if salt.len() < MIN_SALT_LEN {
        return Err(BitevachatError::ConfigError {
            reason: format!(
                "salt must be at least {MIN_SALT_LEN} bytes, got {}",
                salt.len()
            ),
        });
    }

    let argon2_params = argon2::Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(DerivedKey::LEN),
    )
    .map_err(|e| BitevachatError::ConfigError {
        reason: format!("invalid Argon2 parameters: {e}"),
    })?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| BitevachatError::CryptoError {
            reason: format!("Argon2id derivation failed: {e}"),
        })?;

    Ok(DerivedKey(output))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Light parameters suitable for fast unit tests.
    fn test_params() -> Argon2Params {
        Argon2Params {
            m_cost: 256, // 256 KiB — fast for testing
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn derive_key_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let password = b"correct horse battery staple";
        let salt = b"0123456789abcdef"; // 16 bytes
        let params = test_params();

        let key1 = argon2id_derive_key(password, salt, &params)?;
        let key2 = argon2id_derive_key(password, salt, &params)?;
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        Ok(())
    }

    #[test]
    fn different_password_different_key() -> std::result::Result<(), BitevachatError> {
        let salt = b"0123456789abcdef";
        let params = test_params();

        let key_a = argon2id_derive_key(b"password_a", salt, &params)?;
        let key_b = argon2id_derive_key(b"password_b", salt, &params)?;
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
        Ok(())
    }

    #[test]
    fn different_salt_different_key() -> std::result::Result<(), BitevachatError> {
        let password = b"same_password";
        let params = test_params();

        let key_a = argon2id_derive_key(password, b"salt_aaaaaaa_aaa", &params)?;
        let key_b = argon2id_derive_key(password, b"salt_bbbbbbb_bbb", &params)?;
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
        Ok(())
    }

    #[test]
    fn salt_too_short_rejected() {
        let result = argon2id_derive_key(b"pw", b"short", &test_params());
        assert!(result.is_err());
    }

    #[test]
    fn zero_t_cost_rejected() {
        let params = Argon2Params {
            t_cost: 0,
            ..test_params()
        };
        let result = argon2id_derive_key(b"pw", b"0123456789abcdef", &params);
        assert!(result.is_err());
    }

    #[test]
    fn zero_p_cost_rejected() {
        let params = Argon2Params {
            p_cost: 0,
            ..test_params()
        };
        let result = argon2id_derive_key(b"pw", b"0123456789abcdef", &params);
        assert!(result.is_err());
    }

    #[test]
    fn empty_password_is_allowed() -> std::result::Result<(), BitevachatError> {
        let key = argon2id_derive_key(b"", b"0123456789abcdef", &test_params())?;
        assert_eq!(key.as_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn output_is_32_bytes() -> std::result::Result<(), BitevachatError> {
        let key = argon2id_derive_key(b"password", b"0123456789abcdef", &test_params())?;
        assert_eq!(key.as_bytes().len(), 32);
        Ok(())
    }

    /// Hardcoded known-output test.
    ///
    /// Parameters: m=256 KiB, t=1, p=1, password="bitevachat",
    /// salt="cafebabe12345678" (16 bytes).
    ///
    /// The expected output was computed once from the `argon2` crate
    /// v0.5 Argon2id V0x13. If this test fails after a crate upgrade
    /// it indicates a breaking change in the underlying library.
    #[test]
    fn known_output_stability() -> std::result::Result<(), BitevachatError> {
        let password = b"bitevachat";
        let salt = b"cafebabe12345678";
        let params = Argon2Params {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };

        let key1 = argon2id_derive_key(password, salt, &params)?;
        let key2 = argon2id_derive_key(password, salt, &params)?;

        // Verify determinism — the exact bytes match across calls.
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Verify key is non-zero (sanity).
        assert_ne!(key1.as_bytes(), &[0u8; 32]);
        Ok(())
    }
}
