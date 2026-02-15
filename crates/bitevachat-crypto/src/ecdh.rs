//! X25519 Elliptic-Curve Diffie-Hellman key agreement.
//!
//! Provides ephemeral and static key agreement for deriving shared
//! secrets, plus conversion from Ed25519 keypairs to X25519 keypairs
//! (RFC 7748 compatible).

use bitevachat_types::{BitevachatError, Result};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::signing::Keypair;

// ---------------------------------------------------------------------------
// X25519PublicKey
// ---------------------------------------------------------------------------

/// X25519 public key (32 bytes) for Diffie-Hellman key agreement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519PublicKey(x25519_dalek::PublicKey);

impl X25519PublicKey {
    /// Creates an [`X25519PublicKey`] from raw 32-byte Montgomery-form
    /// representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(bytes))
    }

    /// Returns the raw 32-byte representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// X25519StaticSecret
// ---------------------------------------------------------------------------

/// Long-lived X25519 secret key.
///
/// Used for the Ed25519-to-X25519 conversion path. The underlying
/// `x25519-dalek` [`StaticSecret`](x25519_dalek::StaticSecret) zeroizes
/// its memory on drop.
pub struct X25519StaticSecret(x25519_dalek::StaticSecret);

impl X25519StaticSecret {
    /// Creates an [`X25519StaticSecret`] from raw 32-byte key material.
    ///
    /// Clamping is performed internally by `x25519-dalek` during scalar
    /// multiplication, so the raw bytes are stored as-is.
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(x25519_dalek::PublicKey::from(&self.0))
    }
}

// X25519StaticSecret does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// X25519EphemeralSecret
// ---------------------------------------------------------------------------

/// Single-use ephemeral X25519 secret key.
///
/// Intended for one-message forward secrecy: generate per message,
/// perform ECDH, then discard. Consumed on use.
pub struct X25519EphemeralSecret {
    /// Stored as [`StaticSecret`](x25519_dalek::StaticSecret) because
    /// `x25519_dalek::EphemeralSecret` is consumed on `diffie_hellman`
    /// and we need to extract the public key *before* performing ECDH.
    inner: x25519_dalek::StaticSecret,
}

impl X25519EphemeralSecret {
    /// Generates a fresh ephemeral secret from OS entropy.
    pub fn generate() -> Self {
        let inner = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        Self { inner }
    }

    /// Returns the public key corresponding to this ephemeral secret.
    ///
    /// The caller must send this public key to the recipient so they
    /// can derive the same shared secret.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(x25519_dalek::PublicKey::from(&self.inner))
    }
}

// X25519EphemeralSecret does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// SharedSecret
// ---------------------------------------------------------------------------

/// Shared secret derived from an X25519 Diffie-Hellman exchange (32 bytes).
///
/// Automatically zeroized on drop. Should be passed to an HKDF or
/// directly used as keying material for AEAD.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Returns the raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// SharedSecret does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// ECDH functions
// ---------------------------------------------------------------------------

/// Performs X25519 ECDH with a static (long-lived) secret key.
///
/// Computes the shared secret between `our_secret` and `their_public`.
/// Both parties performing this operation with the other's public key
/// derive the identical shared secret.
pub fn ecdh_derive_shared(
    our_secret: &X25519StaticSecret,
    their_public: &X25519PublicKey,
) -> SharedSecret {
    let raw = our_secret.0.diffie_hellman(&their_public.0);
    SharedSecret(*raw.as_bytes())
}

/// Performs X25519 ECDH with an ephemeral (single-use) secret key.
///
/// The ephemeral secret is consumed and cannot be reused.
pub fn ecdh_derive_shared_ephemeral(
    our_secret: X25519EphemeralSecret,
    their_public: &X25519PublicKey,
) -> SharedSecret {
    let raw = our_secret.inner.diffie_hellman(&their_public.0);
    SharedSecret(*raw.as_bytes())
}

// ---------------------------------------------------------------------------
// Ed25519 → X25519 conversion
// ---------------------------------------------------------------------------

/// Converts an Ed25519 signing keypair to an X25519 static secret and
/// public key pair.
///
/// Process (RFC 7748 / RFC 8032 compatible):
/// 1. `SHA-512(ed25519_seed)` → 64 bytes
/// 2. Take lower 32 bytes → X25519 secret (clamping done internally by
///    `x25519-dalek`)
/// 3. Derive X25519 public key from the secret
///
/// Intermediate values are zeroized before returning.
pub fn ed25519_to_x25519(
    keypair: &Keypair,
) -> Result<(X25519StaticSecret, X25519PublicKey)> {
    let mut seed = keypair.signing_key.to_bytes();
    let hash_output = Sha512::digest(&seed);
    seed.zeroize();

    let mut hash_bytes = [0u8; 64];
    hash_bytes.copy_from_slice(&hash_output);

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&hash_bytes[..32]);
    hash_bytes.zeroize();

    let static_secret = x25519_dalek::StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();

    let public_key = x25519_dalek::PublicKey::from(&static_secret);

    Ok((
        X25519StaticSecret(static_secret),
        X25519PublicKey(public_key),
    ))
}

/// Converts an Ed25519 verifying (public) key to an X25519 public key
/// by deriving through the secret-key path.
///
/// This requires the full keypair because the Montgomery-form public
/// key is derived from the X25519 secret (which itself comes from the
/// Ed25519 seed). This ensures consistency: the returned X25519 public
/// key always matches the X25519 static secret from
/// [`ed25519_to_x25519`].
pub fn ed25519_pubkey_to_x25519(
    keypair: &Keypair,
) -> Result<X25519PublicKey> {
    let (_, pk) = ed25519_to_x25519(keypair)?;
    Ok(pk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_ecdh_shared_secret_matches() {
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public_a = x25519_dalek::PublicKey::from(&secret_a);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let a = X25519StaticSecret(secret_a);
        let b = X25519StaticSecret(secret_b);
        let pub_a = X25519PublicKey(public_a);
        let pub_b = X25519PublicKey(public_b);

        let shared_ab = ecdh_derive_shared(&a, &pub_b);
        let shared_ba = ecdh_derive_shared(&b, &pub_a);
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn ephemeral_ecdh_shared_secret_matches() {
        let static_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let static_pub = X25519PublicKey(x25519_dalek::PublicKey::from(&static_secret));
        let static_wrap = X25519StaticSecret(static_secret);

        let eph = X25519EphemeralSecret::generate();
        let eph_pub = eph.public_key();

        let shared_eph = ecdh_derive_shared_ephemeral(eph, &static_pub);
        let shared_static = ecdh_derive_shared(&static_wrap, &eph_pub);
        assert_eq!(shared_eph.as_bytes(), shared_static.as_bytes());
    }

    #[test]
    fn ed25519_to_x25519_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let seed = [0x55u8; 32];
        let kp = Keypair::from_seed(&seed);

        let (_, pub1) = ed25519_to_x25519(&kp)?;
        let (_, pub2) = ed25519_to_x25519(&kp)?;
        assert_eq!(pub1.as_bytes(), pub2.as_bytes());
        Ok(())
    }

    #[test]
    fn ed25519_to_x25519_secret_matches_public() -> std::result::Result<(), BitevachatError> {
        let kp = Keypair::generate();
        let (secret, public) = ed25519_to_x25519(&kp)?;
        let derived_public = secret.public_key();
        assert_eq!(public.as_bytes(), derived_public.as_bytes());
        Ok(())
    }

    #[test]
    fn different_keys_produce_different_shared_secrets() {
        let a = X25519EphemeralSecret::generate();
        let b = X25519EphemeralSecret::generate();
        let c = X25519EphemeralSecret::generate();
        let pub_c = c.public_key();

        let shared_ac = ecdh_derive_shared_ephemeral(a, &pub_c);
        let shared_bc = ecdh_derive_shared_ephemeral(b, &pub_c);
        assert_ne!(shared_ac.as_bytes(), shared_bc.as_bytes());
    }
}
