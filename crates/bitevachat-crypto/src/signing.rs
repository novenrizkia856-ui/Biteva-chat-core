//! Ed25519 digital signature operations.
//!
//! Provides keypair generation, message signing, signature verification,
//! and public-key-to-address derivation. The private key is automatically
//! zeroized on drop via `ed25519-dalek`'s built-in `ZeroizeOnDrop`.

use bitevachat_types::{Address, BitevachatError, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::hash::sha3_256;

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// Ed25519 public key (32 bytes).
///
/// Wrapper around the raw verifying key bytes. Used for signature
/// verification and address derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Fixed byte length of an Ed25519 public key.
    pub const LEN: usize = 32;

    /// Creates a [`PublicKey`] from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// Ed25519 signature (64 bytes).
///
/// Contains the raw signature bytes produced by [`Keypair::sign`] and
/// consumed by [`verify`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; 64]);

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("64 bytes for Ed25519 signature")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> std::result::Result<Signature, E> {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &"64"));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(Signature(arr))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Signature, A::Error> {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"64"))?;
                }
                Ok(Signature(arr))
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}

impl Signature {
    /// Fixed byte length of an Ed25519 signature.
    pub const LEN: usize = 64;

    /// Creates a [`Signature`] from raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 64-byte array.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

/// Ed25519 signing keypair.
///
/// Wraps an `ed25519-dalek` [`SigningKey`]. The private key is
/// automatically zeroized when this struct is dropped, courtesy of
/// `ed25519-dalek`'s `ZeroizeOnDrop` implementation.
pub struct Keypair {
    /// Internal signing key. `pub(crate)` so [`crate::ecdh`] can convert
    /// to X25519 without exposing the seed to external callers.
    pub(crate) signing_key: SigningKey,
}

impl Keypair {
    /// Generates a new random keypair using OS-level entropy.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstructs a keypair deterministically from a 32-byte seed.
    ///
    /// Given the same seed, this always produces the same keypair.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Returns the public half of this keypair.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key().to_bytes())
    }

    /// Signs an arbitrary message and returns the Ed25519 signature.
    ///
    /// The signature covers the entire `message` byte slice.
    /// Deterministic: the same keypair + message always yields the
    /// same signature (Ed25519 is deterministic per RFC 8032).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature(sig.to_bytes())
    }

    // ------------------------------------------------------------------
    // ADDED FOR TAHAP 9 — libp2p identity conversion
    // ------------------------------------------------------------------

    /// Returns the 32-byte seed (secret scalar) of this keypair.
    ///
    /// This is the minimal secret material needed to reconstruct the
    /// full Ed25519 keypair deterministically. Used by the network
    /// layer to convert a wallet identity into a libp2p peer identity.
    ///
    /// # Security
    ///
    /// The returned bytes are sensitive key material. Callers **must**
    /// zeroize or discard the copy as soon as it is no longer needed.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the full 64-byte keypair encoding (seed ‖ public key).
    ///
    /// Format: 32-byte secret scalar followed by 32-byte compressed
    /// public point. This matches the `ed25519-dalek` canonical
    /// encoding and is accepted by `libp2p::identity::ed25519::Keypair::try_from_bytes`.
    ///
    /// # Security
    ///
    /// The returned bytes contain the private key. Callers **must**
    /// zeroize or discard the copy as soon as it is no longer needed.
    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        self.signing_key.to_keypair_bytes()
    }
}

// Keypair intentionally does not implement Clone or Debug to prevent
// accidental leakage of the private key in logs or copies.

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Verifies an Ed25519 signature against a public key and message.
///
/// Returns `Ok(())` if the signature is valid, or
/// [`BitevachatError::CryptoError`] if verification fails.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&public_key.0).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("invalid public key: {e}"),
        }
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify_strict(message, &sig).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("signature verification failed: {e}"),
        }
    })
}

/// Derives a Bitevachat [`Address`] from an Ed25519 public key.
///
/// Process: `Address = SHA3-256(public_key_bytes)`.
///
/// The returned address is the canonical 32-byte identifier. For a
/// display-ready form with checksum and Bech32 encoding, pass this
/// address to [`crate::checksum::append_checksum`].
pub fn pubkey_to_address(public_key: &PublicKey) -> Address {
    let hash = sha3_256(&public_key.0);
    Address::new(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_keypair() {
        let kp = Keypair::generate();
        let msg = b"test message";
        let sig = kp.sign(msg);
        let pk = kp.public_key();
        assert!(verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());

        let msg = b"determinism";
        assert_eq!(kp1.sign(msg).as_bytes(), kp2.sign(msg).as_bytes());
    }

    #[test]
    fn wrong_message_fails_verification() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"correct message");
        let pk = kp.public_key();
        assert!(verify(&pk, b"wrong message", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let msg = b"test";
        let sig = kp1.sign(msg);
        assert!(verify(&kp2.public_key(), msg, &sig).is_err());
    }

    #[test]
    fn pubkey_to_address_is_deterministic() {
        let seed = [0xAA; 32];
        let kp = Keypair::from_seed(&seed);
        let addr1 = pubkey_to_address(&kp.public_key());
        let addr2 = pubkey_to_address(&kp.public_key());
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn seed_bytes_roundtrip() {
        let seed = [0x42u8; 32];
        let kp = Keypair::from_seed(&seed);
        assert_eq!(kp.seed_bytes(), seed);
    }

    #[test]
    fn to_keypair_bytes_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);
        assert_eq!(kp1.to_keypair_bytes(), kp2.to_keypair_bytes());
    }

    #[test]
    fn to_keypair_bytes_contains_seed_and_pubkey() {
        let seed = [0x42u8; 32];
        let kp = Keypair::from_seed(&seed);
        let full = kp.to_keypair_bytes();
        // First 32 bytes = seed
        assert_eq!(&full[..32], &seed);
        // Last 32 bytes = public key
        assert_eq!(&full[32..], kp.public_key().as_bytes());
    }
}