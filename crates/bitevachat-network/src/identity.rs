//! Conversion between Bitevachat wallet identities and libp2p identities.
//!
//! All conversions are deterministic: the same wallet keypair always
//! produces the same libp2p `Keypair` and `PeerId`.
//!
//! # Address → PeerId
//!
//! A direct `Address → PeerId` conversion is **not possible** because
//! `Address = SHA3-256(public_key)` is a one-way hash — the original
//! public key cannot be recovered. Use the DHT-based lookup in
//! [`crate::discovery`] to resolve an `Address` to a `PeerId` at
//! runtime via [`crate::discovery::DiscoveryBehaviour::publish_address`]
//! and [`crate::discovery::DiscoveryBehaviour::find_peer`].

use libp2p::identity;
use libp2p::PeerId;

use bitevachat_crypto::signing::{Keypair, PublicKey};
use bitevachat_types::{BitevachatError, Result};

/// Converts a Bitevachat wallet Ed25519 keypair into a libp2p identity.
///
/// # Determinism
///
/// The resulting `PeerId` is fully deterministic: identical seed bytes
/// always produce the same libp2p identity and `PeerId`.
///
/// # Security
///
/// Internally copies the 64-byte keypair encoding (seed ‖ public key)
/// and passes it to libp2p's `ed25519::Keypair::try_from_bytes`, which
/// zeroes the input buffer on success.
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if the raw bytes cannot be
/// parsed as a valid Ed25519 keypair by libp2p.
pub fn wallet_keypair_to_libp2p(
    keypair: &Keypair,
) -> Result<identity::Keypair> {
    // Obtain the 64-byte representation: seed (32) ‖ public (32).
    // `try_from_bytes` zeroes this buffer on success.
    let mut raw = keypair.to_keypair_bytes();

    let ed25519_kp =
        identity::ed25519::Keypair::try_from_bytes(&mut raw).map_err(|e| {
            BitevachatError::NetworkError {
                reason: format!(
                    "failed to convert wallet keypair to libp2p ed25519 identity: {e}"
                ),
            }
        })?;

    Ok(identity::Keypair::from(ed25519_kp))
}

/// Derives a deterministic `PeerId` from a Bitevachat Ed25519 public key.
///
/// # Determinism
///
/// The same 32-byte public key always produces the same `PeerId`.
/// This is because libp2p computes `PeerId = Multihash(protobuf(public_key))`.
///
/// # Difference from `Address`
///
/// - `Address = SHA3-256(public_key)` — Bitevachat-internal identifier.
/// - `PeerId = Multihash(protobuf(public_key))` — libp2p-level identifier.
///
/// Both are deterministic derivations from the same public key but
/// use different hash functions and encodings.
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if the raw bytes are not a
/// valid Ed25519 public key.
pub fn peer_id_from_public_key(
    public_key: &PublicKey,
) -> Result<PeerId> {
    let ed25519_pk =
        identity::ed25519::PublicKey::try_from_bytes(public_key.as_bytes()).map_err(
            |e| BitevachatError::NetworkError {
                reason: format!(
                    "failed to convert public key to libp2p ed25519 public key: {e}"
                ),
            },
        )?;

    let libp2p_pk = identity::PublicKey::from(ed25519_pk);
    Ok(PeerId::from(libp2p_pk))
}

/// Extracts the `PeerId` from a libp2p `Keypair`.
///
/// Convenience wrapper — equivalent to `PeerId::from(keypair.public())`.
pub fn peer_id_from_keypair(keypair: &identity::Keypair) -> PeerId {
    PeerId::from(keypair.public())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_to_libp2p_is_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);

        let libp2p_kp1 = wallet_keypair_to_libp2p(&kp1);
        let libp2p_kp2 = wallet_keypair_to_libp2p(&kp2);

        assert!(libp2p_kp1.is_ok());
        assert!(libp2p_kp2.is_ok());

        let pid1 = peer_id_from_keypair(&libp2p_kp1.unwrap());
        let pid2 = peer_id_from_keypair(&libp2p_kp2.unwrap());
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn peer_id_from_public_key_is_deterministic() {
        let seed = [0xAA; 32];
        let kp = Keypair::from_seed(&seed);
        let pk = kp.public_key();

        let pid1 = peer_id_from_public_key(&pk);
        let pid2 = peer_id_from_public_key(&pk);

        assert!(pid1.is_ok());
        assert!(pid2.is_ok());
        assert_eq!(pid1.unwrap(), pid2.unwrap());
    }

    #[test]
    fn peer_id_matches_between_keypair_and_pubkey() {
        let seed = [0xBB; 32];
        let wallet_kp = Keypair::from_seed(&seed);

        // PeerId from full keypair conversion
        let libp2p_kp = wallet_keypair_to_libp2p(&wallet_kp).unwrap();
        let pid_from_kp = peer_id_from_keypair(&libp2p_kp);

        // PeerId from public key only
        let pid_from_pk = peer_id_from_public_key(&wallet_kp.public_key()).unwrap();

        assert_eq!(pid_from_kp, pid_from_pk);
    }

    #[test]
    fn different_seeds_produce_different_peer_ids() {
        let kp1 = Keypair::from_seed(&[0x01; 32]);
        let kp2 = Keypair::from_seed(&[0x02; 32]);

        let pid1 = peer_id_from_public_key(&kp1.public_key()).unwrap();
        let pid2 = peer_id_from_public_key(&kp2.public_key()).unwrap();

        assert_ne!(pid1, pid2);
    }
}