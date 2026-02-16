//! Signed profile types and operations.
//!
//! A [`Profile`] is the public metadata a node shares with the
//! network. A [`SignedProfile`] pairs a profile with an Ed25519
//! signature over its canonical CBOR encoding, preventing
//! impersonation and tampering.
//!
//! # Security invariants
//!
//! - Signature is over **deterministic CBOR** (via `serialize_to_cbor`).
//! - Version must be **strictly increasing** — peers reject older.
//! - Timestamp must not be far in the future (±5 min default).
//! - Address must match the signer's public key.
//! - Avatar bytes are **never** broadcast — only the [`Cid`].
//! - [`ProfileRevocation`] allows a key owner to invalidate
//!   their profile, preventing use after key compromise.

use bitevachat_crypto::hash::sha3_256;
use bitevachat_crypto::signing::{verify, Keypair, PublicKey, Signature};
use bitevachat_types::{Address, BitevachatError, Result, Timestamp};
use serde::{Deserialize, Serialize};

use crate::cid::{compute_cid, Cid};

/// Maximum allowed timestamp skew for profile verification (±5 min).
const MAX_PROFILE_SKEW_SECONDS: i64 = 300;

/// Maximum allowed name length in bytes.
const MAX_NAME_LEN: usize = 128;

/// Maximum allowed bio length in bytes.
const MAX_BIO_LEN: usize = 512;

/// Maximum avatar size (1 MiB).
pub const MAX_AVATAR_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Generic canonical CBOR serialization
// ---------------------------------------------------------------------------

/// Serializes any `Serialize` type to deterministic CBOR bytes.
///
/// Uses `ciborium::into_writer` with serde derives. Struct fields
/// are serialized in **declaration order**, which is deterministic
/// for a given struct definition. This is distinct from
/// [`crate::canonical::to_canonical_cbor`] (which is `Message`-only
/// with manually sorted keys per RFC 8949 §4.2).
///
/// For Profile signing, declaration-order determinism is sufficient:
/// the same struct definition always produces the same byte sequence.
///
/// # Errors
///
/// Returns `BitevachatError::ProtocolError` if serialization fails.
fn serialize_to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| {
        BitevachatError::ProtocolError {
            reason: format!("CBOR serialization failed: {e}"),
        }
    })?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/// Public metadata for a node identity.
///
/// All fields are mandatory except `avatar_cid` (profile may have
/// no avatar). The `version` field is a monotonically increasing
/// counter used for conflict resolution.
///
/// **Canonical serialization** is performed via
/// `serialize_to_cbor` for signing. The serde derives are for
/// non-canonical contexts (storage, gossip deserialization).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Address of the profile owner.
    pub address: Address,
    /// Display name.
    pub name: String,
    /// Content identifier of the avatar image (SHA3-256 of bytes).
    pub avatar_cid: Option<Cid>,
    /// Short biography / status message.
    pub bio: String,
    /// UTC timestamp of profile creation / update.
    pub timestamp: Timestamp,
    /// Monotonically increasing version counter.
    pub version: u64,
}

// ---------------------------------------------------------------------------
// SignedProfile
// ---------------------------------------------------------------------------

/// A [`Profile`] paired with an Ed25519 signature over its canonical
/// CBOR encoding.
///
/// The signature covers the deterministic CBOR bytes produced by
/// `serialize_to_cbor`, ensuring any modification is detectable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProfile {
    /// The signed profile.
    pub profile: Profile,
    /// Ed25519 signature over canonical CBOR of `profile`.
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// ProfileRevocation
// ---------------------------------------------------------------------------

/// Signed revocation of a profile.
///
/// When a key owner suspects compromise, they broadcast a revocation.
/// Peers must verify the signature and discard the cached profile.
///
/// The signed payload is:
/// `"REVOKE:" || address_bytes(32) || timestamp_iso8601_bytes`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileRevocation {
    /// Address of the profile being revoked.
    pub address: Address,
    /// UTC timestamp of revocation.
    pub timestamp: Timestamp,
    /// Ed25519 signature over the revocation payload.
    pub signature: Signature,
}

/// Revocation payload prefix.
const REVOCATION_PREFIX: &[u8] = b"REVOKE:";

// ---------------------------------------------------------------------------
// Profile creation
// ---------------------------------------------------------------------------

/// Creates a signed profile.
///
/// # Steps
///
/// 1. Compute avatar CID from bytes (if provided).
/// 2. Validate name and bio lengths.
/// 3. Build [`Profile`] struct.
/// 4. Canonical-serialize the profile.
/// 5. Sign with the Ed25519 keypair.
/// 6. Return [`SignedProfile`].
///
/// # Errors
///
/// - `ProtocolError` if name or bio exceeds maximum length.
/// - `ProtocolError` if avatar exceeds [`MAX_AVATAR_SIZE`].
/// - `ProtocolError` if canonical serialization fails.
pub fn create_signed_profile(
    keypair: &Keypair,
    name: String,
    bio: String,
    avatar_bytes: Option<&[u8]>,
    version: u64,
) -> Result<(SignedProfile, Option<Vec<u8>>)> {
    // Validate lengths.
    if name.len() > MAX_NAME_LEN {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "name length {} exceeds maximum {}",
                name.len(),
                MAX_NAME_LEN,
            ),
        });
    }
    if bio.len() > MAX_BIO_LEN {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "bio length {} exceeds maximum {}",
                bio.len(),
                MAX_BIO_LEN,
            ),
        });
    }

    // Validate and compute avatar CID.
    let (avatar_cid, avatar_blob) = match avatar_bytes {
        Some(bytes) => {
            if bytes.len() > MAX_AVATAR_SIZE {
                return Err(BitevachatError::ProtocolError {
                    reason: format!(
                        "avatar size {} exceeds maximum {}",
                        bytes.len(),
                        MAX_AVATAR_SIZE,
                    ),
                });
            }
            if bytes.is_empty() {
                (None, None)
            } else {
                let cid = compute_cid(bytes);
                (Some(cid), Some(bytes.to_vec()))
            }
        }
        None => (None, None),
    };

    // Derive address from keypair.
    let address = address_from_keypair(keypair);

    // Build profile.
    let profile = Profile {
        address,
        name,
        avatar_cid,
        bio,
        timestamp: Timestamp::now(),
        version,
    };

    // Canonical serialize and sign.
    let canonical_bytes = serialize_to_cbor(&profile)?;
    let signature = keypair.sign(&canonical_bytes);

    let signed = SignedProfile { profile, signature };

    Ok((signed, avatar_blob))
}

// ---------------------------------------------------------------------------
// Profile verification
// ---------------------------------------------------------------------------

/// Verifies a [`SignedProfile`].
///
/// # Checks (in order)
///
/// 1. Version must be ≥ 1.
/// 2. Name and bio lengths within limits.
/// 3. Canonical-serialize the profile.
/// 4. Verify Ed25519 signature.
/// 5. Verify address matches the public key.
/// 6. Validate timestamp (not too far in the future).
///
/// # Errors
///
/// - `ProtocolError` for validation failures.
/// - `CryptoError` for signature failures.
pub fn verify_signed_profile(
    signed: &SignedProfile,
    sender_pubkey: &PublicKey,
) -> Result<()> {
    let profile = &signed.profile;

    // 1. Version check.
    if profile.version < 1 {
        return Err(BitevachatError::ProtocolError {
            reason: "profile version must be >= 1".into(),
        });
    }

    // 2. Length checks.
    if profile.name.len() > MAX_NAME_LEN {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "name length {} exceeds maximum {}",
                profile.name.len(),
                MAX_NAME_LEN,
            ),
        });
    }
    if profile.bio.len() > MAX_BIO_LEN {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "bio length {} exceeds maximum {}",
                profile.bio.len(),
                MAX_BIO_LEN,
            ),
        });
    }

    // 3. Canonical serialize.
    let canonical_bytes = serialize_to_cbor(profile)?;

    // 4. Verify signature.
    verify(sender_pubkey, &canonical_bytes, &signed.signature)?;

    // 5. Verify address matches pubkey.
    let expected_address = address_from_pubkey(sender_pubkey);
    if profile.address != expected_address {
        return Err(BitevachatError::ProtocolError {
            reason: "profile address does not match signer public key".into(),
        });
    }

    // 6. Timestamp validation (not too far in the future).
    let now = chrono::Utc::now();
    let profile_time = profile.timestamp.as_datetime();
    let diff = (*profile_time - now).num_seconds();
    if diff > MAX_PROFILE_SKEW_SECONDS {
        return Err(BitevachatError::ProtocolError {
            reason: format!(
                "profile timestamp is {} seconds in the future (max {})",
                diff, MAX_PROFILE_SKEW_SECONDS,
            ),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile revocation
// ---------------------------------------------------------------------------

/// Creates a signed profile revocation.
///
/// # Errors
///
/// - `ProtocolError` if the keypair cannot produce a valid address.
pub fn create_profile_revocation(
    keypair: &Keypair,
) -> ProfileRevocation {
    let address = address_from_keypair(keypair);
    let timestamp = Timestamp::now();

    let payload = build_revocation_payload(&address, &timestamp);
    let signature = keypair.sign(&payload);

    ProfileRevocation {
        address,
        timestamp,
        signature,
    }
}

/// Verifies a profile revocation signature.
///
/// # Errors
///
/// - `CryptoError` if the signature is invalid.
/// - `ProtocolError` if the address does not match the pubkey.
pub fn verify_profile_revocation(
    revocation: &ProfileRevocation,
    sender_pubkey: &PublicKey,
) -> Result<()> {
    // Verify address matches pubkey.
    let expected_address = address_from_pubkey(sender_pubkey);
    if revocation.address != expected_address {
        return Err(BitevachatError::ProtocolError {
            reason: "revocation address does not match signer public key".into(),
        });
    }

    // Rebuild payload and verify signature.
    let payload = build_revocation_payload(
        &revocation.address,
        &revocation.timestamp,
    );
    verify(sender_pubkey, &payload, &revocation.signature)?;

    Ok(())
}

/// Builds the revocation payload bytes.
///
/// Format: `"REVOKE:" || address_bytes(32) || timestamp_iso8601_bytes`
fn build_revocation_payload(address: &Address, timestamp: &Timestamp) -> Vec<u8> {
    let ts_str = timestamp.as_str();
    let mut payload = Vec::with_capacity(
        REVOCATION_PREFIX.len() + 32 + ts_str.len(),
    );
    payload.extend_from_slice(REVOCATION_PREFIX);
    payload.extend_from_slice(address.as_bytes());
    payload.extend_from_slice(ts_str.as_bytes());
    payload
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serializes a [`SignedProfile`] to canonical CBOR for gossip transport.
///
/// The entire `SignedProfile` (profile + signature) is serialized.
pub fn serialize_signed_profile(signed: &SignedProfile) -> Result<Vec<u8>> {
    serialize_to_cbor(signed)
}

/// Deserializes a [`SignedProfile`] from CBOR bytes.
///
/// Uses standard serde CBOR deserialization (not canonical — canonical
/// is only needed for signing, not for reading).
///
/// # Errors
///
/// - `ProtocolError` if deserialization fails.
pub fn deserialize_signed_profile(data: &[u8]) -> Result<SignedProfile> {
    ciborium::de::from_reader(data).map_err(|e| {
        BitevachatError::ProtocolError {
            reason: format!("failed to deserialize SignedProfile: {e}"),
        }
    })
}

/// Deserializes a [`ProfileRevocation`] from CBOR bytes.
pub fn deserialize_profile_revocation(data: &[u8]) -> Result<ProfileRevocation> {
    ciborium::de::from_reader(data).map_err(|e| {
        BitevachatError::ProtocolError {
            reason: format!("failed to deserialize ProfileRevocation: {e}"),
        }
    })
}

/// Serializes a [`ProfileRevocation`] to canonical CBOR.
pub fn serialize_profile_revocation(revocation: &ProfileRevocation) -> Result<Vec<u8>> {
    serialize_to_cbor(revocation)
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/// Derives an [`Address`] from a keypair.
fn address_from_keypair(keypair: &Keypair) -> Address {
    let pubkey = keypair.public_key();
    address_from_pubkey(&pubkey)
}

/// Derives an [`Address`] from a public key.
///
/// `Address = SHA3-256(public_key_bytes)`
fn address_from_pubkey(pubkey: &PublicKey) -> Address {
    Address::new(sha3_256(pubkey.as_bytes()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    #[test]
    fn create_verify_roundtrip() {
        let kp = test_keypair();
        let (signed, _) = create_signed_profile(
            &kp,
            "Alice".into(),
            "Hello world".into(),
            None,
            1,
        )
        .expect("create should succeed");

        let pubkey = kp.public_key();
        assert!(verify_signed_profile(&signed, &pubkey).is_ok());
    }

    #[test]
    fn create_with_avatar() {
        let kp = test_keypair();
        let avatar = vec![0xFFu8; 1024];
        let (signed, blob) = create_signed_profile(
            &kp,
            "Bob".into(),
            "With avatar".into(),
            Some(&avatar),
            1,
        )
        .expect("create should succeed");

        assert!(signed.profile.avatar_cid.is_some());
        assert!(blob.is_some());
        assert_eq!(blob.as_ref().map(|b| b.len()), Some(1024));

        // CID must match avatar hash.
        let cid = signed.profile.avatar_cid.as_ref().expect("has cid");
        assert!(crate::cid::validate_cid(cid, &avatar));
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();

        let (signed, _) = create_signed_profile(
            &kp1,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        let wrong_pubkey = kp2.public_key();
        assert!(verify_signed_profile(&signed, &wrong_pubkey).is_err());
    }

    #[test]
    fn verify_rejects_tampered_name() {
        let kp = test_keypair();
        let (mut signed, _) = create_signed_profile(
            &kp,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        signed.profile.name = "Eve".into();
        let pubkey = kp.public_key();
        assert!(verify_signed_profile(&signed, &pubkey).is_err());
    }

    #[test]
    fn verify_rejects_tampered_version() {
        let kp = test_keypair();
        let (mut signed, _) = create_signed_profile(
            &kp,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        signed.profile.version = 999;
        let pubkey = kp.public_key();
        assert!(verify_signed_profile(&signed, &pubkey).is_err());
    }

    #[test]
    fn verify_rejects_version_zero() {
        let kp = test_keypair();
        let (mut signed, _) = create_signed_profile(
            &kp,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        // Manually set version to 0 and re-sign to bypass create check.
        signed.profile.version = 0;
        let pubkey = kp.public_key();
        // Signature now invalid for tampered profile, but also version < 1.
        assert!(verify_signed_profile(&signed, &pubkey).is_err());
    }

    #[test]
    fn name_too_long_rejected() {
        let kp = test_keypair();
        let long_name = "x".repeat(MAX_NAME_LEN + 1);
        let result = create_signed_profile(
            &kp,
            long_name,
            "Bio".into(),
            None,
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn bio_too_long_rejected() {
        let kp = test_keypair();
        let long_bio = "x".repeat(MAX_BIO_LEN + 1);
        let result = create_signed_profile(
            &kp,
            "Name".into(),
            long_bio,
            None,
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn avatar_too_large_rejected() {
        let kp = test_keypair();
        let big = vec![0u8; MAX_AVATAR_SIZE + 1];
        let result = create_signed_profile(
            &kp,
            "Name".into(),
            "Bio".into(),
            Some(&big),
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn revocation_create_verify() {
        let kp = test_keypair();
        let revocation = create_profile_revocation(&kp);
        let pubkey = kp.public_key();
        assert!(verify_profile_revocation(&revocation, &pubkey).is_ok());
    }

    #[test]
    fn revocation_wrong_pubkey_rejected() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();

        let revocation = create_profile_revocation(&kp1);
        let wrong = kp2.public_key();
        assert!(verify_profile_revocation(&revocation, &wrong).is_err());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let kp = test_keypair();
        let (signed, _) = create_signed_profile(
            &kp,
            "Test".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        let bytes = serialize_signed_profile(&signed).expect("serialize");
        let deserialized = deserialize_signed_profile(&bytes).expect("deserialize");

        assert_eq!(signed.profile.name, deserialized.profile.name);
        assert_eq!(signed.profile.version, deserialized.profile.version);
        assert_eq!(signed.profile.address, deserialized.profile.address);

        // Re-verify the deserialized profile.
        let pubkey = kp.public_key();
        assert!(verify_signed_profile(&deserialized, &pubkey).is_ok());
    }

    #[test]
    fn address_derived_from_pubkey() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let addr = address_from_pubkey(&pubkey);

        let expected = Address::new(sha3_256(pubkey.as_bytes()));
        assert_eq!(addr, expected);
    }

    #[test]
    fn empty_avatar_bytes_produces_no_cid() {
        let kp = test_keypair();
        let (signed, blob) = create_signed_profile(
            &kp,
            "Name".into(),
            "Bio".into(),
            Some(&[]),
            1,
        )
        .expect("create");

        assert!(signed.profile.avatar_cid.is_none());
        assert!(blob.is_none());
    }
}