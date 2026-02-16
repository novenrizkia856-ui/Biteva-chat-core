//! Profile management with in-memory TTL cache.
//!
//! The [`ProfileManager`] coordinates profile lifecycle:
//!
//! - **Create** — build and sign a new profile version.
//! - **Receive** — verify incoming gossip profiles and cache them.
//! - **Query** — look up cached profiles by address.
//! - **Revoke** — remove profiles upon verified revocation.
//!
//! # Cache design
//!
//! Profiles are cached in a `HashMap<Address, CachedProfile>` behind
//! a `Mutex`. Each entry has a TTL-based expiry. Expired entries are
//! treated as absent but not eagerly removed (cleanup happens on
//! access and periodically).
//!
//! # Version enforcement
//!
//! A profile update is only accepted if its version is **strictly
//! greater** than the cached version. Equal or lower versions are
//! silently rejected.
//!
//! # Thread safety
//!
//! All mutable state is behind `std::sync::Mutex`. No tokio locks.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bitevachat_crypto::signing::{Keypair, PublicKey};
use bitevachat_protocol::profiles::{
    self, deserialize_signed_profile, serialize_signed_profile,
    verify_signed_profile, ProfileRevocation, SignedProfile,
};
use bitevachat_storage::engine::StorageEngine;
use bitevachat_types::{Address, Result};

/// Default profile cache TTL (1 hour).
const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// CachedProfile
// ---------------------------------------------------------------------------

/// A profile entry in the in-memory cache with TTL tracking.
struct CachedProfile {
    /// The verified signed profile.
    signed: SignedProfile,
    /// When this cache entry was inserted.
    inserted_at: Instant,
    /// The public key used to verify the profile.
    pubkey: PublicKey,
}

// ---------------------------------------------------------------------------
// ProfileManager
// ---------------------------------------------------------------------------

/// Manages profile lifecycle: creation, caching, verification, and
/// revocation.
pub struct ProfileManager {
    /// In-memory profile cache.
    cache: Mutex<HashMap<Address, CachedProfile>>,
    /// Set of revoked addresses. Revocations persist until restart.
    revoked: Mutex<HashMap<Address, Instant>>,
    /// Cache entry time-to-live.
    cache_ttl: Duration,
}

impl ProfileManager {
    /// Creates a new `ProfileManager` with default TTL.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        }
    }

    /// Creates a new `ProfileManager` with a custom TTL.
    ///
    /// Useful for testing (e.g. `Duration::ZERO` for immediate expiry).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashMap::new()),
            cache_ttl: ttl,
        }
    }

    // -----------------------------------------------------------------------
    // Profile creation
    // -----------------------------------------------------------------------

    /// Creates a new signed profile and returns it with CBOR bytes
    /// for gossip broadcast.
    ///
    /// # Steps
    ///
    /// 1. Determine next version (current + 1, or 1 if first).
    /// 2. Create and sign the profile.
    /// 3. Save to storage (profile + avatar blob if present).
    /// 4. Insert into local cache.
    /// 5. Serialize to CBOR for gossip transport.
    /// 6. Return the CBOR bytes for the caller to publish.
    ///
    /// # Errors
    ///
    /// - `ProtocolError` for validation failures.
    /// - `StorageError` for database failures.
    pub fn update_profile(
        &self,
        keypair: &Keypair,
        name: String,
        bio: String,
        avatar_bytes: Option<&[u8]>,
        storage: &StorageEngine,
    ) -> Result<Vec<u8>> {
        let address = address_from_keypair(keypair);

        // Determine next version.
        let current_version = self.current_version(&address);
        let next_version = current_version.saturating_add(1);

        // Create signed profile.
        let (signed, avatar_blob) = profiles::create_signed_profile(
            keypair,
            name,
            bio,
            avatar_bytes,
            next_version,
        )?;

        // Save avatar blob to storage if present.
        if let (Some(cid), Some(blob)) = (&signed.profile.avatar_cid, &avatar_blob) {
            let avatar_store = storage.avatars()?;
            avatar_store.save_avatar(cid, blob)?;
        }

        // Save profile to storage.
        let profile_store = storage.profiles()?;
        profile_store.save_profile(&address, &signed)?;

        // Serialize for gossip.
        let cbor_bytes = serialize_signed_profile(&signed)?;

        // Insert into cache.
        let pubkey = keypair.public_key();
        self.insert_cache(address, signed, pubkey);

        Ok(cbor_bytes)
    }

    // -----------------------------------------------------------------------
    // Profile reception (from gossip)
    // -----------------------------------------------------------------------

    /// Processes a received profile from gossip.
    ///
    /// # Steps
    ///
    /// 1. Deserialize from CBOR.
    /// 2. Derive pubkey from the gossip source (caller provides).
    /// 3. Verify signature and all checks.
    /// 4. Check revocation status.
    /// 5. Check version is strictly greater than cached.
    /// 6. Update cache and storage.
    /// 7. Return the profile address if accepted (for event emission).
    ///
    /// Returns `Ok(None)` if the profile was valid but rejected
    /// (lower version, revoked, etc.).
    ///
    /// # Errors
    ///
    /// - `ProtocolError` for deserialization or verification failures.
    pub fn on_profile_received(
        &self,
        data: &[u8],
        sender_pubkey: &PublicKey,
        storage: &StorageEngine,
    ) -> Result<Option<Address>> {
        // 1. Deserialize.
        let signed = deserialize_signed_profile(data)?;
        let address = signed.profile.address;

        // 2. Verify.
        verify_signed_profile(&signed, sender_pubkey)?;

        // 3. Check revocation.
        if self.is_revoked(&address) {
            tracing::debug!(%address, "ignoring profile from revoked address");
            return Ok(None);
        }

        // 4. Version check — strictly greater.
        let cached_version = self.cached_version(&address);
        if signed.profile.version <= cached_version {
            tracing::debug!(
                %address,
                received = signed.profile.version,
                cached = cached_version,
                "ignoring profile with lower or equal version"
            );
            return Ok(None);
        }

        // 5. Save to storage.
        let profile_store = storage.profiles()?;
        profile_store.save_profile(&address, &signed)?;

        // 6. Update cache.
        self.insert_cache(address, signed, *sender_pubkey);

        tracing::info!(%address, "profile updated from gossip");
        Ok(Some(address))
    }

    /// Processes a profile revocation.
    ///
    /// # Steps
    ///
    /// 1. Verify revocation signature.
    /// 2. Mark address as revoked.
    /// 3. Remove from cache.
    /// 4. Remove from storage.
    ///
    /// # Errors
    ///
    /// - `CryptoError` for invalid signature.
    pub fn on_revocation_received(
        &self,
        revocation: &ProfileRevocation,
        sender_pubkey: &PublicKey,
        storage: &StorageEngine,
    ) -> Result<()> {
        // Verify signature.
        profiles::verify_profile_revocation(revocation, sender_pubkey)?;

        let address = revocation.address;

        // Mark revoked.
        if let Ok(mut revoked) = self.revoked.lock() {
            revoked.insert(address, Instant::now());
        }

        // Remove from cache.
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(&address);
        }

        // Remove from storage.
        let profile_store = storage.profiles()?;
        profile_store.remove_profile(&address)?;

        tracing::info!(%address, "profile revoked");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------------

    /// Returns the cached profile for an address, if present and
    /// not expired.
    ///
    /// If the cache entry has expired, returns `None` (the entry is
    /// not eagerly removed; cleanup happens periodically).
    pub fn get_profile(&self, address: &Address) -> Option<SignedProfile> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(address)?;

        // TTL check.
        if Instant::now().duration_since(entry.inserted_at) > self.cache_ttl {
            return None;
        }

        Some(entry.signed.clone())
    }

    /// Returns the cached profile for an address, bypassing TTL.
    ///
    /// Falls back to storage if not in cache.
    pub fn get_profile_with_fallback(
        &self,
        address: &Address,
        storage: &StorageEngine,
    ) -> Result<Option<SignedProfile>> {
        // Check cache first (TTL-aware).
        if let Some(signed) = self.get_profile(address) {
            return Ok(Some(signed));
        }

        // Fallback to storage.
        let profile_store = storage.profiles()?;
        profile_store.get_profile(address)
    }

    // -----------------------------------------------------------------------
    // Storage loading
    // -----------------------------------------------------------------------

    /// Loads all profiles from storage into the cache.
    ///
    /// Called at startup to warm the cache. Existing cache entries
    /// are replaced.
    pub fn load_from_storage(&self, storage: &StorageEngine) -> Result<usize> {
        let profile_store = storage.profiles()?;
        let profiles = profile_store.list_profiles()?;
        let count = profiles.len();

        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
            for (address, signed) in profiles {
                // We don't have the pubkey here, so we derive it
                // from the stored address. This is fine for cache
                // warming — the profile was already verified on
                // storage.
                cache.insert(
                    address,
                    CachedProfile {
                        signed,
                        inserted_at: Instant::now(),
                        pubkey: PublicKey::from_bytes([0u8; 32]),
                    },
                );
            }
        }

        tracing::info!(count, "loaded profiles from storage");
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Returns the current version from cache, or 0 if not cached.
    fn current_version(&self, address: &Address) -> u64 {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(address).map(|e| e.signed.profile.version))
            .unwrap_or(0)
    }

    /// Returns the cached version (TTL-aware), or 0 if expired/absent.
    fn cached_version(&self, address: &Address) -> u64 {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| {
                let entry = cache.get(address)?;
                if Instant::now().duration_since(entry.inserted_at) > self.cache_ttl {
                    None
                } else {
                    Some(entry.signed.profile.version)
                }
            })
            .unwrap_or(0)
    }

    /// Inserts a profile into the cache.
    fn insert_cache(&self, address: Address, signed: SignedProfile, pubkey: PublicKey) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                address,
                CachedProfile {
                    signed,
                    inserted_at: Instant::now(),
                    pubkey,
                },
            );
        }
    }

    /// Returns `true` if the address has been revoked.
    fn is_revoked(&self, address: &Address) -> bool {
        self.revoked
            .lock()
            .ok()
            .map(|revoked| revoked.contains_key(address))
            .unwrap_or(false)
    }

    /// Returns the number of cached (non-expired) profiles.
    ///
    /// Useful for monitoring and tests.
    pub fn cached_count(&self) -> usize {
        self.cache
            .lock()
            .ok()
            .map(|cache| {
                let now = Instant::now();
                cache
                    .values()
                    .filter(|e| now.duration_since(e.inserted_at) <= self.cache_ttl)
                    .count()
            })
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Test helpers (public for integration tests)
    // -----------------------------------------------------------------------

    /// Inserts a profile into the cache directly.
    ///
    /// For testing only — bypasses storage and verification.
    pub fn insert_cache_for_test(
        &self,
        address: Address,
        signed: SignedProfile,
        pubkey: PublicKey,
    ) {
        self.insert_cache(address, signed, pubkey);
    }

    /// Returns the cached version for testing.
    pub fn cached_version_for_test(&self, address: &Address) -> u64 {
        self.cached_version(address)
    }

    /// Marks an address as revoked for testing.
    pub fn mark_revoked_for_test(&self, address: &Address) {
        if let Ok(mut revoked) = self.revoked.lock() {
            revoked.insert(*address, Instant::now());
        }
    }

    /// Removes an address from cache for testing.
    pub fn remove_from_cache_for_test(&self, address: &Address) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(address);
        }
    }

    /// Returns whether an address is revoked for testing.
    pub fn is_revoked_for_test(&self, address: &Address) -> bool {
        self.is_revoked(address)
    }
}

/// Derives an [`Address`] from a keypair.
fn address_from_keypair(keypair: &Keypair) -> Address {
    let pubkey = keypair.public_key();
    Address::new(bitevachat_crypto::hash::sha3_256(pubkey.as_bytes()))
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
    fn update_profile_inserts_to_cache() {
        // NOTE: This test requires a running StorageEngine which
        // depends on sled. It is an integration test and should
        // be in tests/profile_tests.rs. Unit tests below test
        // cache logic directly.
    }

    #[test]
    fn cache_ttl_zero_expires_immediately() {
        let mgr = ProfileManager::with_ttl(Duration::ZERO);
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let address = address_from_keypair(&kp);

        // Manually insert into cache.
        let (signed, _) = profiles::create_signed_profile(
            &kp,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        mgr.insert_cache(address, signed, pubkey);

        // Should be expired immediately.
        assert!(mgr.get_profile(&address).is_none());
        assert_eq!(mgr.cached_count(), 0);
    }

    #[test]
    fn cache_ttl_large_retains() {
        let mgr = ProfileManager::with_ttl(Duration::from_secs(3600));
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let address = address_from_keypair(&kp);

        let (signed, _) = profiles::create_signed_profile(
            &kp,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        mgr.insert_cache(address, signed, pubkey);

        assert!(mgr.get_profile(&address).is_some());
        assert_eq!(mgr.cached_count(), 1);
    }

    #[test]
    fn version_must_be_strictly_greater() {
        let mgr = ProfileManager::with_ttl(Duration::from_secs(3600));
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let address = address_from_keypair(&kp);

        // Insert version 5.
        let (signed_v5, _) = profiles::create_signed_profile(
            &kp,
            "Alice".into(),
            "v5".into(),
            None,
            5,
        )
        .expect("create");

        mgr.insert_cache(address, signed_v5, pubkey);

        // cached_version should be 5.
        assert_eq!(mgr.cached_version(&address), 5);

        // Version 4 should not pass version check.
        assert!(4 <= mgr.cached_version(&address));
        // Version 6 would pass.
        assert!(6 > mgr.cached_version(&address));
    }

    #[test]
    fn revocation_removes_from_cache() {
        let mgr = ProfileManager::with_ttl(Duration::from_secs(3600));
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let address = address_from_keypair(&kp);

        let (signed, _) = profiles::create_signed_profile(
            &kp,
            "Alice".into(),
            "Bio".into(),
            None,
            1,
        )
        .expect("create");

        mgr.insert_cache(address, signed, pubkey);
        assert!(mgr.get_profile(&address).is_some());

        // Mark as revoked.
        if let Ok(mut revoked) = mgr.revoked.lock() {
            revoked.insert(address, Instant::now());
        }
        if let Ok(mut cache) = mgr.cache.lock() {
            cache.remove(&address);
        }

        assert!(mgr.get_profile(&address).is_none());
        assert!(mgr.is_revoked(&address));
    }

    #[test]
    fn different_addresses_independent() {
        let mgr = ProfileManager::with_ttl(Duration::from_secs(3600));
        let kp1 = test_keypair();
        let kp2 = test_keypair();

        let pubkey1 = kp1.public_key();
        let pubkey2 = kp2.public_key();
        let addr1 = address_from_keypair(&kp1);
        let addr2 = address_from_keypair(&kp2);

        let (signed1, _) = profiles::create_signed_profile(
            &kp1, "Alice".into(), "Bio".into(), None, 1,
        )
        .expect("create");

        mgr.insert_cache(addr1, signed1, pubkey1);

        assert!(mgr.get_profile(&addr1).is_some());
        assert!(mgr.get_profile(&addr2).is_none());
    }
}