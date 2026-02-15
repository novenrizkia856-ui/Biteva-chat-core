//! Key rotation with signed migration statements.
//!
//! When a user rotates their keypair, a [`MigrationStatement`] is
//! produced that cryptographically binds the old address to the new
//! address. The statement is signed by the **old** key to prove that
//! the holder of the previous identity authorises the transition.
//!
//! ```text
//! message = b"BTVC:migrate:v1:" || old_address(32) || new_address(32) || timestamp_millis_be(8)
//! signature = Ed25519.sign(old_keypair, message)
//! ```

use bitevachat_crypto::signing::{pubkey_to_address, verify, PublicKey, Signature};
use bitevachat_types::{Address, BitevachatError, Result, Timestamp};

use crate::wallet::Wallet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain-separation prefix for migration signing messages.
const MIGRATION_PREFIX: &[u8] = b"BTVC:migrate:v1:";

// ---------------------------------------------------------------------------
// MigrationStatement
// ---------------------------------------------------------------------------

/// Signed statement binding an old wallet identity to a new one.
///
/// The signature is produced by the **old** keypair, proving that the
/// previous identity holder authorises the migration. Validators can
/// verify this using [`verify_migration`].
pub struct MigrationStatement {
    /// Address of the wallet being retired.
    pub old_address: Address,
    /// Address of the newly created wallet.
    pub new_address: Address,
    /// UTC timestamp of the rotation.
    pub timestamp: Timestamp,
    /// Ed25519 signature by the old key over the canonical message.
    pub signature_by_old_key: [u8; 64],
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

/// Rotates a wallet's key to a new mnemonic.
///
/// # Process
///
/// 1. Verify the old wallet is unlocked (keypair available).
/// 2. Create the new wallet from `new_mnemonic` + `new_passphrase`.
/// 3. Build the canonical migration message.
/// 4. Sign the message with the **old** keypair.
/// 5. Return the new wallet (locked) and the migration statement.
///
/// # Parameters
///
/// - `old_wallet` — must be in the **Unlocked** state.
/// - `new_mnemonic` — validated BIP39 mnemonic for the new identity.
/// - `new_passphrase` — encryption passphrase for the new wallet.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if the old wallet is locked, the
///   new mnemonic is invalid, or signing fails.
pub fn rotate_key(
    old_wallet: &Wallet,
    new_mnemonic: &str,
    new_passphrase: &str,
) -> Result<(Wallet, MigrationStatement)> {
    // 1. Old wallet must be unlocked.
    let old_keypair = old_wallet.get_keypair()?;
    let old_address = *old_wallet.address();

    // 2. Create new wallet.
    let new_wallet = Wallet::create_wallet(new_mnemonic, new_passphrase)?;
    let new_address = *new_wallet.address();

    // 3. Build canonical migration message.
    let timestamp = Timestamp::now();
    let message = build_migration_message(&old_address, &new_address, &timestamp);

    // 4. Sign with old key.
    let sig = old_keypair.sign(&message);

    // 5. Return.
    let statement = MigrationStatement {
        old_address,
        new_address,
        timestamp,
        signature_by_old_key: *sig.as_bytes(),
    };

    Ok((new_wallet, statement))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verifies a migration statement against the old wallet's public key.
///
/// Reconstructs the canonical migration message from the statement's
/// fields and verifies the Ed25519 signature using the provided
/// public key.
///
/// # Parameters
///
/// - `statement` — the migration statement to verify.
/// - `old_public_key` — the Ed25519 public key of the old wallet.
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if the signature is invalid.
pub fn verify_migration(
    statement: &MigrationStatement,
    old_public_key: &[u8; 32],
) -> Result<()> {
    let message = build_migration_message(
        &statement.old_address,
        &statement.new_address,
        &statement.timestamp,
    );

    let pk = PublicKey::from_bytes(*old_public_key);
    let sig = Signature::from_bytes(statement.signature_by_old_key);

    verify(&pk, &message, &sig)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/// Builds the canonical byte message for migration signing/verification.
///
/// Format: `b"BTVC:migrate:v1:" || old_address(32) || new_address(32) || timestamp_millis_be(8)`
///
/// Total: 16 + 32 + 32 + 8 = 88 bytes.
fn build_migration_message(
    old_address: &Address,
    new_address: &Address,
    timestamp: &Timestamp,
) -> Vec<u8> {
    let ts_millis = timestamp.as_datetime().timestamp_millis();
    let ts_bytes = ts_millis.to_be_bytes();

    let mut msg = Vec::with_capacity(MIGRATION_PREFIX.len() + 32 + 32 + 8);
    msg.extend_from_slice(MIGRATION_PREFIX);
    msg.extend_from_slice(old_address.as_ref());
    msg.extend_from_slice(new_address.as_ref());
    msg.extend_from_slice(&ts_bytes);
    msg
}