//! Integration tests for bitevachat-wallet.
//!
//! All tests use deterministic BIP39 mnemonics (all-zero and all-FF
//! entropy) and fixed passphrases. No test relies on randomness for
//! its assertions — only for wallet-internal salt/nonce generation
//! which does not affect test correctness.

use bitevachat_types::BitevachatError;

use bitevachat_wallet::backup::{export_backup, import_from_mnemonic, BackupState};
use bitevachat_wallet::rotation::{rotate_key, verify_migration};
use bitevachat_wallet::wallet::Wallet;
use bitevachat_wallet::wallet_file::{
    read_wallet_file, write_wallet_file, WalletFileHeader, WALLET_FILE_VERSION, WALLET_MAGIC,
};

// ---------------------------------------------------------------------------
// Test constants (deterministic BIP39 mnemonics)
// ---------------------------------------------------------------------------

/// BIP39 mnemonic from all-zero (0x00) 256-bit entropy.
const MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon art";

/// BIP39 mnemonic from all-0xFF 256-bit entropy.
const MNEMONIC_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                           zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

/// Wallet encryption passphrase used in tests.
const PASSPHRASE: &str = "correct horse battery staple";

/// Alternative passphrase for wrong-passphrase tests.
const WRONG_PASSPHRASE: &str = "wrong passphrase entirely";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// RAII guard that removes a temporary file on drop.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bitevachat_test_{name}_{}.dat",
            std::process::id()
        ));
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------
// 1. Create → Lock → Unlock cycle
// ---------------------------------------------------------------------------

#[test]
fn create_lock_unlock_cycle() -> std::result::Result<(), BitevachatError> {
    // Create wallet (starts Locked).
    let mut wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    assert!(!wallet.is_unlocked());

    // get_keypair must fail while locked.
    assert!(wallet.get_keypair().is_err());

    // Unlock.
    wallet.unlock(PASSPHRASE)?;
    assert!(wallet.is_unlocked());

    // Keypair available.
    let pk = wallet.get_keypair()?.public_key();
    assert_eq!(pk.as_bytes(), wallet.public_key());

    // Lock again.
    wallet.lock();
    assert!(!wallet.is_unlocked());
    assert!(wallet.get_keypair().is_err());

    // Unlock again to verify repeatability.
    wallet.unlock(PASSPHRASE)?;
    assert!(wallet.is_unlocked());
    assert_eq!(wallet.get_keypair()?.public_key().as_bytes(), wallet.public_key());

    Ok(())
}

#[test]
fn create_two_wallets_same_mnemonic_same_address() -> std::result::Result<(), BitevachatError> {
    let w1 = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    let w2 = Wallet::create_wallet(MNEMONIC_A, "different passphrase")?;

    // Same mnemonic → same address regardless of encryption passphrase.
    assert_eq!(w1.address(), w2.address());
    assert_eq!(w1.public_key(), w2.public_key());

    // But encrypted payloads differ (different salt, nonce, passphrase).
    assert_ne!(w1.encrypted_private_key(), w2.encrypted_private_key());

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Backup → Restore roundtrip
// ---------------------------------------------------------------------------

#[test]
fn backup_restore_roundtrip() -> std::result::Result<(), BitevachatError> {
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    let original_address = *wallet.address();
    let original_pubkey = *wallet.public_key();

    // Export backup.
    let mut flow = export_backup(&wallet, PASSPHRASE)?;
    assert_eq!(flow.state(), BackupState::ShowMnemonic);

    // Read mnemonic.
    let mnemonic = flow.mnemonic()?.to_string();

    // Acknowledge and confirm.
    flow.acknowledge_shown()?;
    assert_eq!(flow.state(), BackupState::ConfirmMnemonic);

    flow.confirm(&mnemonic)?;
    assert!(flow.is_complete());

    // Import (restore) from the exported mnemonic.
    let restored = import_from_mnemonic(&mnemonic, "new passphrase")?;

    // Address and public key must match.
    assert_eq!(restored.address(), &original_address);
    assert_eq!(restored.public_key(), &original_pubkey);

    Ok(())
}

#[test]
fn backup_wrong_confirmation_rejected() -> std::result::Result<(), BitevachatError> {
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    let mut flow = export_backup(&wallet, PASSPHRASE)?;

    flow.acknowledge_shown()?;

    // Confirm with wrong words.
    let result = flow.confirm(MNEMONIC_B);
    assert!(result.is_err());

    // State should remain ConfirmMnemonic.
    assert_eq!(flow.state(), BackupState::ConfirmMnemonic);

    Ok(())
}

#[test]
fn backup_state_machine_ordering() -> std::result::Result<(), BitevachatError> {
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    let mut flow = export_backup(&wallet, PASSPHRASE)?;

    // Cannot confirm before acknowledging.
    assert!(flow.confirm(MNEMONIC_A).is_err());

    // Cannot acknowledge twice.
    flow.acknowledge_shown()?;
    assert!(flow.acknowledge_shown().is_err());

    // Cannot read mnemonic after acknowledging.
    assert!(flow.mnemonic().is_err());

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Wrong passphrase rejection
// ---------------------------------------------------------------------------

#[test]
fn wrong_passphrase_rejected() -> std::result::Result<(), BitevachatError> {
    let mut wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    let result = wallet.unlock(WRONG_PASSPHRASE);
    assert!(result.is_err());

    // Wallet remains locked.
    assert!(!wallet.is_unlocked());

    // Correct passphrase still works after failed attempt.
    wallet.unlock(PASSPHRASE)?;
    assert!(wallet.is_unlocked());

    Ok(())
}

#[test]
fn wrong_passphrase_backup_rejected() -> std::result::Result<(), BitevachatError> {
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    let result = export_backup(&wallet, WRONG_PASSPHRASE);
    assert!(result.is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Wallet file corruption detection
// ---------------------------------------------------------------------------

#[test]
fn wallet_file_roundtrip() -> std::result::Result<(), BitevachatError> {
    let tmp = TempFile::new("roundtrip");
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    let header = WalletFileHeader {
        argon2_params: *wallet.argon2_params(),
        salt: *wallet.salt(),
        nonce: *wallet.nonce(),
        public_key: *wallet.public_key(),
    };

    write_wallet_file(tmp.path(), &header, wallet.encrypted_private_key())?;
    let (read_header, read_payload) = read_wallet_file(tmp.path())?;

    assert_eq!(read_header.salt, *wallet.salt());
    assert_eq!(read_header.nonce, *wallet.nonce());
    assert_eq!(read_header.public_key, *wallet.public_key());
    assert_eq!(read_payload, wallet.encrypted_private_key());

    // Reconstruct wallet from file data and verify unlock works.
    let mut restored = Wallet::from_parts(
        read_header.public_key,
        read_payload,
        read_header.salt,
        read_header.nonce,
        read_header.argon2_params,
    );
    restored.unlock(PASSPHRASE)?;
    assert!(restored.is_unlocked());
    assert_eq!(restored.public_key(), wallet.public_key());

    Ok(())
}

#[test]
fn wallet_file_magic_mismatch() -> std::result::Result<(), BitevachatError> {
    let tmp = TempFile::new("bad_magic");
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    let header = WalletFileHeader {
        argon2_params: *wallet.argon2_params(),
        salt: *wallet.salt(),
        nonce: *wallet.nonce(),
        public_key: *wallet.public_key(),
    };

    write_wallet_file(tmp.path(), &header, wallet.encrypted_private_key())?;

    // Corrupt magic bytes.
    let mut data = std::fs::read(tmp.path()).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;
    data[0] = 0xFF;
    data[1] = 0xFF;
    std::fs::write(tmp.path(), &data).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;

    let result = read_wallet_file(tmp.path());
    assert!(result.is_err());

    Ok(())
}

#[test]
fn wallet_file_version_mismatch() -> std::result::Result<(), BitevachatError> {
    let tmp = TempFile::new("bad_version");
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    let header = WalletFileHeader {
        argon2_params: *wallet.argon2_params(),
        salt: *wallet.salt(),
        nonce: *wallet.nonce(),
        public_key: *wallet.public_key(),
    };

    write_wallet_file(tmp.path(), &header, wallet.encrypted_private_key())?;

    // Corrupt version byte (offset 4).
    let mut data = std::fs::read(tmp.path()).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;
    data[4] = 0xFF;
    std::fs::write(tmp.path(), &data).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;

    let result = read_wallet_file(tmp.path());
    assert!(result.is_err());

    Ok(())
}

#[test]
fn wallet_file_truncated() -> std::result::Result<(), BitevachatError> {
    let tmp = TempFile::new("truncated");
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    let header = WalletFileHeader {
        argon2_params: *wallet.argon2_params(),
        salt: *wallet.salt(),
        nonce: *wallet.nonce(),
        public_key: *wallet.public_key(),
    };

    write_wallet_file(tmp.path(), &header, wallet.encrypted_private_key())?;

    // Truncate to just the magic bytes.
    std::fs::write(tmp.path(), &WALLET_MAGIC).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;

    let result = read_wallet_file(tmp.path());
    assert!(result.is_err());

    Ok(())
}

#[test]
fn wallet_file_payload_corrupted_fails_decrypt() -> std::result::Result<(), BitevachatError> {
    let tmp = TempFile::new("corrupt_payload");
    let wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    let header = WalletFileHeader {
        argon2_params: *wallet.argon2_params(),
        salt: *wallet.salt(),
        nonce: *wallet.nonce(),
        public_key: *wallet.public_key(),
    };

    write_wallet_file(tmp.path(), &header, wallet.encrypted_private_key())?;

    // Corrupt payload (flip bits in the encrypted data area).
    let mut data = std::fs::read(tmp.path()).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;
    // Header is 105 bytes; corrupt first byte of payload.
    if data.len() > 105 {
        data[105] ^= 0xFF;
    }
    std::fs::write(tmp.path(), &data).map_err(|e| BitevachatError::StorageError {
        reason: format!("{e}"),
    })?;

    // File reads OK (header is intact).
    let (read_header, read_payload) = read_wallet_file(tmp.path())?;

    // But decryption must fail (authentication tag mismatch).
    let mut restored = Wallet::from_parts(
        read_header.public_key,
        read_payload,
        read_header.salt,
        read_header.nonce,
        read_header.argon2_params,
    );
    let result = restored.unlock(PASSPHRASE);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn wallet_file_header_constants_correct() {
    // Verify magic and version constants are accessible.
    assert_eq!(&WALLET_MAGIC, b"BTVC");
    assert_eq!(WALLET_FILE_VERSION, 1);
}

// ---------------------------------------------------------------------------
// 5. Rotation signature verification
// ---------------------------------------------------------------------------

#[test]
fn rotation_signature_verified() -> std::result::Result<(), BitevachatError> {
    let mut old_wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    old_wallet.unlock(PASSPHRASE)?;

    let (new_wallet, statement) = rotate_key(&old_wallet, MNEMONIC_B, "new_pass")?;

    // Addresses are different.
    assert_ne!(old_wallet.address(), new_wallet.address());
    assert_eq!(&statement.old_address, old_wallet.address());
    assert_eq!(&statement.new_address, new_wallet.address());

    // Signature verifies against old public key.
    verify_migration(&statement, old_wallet.public_key())?;

    // New wallet is locked.
    assert!(!new_wallet.is_unlocked());

    Ok(())
}

#[test]
fn rotation_wrong_public_key_fails_verification() -> std::result::Result<(), BitevachatError> {
    let mut old_wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    old_wallet.unlock(PASSPHRASE)?;

    let (new_wallet, statement) = rotate_key(&old_wallet, MNEMONIC_B, "new_pass")?;

    // Verify with the NEW public key (wrong) must fail.
    let result = verify_migration(&statement, new_wallet.public_key());
    assert!(result.is_err());

    Ok(())
}

#[test]
fn rotation_requires_unlocked_wallet() -> std::result::Result<(), BitevachatError> {
    let old_wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    // old_wallet is Locked.

    let result = rotate_key(&old_wallet, MNEMONIC_B, "new_pass");
    assert!(result.is_err());

    Ok(())
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn unlock_idempotent() -> std::result::Result<(), BitevachatError> {
    let mut wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;
    wallet.unlock(PASSPHRASE)?;

    // Second unlock is a no-op, not an error.
    wallet.unlock(PASSPHRASE)?;
    assert!(wallet.is_unlocked());

    Ok(())
}

#[test]
fn lock_idempotent() -> std::result::Result<(), BitevachatError> {
    let mut wallet = Wallet::create_wallet(MNEMONIC_A, PASSPHRASE)?;

    // Lock while already locked is a no-op.
    wallet.lock();
    assert!(!wallet.is_unlocked());

    Ok(())
}

#[test]
fn empty_passphrase_works() -> std::result::Result<(), BitevachatError> {
    let mut wallet = Wallet::create_wallet(MNEMONIC_A, "")?;
    wallet.unlock("")?;
    assert!(wallet.is_unlocked());

    // Wrong passphrase (non-empty) still rejected.
    wallet.lock();
    assert!(wallet.unlock("any").is_err());

    Ok(())
}