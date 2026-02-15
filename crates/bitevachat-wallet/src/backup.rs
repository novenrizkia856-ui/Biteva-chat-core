//! Backup state machine: export mnemonic and import-from-mnemonic.
//!
//! The backup flow follows a strict state machine to prevent
//! accidental mnemonic leakage:
//!
//! ```text
//! ShowMnemonic → ConfirmMnemonic → Complete
//! ```
//!
//! The mnemonic is held in memory only during the flow and is
//! zeroized when the [`BackupFlow`] is dropped or when the flow
//! reaches [`BackupState::Complete`].

use bitevachat_types::{BitevachatError, Result};
use zeroize::Zeroize;

use crate::wallet::{decrypt_mnemonic, Wallet};

// ---------------------------------------------------------------------------
// BackupState
// ---------------------------------------------------------------------------

/// States of the backup export flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupState {
    /// Mnemonic has been decrypted and is available for display.
    ShowMnemonic,
    /// User has acknowledged viewing; awaiting confirmation input.
    ConfirmMnemonic,
    /// User has correctly confirmed the mnemonic. Flow is finished.
    Complete,
}

// ---------------------------------------------------------------------------
// BackupFlow
// ---------------------------------------------------------------------------

/// State machine for exporting a wallet backup.
///
/// Created by [`export_backup`]. The mnemonic is zeroized on drop
/// regardless of the current state.
pub struct BackupFlow {
    /// Current state in the flow.
    state: BackupState,
    /// The decrypted BIP39 mnemonic phrase. Zeroized on drop.
    mnemonic_phrase: String,
}

impl Drop for BackupFlow {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
    }
}

impl BackupFlow {
    /// Returns the current backup flow state.
    pub fn state(&self) -> BackupState {
        self.state
    }

    /// Returns the mnemonic phrase for display.
    ///
    /// Only available in [`BackupState::ShowMnemonic`].
    ///
    /// # Errors
    ///
    /// Returns [`BitevachatError::CryptoError`] if called in any other
    /// state.
    pub fn mnemonic(&self) -> Result<&str> {
        if self.state != BackupState::ShowMnemonic {
            return Err(BitevachatError::CryptoError {
                reason: "mnemonic is only available in ShowMnemonic state".into(),
            });
        }
        Ok(&self.mnemonic_phrase)
    }

    /// Acknowledges that the user has viewed the mnemonic.
    ///
    /// Transitions from [`BackupState::ShowMnemonic`] to
    /// [`BackupState::ConfirmMnemonic`].
    ///
    /// # Errors
    ///
    /// Returns [`BitevachatError::CryptoError`] if not in
    /// `ShowMnemonic` state.
    pub fn acknowledge_shown(&mut self) -> Result<()> {
        if self.state != BackupState::ShowMnemonic {
            return Err(BitevachatError::CryptoError {
                reason: "can only acknowledge from ShowMnemonic state".into(),
            });
        }
        self.state = BackupState::ConfirmMnemonic;
        Ok(())
    }

    /// Confirms the backup by verifying user-entered words match the
    /// stored mnemonic.
    ///
    /// Transitions from [`BackupState::ConfirmMnemonic`] to
    /// [`BackupState::Complete`] on success.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::CryptoError`] if not in `ConfirmMnemonic`
    ///   state, or if the entered words do not match.
    pub fn confirm(&mut self, words: &str) -> Result<()> {
        if self.state != BackupState::ConfirmMnemonic {
            return Err(BitevachatError::CryptoError {
                reason: "can only confirm from ConfirmMnemonic state".into(),
            });
        }

        // Normalize whitespace for comparison.
        let entered: Vec<&str> = words.split_whitespace().collect();
        let stored: Vec<&str> = self.mnemonic_phrase.split_whitespace().collect();

        if entered != stored {
            return Err(BitevachatError::CryptoError {
                reason: "confirmation words do not match the mnemonic".into(),
            });
        }

        self.mnemonic_phrase.zeroize();
        self.state = BackupState::Complete;
        Ok(())
    }

    /// Returns `true` if the backup flow has completed successfully.
    pub fn is_complete(&self) -> bool {
        self.state == BackupState::Complete
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Exports a wallet backup by decrypting the mnemonic.
///
/// Temporarily decrypts the encrypted mnemonic using the provided
/// passphrase and returns a [`BackupFlow`] in the
/// [`BackupState::ShowMnemonic`] state. The mnemonic is held in
/// memory only within the `BackupFlow` and is never written to disk.
///
/// # Parameters
///
/// - `wallet` — the wallet to back up (may be locked or unlocked).
/// - `passphrase` — the encryption passphrase for this wallet.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if the passphrase is incorrect
///   or decryption fails.
pub fn export_backup(wallet: &Wallet, passphrase: &str) -> Result<BackupFlow> {
    let mnemonic_phrase = decrypt_mnemonic(
        passphrase,
        wallet.salt(),
        wallet.nonce(),
        wallet.argon2_params(),
        wallet.encrypted_private_key(),
    )?;

    Ok(BackupFlow {
        state: BackupState::ShowMnemonic,
        mnemonic_phrase,
    })
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Imports (restores) a wallet from a BIP39 mnemonic and passphrase.
///
/// Validates the mnemonic, derives the keypair via SLIP-0010, encrypts
/// the mnemonic with the given passphrase, and returns a new
/// [`Wallet`] in the `Locked` state.
///
/// This is functionally equivalent to [`Wallet::create_wallet`] and
/// exists as a semantic alias for the restore use-case.
///
/// # Errors
///
/// - [`BitevachatError::CryptoError`] if the mnemonic is invalid or
///   key derivation fails.
pub fn import_from_mnemonic(words: &str, passphrase: &str) -> Result<Wallet> {
    Wallet::create_wallet(words, passphrase)
}