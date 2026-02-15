//! Core wallet creation, encryption, and lock/unlock lifecycle.
//!
//! A [`Wallet`] encrypts its BIP39 mnemonic at rest using
//! Argon2id-derived keys and XChaCha20-Poly1305 AEAD. The private
//! key is only held in memory while the wallet is in the
//! [`WalletState::Unlocked`] state; locking zeroizes the keypair.

use bitevachat_crypto::aead::{decrypt_xchacha20, encrypt_xchacha20, AeadNonce};
use bitevachat_crypto::hd_derive::derive_ed25519_keypair;
use bitevachat_crypto::kdf::{argon2id_derive_key, Argon2Params};
use bitevachat_crypto::mnemonic::{mnemonic_to_seed, validate_mnemonic};
use bitevachat_crypto::signing::{pubkey_to_address, Keypair};
use bitevachat_types::{Address, BitevachatError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default BIP-44 derivation path for Bitevachat wallets.
///
/// `m/44'/0'/0'/0'/0'` — all hardened as required by SLIP-0010 Ed25519.
const DERIVATION_PATH: &str = "m/44'/0'/0'/0'/0'";

/// Additional authenticated data for wallet AEAD encryption.
///
/// Binds ciphertext to the wallet file format. Any attempt to decrypt
/// with a different AAD (e.g. from a different application) will fail
/// authentication.
pub(crate) const WALLET_AAD: &[u8] = b"btvc-wallet-v1";

// ---------------------------------------------------------------------------
// WalletState
// ---------------------------------------------------------------------------

/// Represents the lock state of a wallet.
///
/// - `Locked` — no private key in memory; signing operations are
///   unavailable.
/// - `Unlocked` — the keypair is decrypted and held in memory, ready
///   for signing. Transitions back to `Locked` via [`Wallet::lock`].
pub enum WalletState {
    /// Private key is not in memory.
    Locked,
    /// Private key is decrypted and available.
    Unlocked(UnlockedWallet),
}

// ---------------------------------------------------------------------------
// UnlockedWallet
// ---------------------------------------------------------------------------

/// In-memory decrypted wallet holding the Ed25519 signing keypair.
///
/// The contained [`Keypair`] wraps an `ed25519-dalek` `SigningKey`
/// which implements `ZeroizeOnDrop`, ensuring the private key is
/// scrubbed from memory when this struct is dropped (either explicitly
/// via [`Wallet::lock`] or when the wallet goes out of scope).
pub struct UnlockedWallet {
    /// The Ed25519 signing keypair.
    keypair: Keypair,
}

impl UnlockedWallet {
    /// Returns a reference to the Ed25519 signing keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

/// Encrypted wallet with passphrase-based lock/unlock lifecycle.
///
/// At rest the wallet stores only the encrypted BIP39 mnemonic
/// (the "encrypted private key"). On [`unlock`](Wallet::unlock) the
/// mnemonic is decrypted, the Ed25519 keypair is re-derived via
/// SLIP-0010, and the public key is verified against the stored value.
///
/// # Invariants
///
/// - `encrypted_private_key` is the XChaCha20-Poly1305 ciphertext of
///   the UTF-8 BIP39 mnemonic, encrypted with a key derived from the
///   user passphrase via Argon2id.
/// - `public_key` always matches the keypair derivable from the
///   encrypted mnemonic.
/// - The mnemonic is never stored in plaintext fields.
pub struct Wallet {
    /// Wallet address derived from SHA3-256(public_key).
    address: Address,
    /// Raw Ed25519 public key bytes (32).
    public_key: [u8; 32],
    /// Current lock/unlock state.
    state: WalletState,
    /// XChaCha20-Poly1305 ciphertext of the BIP39 mnemonic + 16-byte tag.
    encrypted_private_key: Vec<u8>,
    /// 32-byte random salt for Argon2id.
    salt: [u8; 32],
    /// 24-byte random nonce for XChaCha20-Poly1305.
    nonce: [u8; 24],
    /// Argon2id tuning parameters used during key derivation.
    argon2_params: Argon2Params,
}

impl Wallet {
    // -- Accessors --------------------------------------------------------

    /// Returns the wallet address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the raw 32-byte Ed25519 public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns `true` if the wallet is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, WalletState::Unlocked(_))
    }

    /// Returns the encrypted mnemonic ciphertext (for file serialization).
    pub fn encrypted_private_key(&self) -> &[u8] {
        &self.encrypted_private_key
    }

    /// Returns the Argon2id salt (for file serialization).
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Returns the AEAD nonce (for file serialization).
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Returns the Argon2id parameters (for file serialization).
    pub fn argon2_params(&self) -> &Argon2Params {
        &self.argon2_params
    }

    // -- Lifecycle --------------------------------------------------------

    /// Creates a new wallet from a validated BIP39 mnemonic and passphrase.
    ///
    /// # Process
    ///
    /// 1. Validate the mnemonic (24 words, checksum).
    /// 2. Derive seed via PBKDF2-HMAC-SHA512 (BIP39, empty BIP39 passphrase).
    /// 3. Derive Ed25519 keypair via SLIP-0010 at `m/44'/0'/0'/0'/0'`.
    /// 4. Generate 32-byte random salt and 24-byte random nonce.
    /// 5. Derive 256-bit encryption key via Argon2id(passphrase, salt).
    /// 6. Encrypt mnemonic with XChaCha20-Poly1305.
    /// 7. Return wallet in **Locked** state.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::CryptoError`] if the mnemonic is invalid, key
    ///   derivation fails, or encryption fails.
    pub fn create_wallet(mnemonic: &str, passphrase: &str) -> Result<Self> {
        // 1. Validate mnemonic.
        validate_mnemonic(mnemonic)?;

        // 2–3. Derive keypair.
        let seed = mnemonic_to_seed(mnemonic, "")?;
        let keypair = derive_ed25519_keypair(&seed, DERIVATION_PATH)?;
        let public_key = keypair.public_key();
        let address = pubkey_to_address(&public_key);

        // 4. Generate salt and nonce.
        let mut salt = [0u8; 32];
        OsRng.try_fill_bytes(&mut salt).map_err(|e| BitevachatError::CryptoError {
            reason: format!("failed to generate random salt: {e}"),
        })?;

        let mut nonce_bytes = [0u8; 24];
        OsRng.try_fill_bytes(&mut nonce_bytes).map_err(|e| BitevachatError::CryptoError {
            reason: format!("failed to generate random nonce: {e}"),
        })?;
        let aead_nonce = AeadNonce::from_bytes(nonce_bytes);

        // 5. Derive encryption key.
        let params = Argon2Params::default();
        let derived_key = argon2id_derive_key(passphrase.as_bytes(), &salt, &params)?;

        // 6. Encrypt mnemonic.
        let encrypted = encrypt_xchacha20(
            derived_key.as_bytes(),
            &aead_nonce,
            mnemonic.as_bytes(),
            WALLET_AAD,
        )?;

        // 7. Return locked wallet.
        Ok(Self {
            address,
            public_key: *public_key.as_bytes(),
            state: WalletState::Locked,
            encrypted_private_key: encrypted.ciphertext,
            salt,
            nonce: nonce_bytes,
            argon2_params: params,
        })
    }

    /// Creates a wallet from pre-computed components.
    ///
    /// Intended for reconstructing a wallet after reading and
    /// validating a wallet file via [`crate::wallet_file::read_wallet_file`].
    /// No cryptographic validation is performed — the caller is
    /// responsible for ensuring the header was verified (magic, version,
    /// corruption checks) before calling this constructor.
    pub fn from_parts(
        public_key: [u8; 32],
        encrypted_private_key: Vec<u8>,
        salt: [u8; 32],
        nonce: [u8; 24],
        argon2_params: Argon2Params,
    ) -> Self {
        let pk = bitevachat_crypto::signing::PublicKey::from_bytes(public_key);
        let address = pubkey_to_address(&pk);
        Self {
            address,
            public_key,
            state: WalletState::Locked,
            encrypted_private_key,
            salt,
            nonce,
            argon2_params,
        }
    }

    /// Unlocks the wallet by decrypting the mnemonic and re-deriving the keypair.
    ///
    /// # Process
    ///
    /// 1. Derive encryption key via Argon2id(passphrase, stored salt).
    /// 2. Decrypt the mnemonic with XChaCha20-Poly1305.
    /// 3. Re-derive Ed25519 keypair from the mnemonic.
    /// 4. Verify the derived public key matches the stored public key.
    /// 5. Transition to `Unlocked` state.
    ///
    /// If the wallet is already unlocked, this is a no-op.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::CryptoError`] if the passphrase is wrong
    ///   (AEAD authentication fails) or the derived key does not match.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        if matches!(self.state, WalletState::Unlocked(_)) {
            return Ok(());
        }

        // 1. Derive encryption key.
        let derived_key = argon2id_derive_key(
            passphrase.as_bytes(),
            &self.salt,
            &self.argon2_params,
        )?;

        // 2. Decrypt mnemonic.
        let aead_nonce = AeadNonce::from_bytes(self.nonce);
        let plaintext = decrypt_xchacha20(
            derived_key.as_bytes(),
            &aead_nonce,
            &self.encrypted_private_key,
            WALLET_AAD,
        )?;

        let mut mnemonic_str = String::from_utf8(plaintext).map_err(|e| {
            let mut bad = e.into_bytes();
            bad.zeroize();
            BitevachatError::CryptoError {
                reason: "decrypted payload is not valid UTF-8".into(),
            }
        })?;

        // 3–4. Re-derive keypair and verify. Zeroize mnemonic in all paths.
        let result = (|| -> Result<Keypair> {
            let seed = mnemonic_to_seed(&mnemonic_str, "")?;
            let kp = derive_ed25519_keypair(&seed, DERIVATION_PATH)?;

            if kp.public_key().as_bytes() != &self.public_key {
                return Err(BitevachatError::CryptoError {
                    reason: "decrypted key does not match wallet public key".into(),
                });
            }

            Ok(kp)
        })();

        mnemonic_str.zeroize();

        // 5. Transition.
        let keypair = result?;
        self.state = WalletState::Unlocked(UnlockedWallet { keypair });
        Ok(())
    }

    /// Locks the wallet, zeroizing the in-memory keypair.
    ///
    /// The `UnlockedWallet` is dropped, which triggers `ZeroizeOnDrop`
    /// on the underlying Ed25519 `SigningKey`. After this call the
    /// wallet is in the `Locked` state and signing is unavailable.
    ///
    /// If already locked, this is a no-op.
    pub fn lock(&mut self) {
        // Assignment drops the previous WalletState::Unlocked variant,
        // which drops UnlockedWallet → Keypair → SigningKey (ZeroizeOnDrop).
        self.state = WalletState::Locked;
    }

    /// Returns a reference to the signing keypair.
    ///
    /// # Errors
    ///
    /// Returns [`BitevachatError::CryptoError`] if the wallet is locked.
    pub fn get_keypair(&self) -> Result<&Keypair> {
        match &self.state {
            WalletState::Unlocked(unlocked) => Ok(&unlocked.keypair),
            WalletState::Locked => Err(BitevachatError::CryptoError {
                reason: "wallet is locked; call unlock() first".into(),
            }),
        }
    }
}

/// Decrypts the mnemonic from a wallet's encrypted payload.
///
/// Shared helper used by [`Wallet::unlock`] and [`crate::backup::export_backup`].
/// The caller is responsible for zeroizing the returned `String`.
pub(crate) fn decrypt_mnemonic(
    passphrase: &str,
    salt: &[u8; 32],
    nonce: &[u8; 24],
    argon2_params: &Argon2Params,
    encrypted: &[u8],
) -> Result<String> {
    let derived_key = argon2id_derive_key(passphrase.as_bytes(), salt, argon2_params)?;

    let aead_nonce = AeadNonce::from_bytes(*nonce);
    let plaintext = decrypt_xchacha20(
        derived_key.as_bytes(),
        &aead_nonce,
        encrypted,
        WALLET_AAD,
    )?;

    String::from_utf8(plaintext).map_err(|e| {
        let mut bad = e.into_bytes();
        bad.zeroize();
        BitevachatError::CryptoError {
            reason: "decrypted payload is not valid UTF-8".into(),
        }
    })
}