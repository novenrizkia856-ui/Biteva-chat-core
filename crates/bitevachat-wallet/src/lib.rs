//! Wallet lifecycle management for Bitevachat.
//!
//! Handles the full wallet lifecycle:
//!
//! - **Create** from BIP39 mnemonic
//! - **Encrypt** private key to `wallet.dat` (Argon2id + XChaCha20-Poly1305)
//! - **Lock / Unlock** with passphrase
//! - **Backup** mnemonic (show once, require confirmation)
//! - **Import** from existing BIP39 mnemonic
//! - **Key rotation** with migration statement signed by old key
