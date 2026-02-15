//! Wallet lifecycle management for the Bitevachat decentralized chat system.
//!
//! Provides wallet creation from BIP39 mnemonics, passphrase-based
//! encryption at rest (Argon2id + XChaCha20-Poly1305), lock/unlock
//! lifecycle, backup/restore flows, and key rotation with signed
//! migration statements.
//!
//! # Modules
//!
//! - [`wallet`] — Core wallet struct, creation, lock/unlock, encryption
//! - [`wallet_file`] — Binary wallet file format: header, read, write
//! - [`backup`] — Backup state machine and mnemonic import/export
//! - [`rotation`] — Key rotation with migration statement signing

pub mod backup;
pub mod rotation;
pub mod wallet;
pub mod wallet_file;