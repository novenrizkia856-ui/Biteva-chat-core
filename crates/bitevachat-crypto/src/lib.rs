//! Cryptographic primitives for the Bitevachat decentralized chat system.
//!
//! This crate is the **sole** location for all cryptographic operations.
//! No other crate in the workspace may perform raw crypto directly.
//!
//! # Modules
//!
//! - [`signing`] — Ed25519 keypair generation, signing, and verification
//! - [`ecdh`] — X25519 Elliptic-Curve Diffie-Hellman key agreement
//! - [`aead`] — XChaCha20-Poly1305 authenticated encryption/decryption
//! - [`hash`] — SHA3-256 hashing and message ID computation
//! - [`kdf`] — Argon2id key derivation for wallet encryption
//! - [`checksum`] — Address checksum and Bech32 encoding
//! - [`mnemonic`] — BIP39 mnemonic generation, validation, and seed derivation
//! - [`hd_derive`] — SLIP-0010 Ed25519 hierarchical deterministic key derivation
//! - [`wordlist`] — Embedded BIP39 English 2048-word list

pub mod aead;
pub mod checksum;
pub mod ecdh;
pub mod hash;
pub mod hd_derive;
pub mod kdf;
pub mod mnemonic;
pub mod signing;
pub mod wordlist;
