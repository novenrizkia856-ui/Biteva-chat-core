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

pub mod aead;
pub mod checksum;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod signing;
