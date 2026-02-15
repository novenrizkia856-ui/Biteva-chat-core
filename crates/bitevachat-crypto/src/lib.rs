//! Cryptographic primitives for the Bitevachat decentralized chat system.
//!
//! This crate is the **sole** location for all cryptographic operations:
//!
//! - **Ed25519** signing and verification
//! - **X25519** ECDH key agreement
//! - **XChaCha20-Poly1305** AEAD encryption/decryption
//! - **SHA3-256** hashing and message ID computation
//! - **Argon2id** key derivation for wallet encryption
//! - **BIP39** mnemonic generation and seed derivation
//! - **HKDF-SHA256** for session key derivation
//!
//! No other crate in the workspace should perform raw crypto operations.
