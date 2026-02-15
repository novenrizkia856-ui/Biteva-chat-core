//! Encrypted storage engine for Bitevachat.
//!
//! Provides an encrypted database layer backed by sled (with optional RocksDB).
//! All data at rest is encrypted with XChaCha20-Poly1305 and tamper-protected
//! via HMAC-SHA256. Subsystems: message store, conversation index, contact
//! store, settings, and nonce cache.

pub mod engine;
pub mod encrypted_tree;
pub mod messages;
pub mod conversations;
pub mod contacts;
pub mod settings;
pub mod pending;
pub mod pending_file;