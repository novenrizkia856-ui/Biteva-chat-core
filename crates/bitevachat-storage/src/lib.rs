//! Encrypted storage engine for Bitevachat.
//!
//! Provides an encrypted database layer backed by sled (with optional RocksDB).
//! All data at rest is encrypted with XChaCha20-Poly1305 and tamper-protected
//! via HMAC. Subsystems: message store, conversation index, contact store,
//! pending queue, settings, and nonce cache.
