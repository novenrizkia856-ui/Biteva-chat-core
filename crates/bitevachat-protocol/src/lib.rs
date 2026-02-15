//! Message protocol for the Bitevachat decentralized chat system.
//!
//! Defines the canonical message format, deterministic CBOR
//! serialization (RFC 8949), Ed25519 signing/verification pipeline,
//! timestamp and message-ID validation, and nonce-based replay
//! protection.
//!
//! # Modules
//!
//! - [`message`] — `Message`, `MessageEnvelope`, `VerifiedMessage` structs
//! - [`canonical`] — Deterministic CBOR encoding/decoding (RFC 8949 §4.2)
//! - [`signing`] — Message signing and envelope verification
//! - [`validation`] — Timestamp skew, message-ID recomputation, schema checks
//! - [`nonce`] — Bounded FIFO nonce cache for replay detection

pub mod canonical;
pub mod message;
pub mod nonce;
pub mod signing;
pub mod validation;