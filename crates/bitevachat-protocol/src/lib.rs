//! Message protocol for the Bitevachat decentralized chat system.
//!
//! Defines the canonical message format, deterministic CBOR
//! serialization (RFC 8949), Ed25519 signing/verification pipeline,
//! timestamp and message-ID validation, nonce-based replay
//! protection, and end-to-end encryption via ephemeral X25519 ECDH.
//!
//! # Modules
//!
//! - [`message`] — `Message`, `MessageEnvelope`, `VerifiedMessage` structs
//! - [`canonical`] — Deterministic CBOR encoding/decoding (RFC 8949 §4.2)
//! - [`signing`] — Message signing and envelope verification
//! - [`validation`] — Timestamp skew, message-ID recomputation, schema checks
//! - [`nonce`] — Bounded FIFO nonce cache for replay detection
//! - [`session`] — Session key derivation from ECDH shared secrets
//! - [`e2e`] — End-to-end encryption with ephemeral X25519 ECDH

pub mod canonical;
pub mod e2e;
pub mod message;
pub mod nonce;
pub mod session;
pub mod signing;
pub mod validation;