//! Bitevachat libp2p network layer.
//!
//! Provides peer identity management, transport configuration,
//! DHT-based peer discovery, and swarm orchestration for the
//! Bitevachat decentralized messaging protocol.
//!
//! # Architecture
//!
//! - [`identity`] — Convert wallet keypairs to libp2p identities
//! - [`transport`] — QUIC + TCP transport with Noise encryption
//! - [`discovery`] — Kademlia DHT + Identify behaviour
//! - [`swarm`] — High-level swarm wrapper with event loop
//! - [`config`] — Network configuration with defaults

pub mod config;
pub mod discovery;
pub mod identity;
pub mod swarm;
pub mod transport;