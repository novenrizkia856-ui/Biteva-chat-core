//! Bitevachat libp2p network layer.
//!
//! Provides peer identity management, transport configuration,
//! DHT-based peer discovery, direct message routing with ACK,
//! gossip pub/sub for metadata, and swarm orchestration for the
//! Bitevachat decentralized messaging protocol.
//!
//! # Architecture
//!
//! - [`identity`] — Convert wallet keypairs to libp2p identities
//! - [`transport`] — QUIC + TCP transport with Noise encryption
//! - [`discovery`] — Kademlia DHT + Identify behaviour
//! - [`protocol`] — Wire codec for message send/ACK (request_response)
//! - [`handler`] — Inbound message validation (sig, timestamp, nonce)
//! - [`routing`] — Outbound delivery tracking and status
//! - [`gossip`] — Gossipsub for presence and profile updates
//! - [`events`] — Unified network event enum
//! - [`swarm`] — Combined behaviour + high-level swarm wrapper
//! - [`config`] — Network configuration with defaults

pub mod config;
pub mod discovery;
pub mod events;
pub mod gossip;
pub mod handler;
pub mod hole_punch;
pub mod identity;
pub mod nat;
pub mod protocol;
pub mod relay;
pub mod routing;
pub mod swarm;
pub mod transport;
pub mod turn;