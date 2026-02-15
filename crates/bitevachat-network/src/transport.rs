//! Transport configuration for the Bitevachat network layer.
//!
//! # Transport Architecture
//!
//! Bitevachat uses a dual-stack transport:
//!
//! - **QUIC** — Primary transport. Provides built-in encryption (TLS 1.3)
//!   and multiplexing without requiring Noise or Yamux on top.
//! - **TCP + Noise + Yamux** — Fallback transport for environments where
//!   UDP/QUIC is blocked.
//!
//! # Implementation Note
//!
//! In libp2p ≥ 0.53, transport construction is integrated into the
//! type-safe [`libp2p::SwarmBuilder`] pipeline. The builder handles
//! all transport generics internally, which avoids complex type
//! parameters leaking into application code.
//!
//! The actual transport setup lives in [`crate::swarm::BitevachatSwarm::new`]
//! where the `SwarmBuilder` is configured as:
//!
//! ```text
//! SwarmBuilder::with_existing_identity(keypair)
//!     .with_tokio()
//!     .with_tcp(tcp::Config, noise::Config::new, yamux::Config::default)?
//!     .with_quic()
//!     .with_behaviour(|key| { ... })?
//!     .build()
//! ```
//!
//! This module provides transport-related constants and configuration
//! used by the swarm builder.

use std::time::Duration;

/// Default timeout for TCP connection establishment.
///
/// If a TCP dial does not complete within this duration, it is aborted.
/// QUIC manages its own timeouts internally.
pub const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout applied to all transports at the swarm level.
///
/// This wraps the combined transport and aborts connection attempts
/// that exceed this duration.
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(20);

/// Returns the TCP configuration used by the swarm builder.
///
/// Configuration:
/// - Port reuse enabled (allows multiple connections on the same port).
/// - Nagle's algorithm disabled (`nodelay`) for lower latency.
pub fn tcp_config() -> libp2p::tcp::Config {
    libp2p::tcp::Config::default()
        .port_reuse(true)
        .nodelay(true)
}