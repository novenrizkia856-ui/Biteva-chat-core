//! gRPC RPC server for the Bitevachat Node.
//!
//! Provides local (Unix socket / localhost TCP) and optional remote
//! (mTLS + API token) access to node operations. The RPC layer is
//! a thin translation shim: it validates input, converts proto types
//! to internal types, delegates to the node via `NodeCommand` channels,
//! and maps results back to proto responses.
//!
//! # Security model
//!
//! - **Local mode** (default): Unix socket with `0600` permissions or
//!   loopback TCP. No additional authentication.
//! - **Remote mode** (opt-in): mTLS for mutual authentication plus
//!   API token in `authorization` metadata header.
//!
//! External message injection always re-verifies the Ed25519
//! signature, pubkey→address binding, and timestamp skew before
//! forwarding to the node core.
//!
//! # Modules
//!
//! - [`auth`] — `AuthInterceptor` (constant-time token validation).
//! - [`config`] — `RpcConfig`, `RpcMode` (bind settings).
//! - [`inject`] — External message re-verification.
//! - [`server`] — `RpcServer::start()` entry point.
//! - [`message_service`] — `MessageService` gRPC implementation.
//! - [`contact_service`] — `ContactService` gRPC implementation.
//! - [`node_service`] — `NodeService` gRPC implementation.

pub mod auth;
pub mod config;
pub mod contact_service;
pub mod inject;
pub mod message_service;
pub mod node_service;
pub mod server;

/// Generated protobuf/gRPC code from `proto/bitevachat.proto`.
pub mod proto {
    tonic::include_proto!("bitevachat");
}

// Re-exports for consumers.
pub use config::{RpcConfig, RpcMode};
pub use server::RpcServer;