//! Bitevachat node runtime.
//!
//! Orchestrates all subsystems: wallet, storage, network, protocol, RPC.
//! Contains the pending delivery scheduler and (future) event loop.

pub mod pending_scheduler;