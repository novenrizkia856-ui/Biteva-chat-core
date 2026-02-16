//! Bitevachat node runtime.
//!
//! Orchestrates all subsystems: wallet, storage, network, protocol,
//! pending delivery, and maintenance. The [`Node`] struct owns all
//! components and drives them through a unified `tokio::select!`
//! event loop.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │                    Node                       │
//! │  ┌─────────┐  ┌─────────┐  ┌──────────────┐ │
//! │  │ Wallet   │  │ Storage │  │ Network Swarm│ │
//! │  └────┬─────┘  └────┬────┘  └──────┬───────┘ │
//! │       │             │              │          │
//! │       └─────────────┼──────────────┘          │
//! │                     │                         │
//! │            ┌────────┴────────┐                │
//! │            │   Event Loop    │                │
//! │            │  tokio::select! │                │
//! │            └─────┬──────────┘                 │
//! │                  │                            │
//! │  ┌───────────────┼───────────────────┐       │
//! │  │               │                   │       │
//! │  ▼               ▼                   ▼       │
//! │ Incoming    PendingScheduler    Maintenance   │
//! │ Handler         (tick)          (periodic)    │
//! └──────────────────────────────────────────────┘
//!        ▲                              │
//!        │ NodeCommand                  │ NodeEvent
//!        │                              ▼
//!     RPC / CLI                      UI / Consumer
//! ```
//!
//! # Modules
//!
//! - [`command`] — `NodeCommand` enum for external → node communication.
//! - [`node`] — `Node` struct, state machine, lifecycle.
//! - [`event_loop`] — Main `tokio::select!` loop driving all subsystems.
//! - [`incoming`] — Inbound message processing (store + emit).
//! - [`outgoing`] — Outbound message construction (encrypt + sign).
//! - [`pending_scheduler`] — Periodic retry of undelivered messages.
//! - [`maintenance`] — Periodic housekeeping (flush, prune, refresh).

pub mod command;
pub mod event_loop;
pub mod incoming;
pub mod maintenance;
pub mod node;
pub mod outgoing;
pub mod pending_scheduler;
pub mod trust;
pub mod rate_limiter;
pub mod spam_filter;

// Re-exports for RPC and CLI consumers.
pub use command::{ContactInfo, MessageInfo, NodeCommand, NodeStatus, PeerInfo};
pub use node::{Node, NodeState};
