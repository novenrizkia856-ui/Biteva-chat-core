//! Node lifecycle and state machine.
//!
//! The [`Node`] is the public entry point for the Bitevachat runtime.
//! It owns all subsystems and exposes a channel-based API for
//! external consumers (RPC, CLI, tests).
//!
//! # State machine
//!
//! ```text
//! Initializing ──start()──▶ Running ──shutdown()──▶ ShuttingDown ──▶ (dropped)
//! ```
//!
//! - `Initializing` — components created, not yet listening.
//! - `Running` — event loop active, processing events and commands.
//! - `ShuttingDown` — draining in-flight work, flushing storage.
//!
//! Double-start and shutdown-from-initializing are rejected with
//! `BitevachatError::ConfigError`.

use std::path::Path;
use std::sync::Arc;

use bitevachat_crypto::signing::pubkey_to_address;
use bitevachat_network::config::NetworkConfig;
use bitevachat_network::events::NetworkEvent;
use bitevachat_network::swarm::BitevachatSwarm;
use bitevachat_storage::pending::PendingQueue;
use bitevachat_storage::engine::StorageEngine;
use bitevachat_types::config::AppConfig;
use bitevachat_types::{BitevachatError, NodeEvent, NodeId};
use bitevachat_wallet::wallet::Wallet;
use libp2p::Multiaddr;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::command::NodeCommand;
use crate::event_loop;

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Channel buffer sizes
// ---------------------------------------------------------------------------

/// Bounded command channel capacity.
///
/// Commands from RPC/CLI. Small buffer — callers await backpressure
/// if the event loop is overloaded.
const COMMAND_CHANNEL_SIZE: usize = 256;

/// Bounded node event channel capacity.
///
/// Events to UI/RPC consumers. Larger buffer to absorb bursts of
/// incoming messages without blocking the event loop.
const EVENT_CHANNEL_SIZE: usize = 1024;

/// Default pending scheduler tick interval in seconds.
const PENDING_TICK_SECS: u64 = 30;

/// Default maintenance tick interval in seconds.
const MAINTENANCE_TICK_SECS: u64 = 300;

/// Default pending queue global max.
const PENDING_GLOBAL_MAX: usize = 5000;

/// Default backoff cap in seconds (60 minutes).
const BACKOFF_CAP_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// NodeState
// ---------------------------------------------------------------------------

/// Lifecycle state of the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeState {
    /// Components created, event loop not started.
    Initializing,
    /// Event loop is active.
    Running,
    /// Graceful shutdown in progress.
    ShuttingDown,
}

impl std::fmt::Display for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "initializing"),
            Self::Running => write!(f, "running"),
            Self::ShuttingDown => write!(f, "shutting_down"),
        }
    }
}

// ---------------------------------------------------------------------------
// NodeRuntime (internal)
// ---------------------------------------------------------------------------

/// Owned runtime state moved into the event loop task.
///
/// Not exported — only [`Node`] and [`event_loop::run_event_loop`]
/// access this struct.
pub(crate) struct NodeRuntime {
    pub wallet: Wallet,
    pub storage: StorageEngine,
    pub network: BitevachatSwarm,
    pub network_rx: mpsc::UnboundedReceiver<NetworkEvent>,
    pub pending_queue: Arc<PendingQueue>,
    pub config: AppConfig,
    pub node_id: NodeId,
    pub listen_addr: libp2p::Multiaddr,
    pub event_tx: mpsc::Sender<NodeEvent>,
    pub command_rx: mpsc::Receiver<NodeCommand>,
    pub shutdown_rx: watch::Receiver<bool>,
    pub pending_tick_secs: u64,
    pub maintenance_tick_secs: u64,
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Bitevachat node — owns all subsystems and drives the event loop.
///
/// After construction via [`Node::new`], call [`Node::start`] to
/// spawn the event loop. Interact through the returned channels:
///
/// - Send [`NodeCommand`]s via [`Node::command_sender`].
/// - Receive [`NodeEvent`]s via [`Node::take_event_receiver`].
/// - Shut down via [`NodeCommand::Shutdown`] or [`Node::shutdown`].
pub struct Node {
    /// Current lifecycle state.
    state: NodeState,

    /// Components to be moved into the event loop. `None` after
    /// `start()` has been called.
    runtime: Option<NodeRuntime>,

    /// Sender for commands to the event loop.
    command_tx: mpsc::Sender<NodeCommand>,

    /// Receiver for events from the event loop.
    /// `None` after taken by the consumer via [`take_event_receiver`].
    event_rx: Option<mpsc::Receiver<NodeEvent>>,

    /// Signals the event loop to shut down.
    shutdown_tx: watch::Sender<bool>,

    /// Handle to the spawned event loop task. `None` before `start()`.
    task_handle: Option<JoinHandle<()>>,
}

impl Node {
    /// Creates a new node with all subsystems initialized.
    ///
    /// The wallet **must** be unlocked before calling this function
    /// (the signing keypair is needed to construct the network swarm).
    ///
    /// # Parameters
    ///
    /// - `wallet` — unlocked wallet for signing and identity.
    /// - `storage` — opened storage engine (encrypted at rest).
    /// - `pending_path` — path to the pending queue file.
    /// - `app_config` — application-level configuration.
    /// - `net_config` — network-level configuration.
    ///
    /// # Errors
    ///
    /// - `BitevachatError::CryptoError` if the wallet is locked.
    /// - `BitevachatError::NetworkError` if swarm creation fails.
    /// - `BitevachatError::StorageError` if the pending queue cannot
    ///   be opened.
    pub async fn new(
        wallet: Wallet,
        storage: StorageEngine,
        pending_path: &Path,
        app_config: AppConfig,
        net_config: NetworkConfig,
    ) -> BResult<Self> {
        // Validate configs.
        app_config.validate()?;
        net_config.validate()?;

        // Derive identity and create swarm inside a block so the
        // immutable borrow of `wallet` (via `get_keypair()`) ends
        // before `wallet` is moved into `NodeRuntime`.
        let (node_id, pending_enc_key, network, network_rx) = {
            let keypair = wallet.get_keypair()?;
            let public_key = keypair.public_key();
            let node_id = NodeId::new(*public_key.as_bytes());
            let address = pubkey_to_address(&public_key);
            let pending_enc_key: [u8; 32] = *address.as_bytes();

            // Create network swarm (consumes the keypair reference).
            let (network, network_rx) = BitevachatSwarm::new(
                net_config.clone(),
                keypair,
            ).await?;

            (node_id, pending_enc_key, network, network_rx)
        };
        // `wallet` is no longer borrowed here.

        // Open pending queue.
        let pending_queue = Arc::new(PendingQueue::open(
            pending_path,
            &pending_enc_key,
            app_config.pending_max,
            PENDING_GLOBAL_MAX,
            BACKOFF_CAP_SECS,
        )?);

        // Create channels.
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_SIZE);
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_SIZE);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let listen_addr = net_config.listen_addr.clone();

        let runtime = NodeRuntime {
            wallet,
            storage,
            network,
            network_rx,
            pending_queue,
            config: app_config,
            node_id,
            listen_addr,
            event_tx,
            command_rx,
            shutdown_rx,
            pending_tick_secs: PENDING_TICK_SECS,
            maintenance_tick_secs: MAINTENANCE_TICK_SECS,
        };

        Ok(Self {
            state: NodeState::Initializing,
            runtime: Some(runtime),
            command_tx,
            event_rx: Some(event_rx),
            shutdown_tx,
            task_handle: None,
        })
    }

    /// Starts the event loop in a new tokio task.
    ///
    /// Transitions `Initializing → Running`. Returns a `JoinHandle`
    /// that resolves when the event loop exits (after shutdown).
    ///
    /// # Errors
    ///
    /// - `BitevachatError::ConfigError` if the node is not in
    ///   `Initializing` state (prevents double-start).
    pub fn start(&mut self) -> BResult<JoinHandle<()>> {
        if self.state != NodeState::Initializing {
            return Err(BitevachatError::ConfigError {
                reason: format!(
                    "cannot start node in state '{}'; expected 'initializing'",
                    self.state,
                ),
            });
        }

        let runtime = self.runtime.take().ok_or_else(|| {
            BitevachatError::ConfigError {
                reason: "runtime already consumed (double start?)".into(),
            }
        })?;

        let handle = tokio::spawn(async move {
            event_loop::run_event_loop(runtime).await;
        });

        self.state = NodeState::Running;
        self.task_handle = Some(handle);

        // Return a clone-handle for the caller. We can't clone
        // JoinHandle, so we return the original and store None.
        // Instead, the caller owns the handle and can await it.
        // Re-design: we take and return. Store a separate handle
        // for shutdown to await.

        // Actually, we need to keep the handle for shutdown().
        // Return a notification instead. Let's use the watch channel.
        // The caller awaits shutdown_tx being set.

        // Simplest: return the task handle directly. shutdown()
        // signals via watch and the caller awaits the handle.
        let handle = self.task_handle.take().ok_or_else(|| {
            BitevachatError::ConfigError {
                reason: "task handle missing after spawn".into(),
            }
        })?;

        Ok(handle)
    }

    /// Initiates graceful shutdown.
    ///
    /// Signals the event loop to exit. The event loop will:
    /// 1. Stop accepting new commands.
    /// 2. Flush pending storage writes.
    /// 3. Close network connections.
    /// 4. Exit the task.
    ///
    /// Await the `JoinHandle` returned by [`start`](Self::start) to
    /// wait for completion.
    ///
    /// # Errors
    ///
    /// - `BitevachatError::ConfigError` if the node is in
    ///   `Initializing` state (nothing to shut down).
    pub fn shutdown(&mut self) -> BResult<()> {
        if self.state == NodeState::Initializing {
            return Err(BitevachatError::ConfigError {
                reason: "cannot shutdown a node that has not been started".into(),
            });
        }

        if self.state == NodeState::ShuttingDown {
            // Already shutting down — idempotent.
            return Ok(());
        }

        self.state = NodeState::ShuttingDown;

        // Signal the event loop to exit.
        let _ = self.shutdown_tx.send(true);

        Ok(())
    }

    /// Returns a sender for submitting commands to the node.
    ///
    /// The sender is cloneable — multiple RPC handlers can hold
    /// copies.
    pub fn command_sender(&self) -> mpsc::Sender<NodeCommand> {
        self.command_tx.clone()
    }

    /// Takes the event receiver (can only be called once).
    ///
    /// Returns `None` if already taken. The receiver delivers
    /// [`NodeEvent`]s from the event loop.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.event_rx.take()
    }

    /// Returns the current lifecycle state.
    pub fn state(&self) -> NodeState {
        self.state
    }
}