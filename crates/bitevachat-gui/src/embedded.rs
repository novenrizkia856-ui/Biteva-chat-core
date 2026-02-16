//! Embedded node bootstrap.
//!
//! Starts the entire Bitevachat stack in-process:
//! wallet → storage → node → RPC server.
//!
//! The RPC port is auto-assigned (find first free port starting from
//! 50051) so multiple instances can run simultaneously on the same
//! machine for P2P testing.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

use bitevachat_network::config::NetworkConfig;
use bitevachat_node::node::Node;
use bitevachat_rpc::config::{RpcConfig, RpcMode};
use bitevachat_rpc::server::RpcServer;
use bitevachat_storage::engine::StorageEngine;
use bitevachat_types::config::AppConfig;
use bitevachat_wallet::wallet::Wallet;
use tokio::sync::watch;

use crate::wallet_persistence;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// First port to try for the RPC server.
const RPC_PORT_START: u16 = 50051;

/// How many ports to scan before giving up.
const RPC_PORT_SCAN_RANGE: u16 = 50;

/// Wallet file name inside the data directory.
const WALLET_FILE: &str = "wallet.json";

/// Storage sub-directory name.
const STORAGE_DIR: &str = "storage";

/// Pending queue sub-directory name.
const PENDING_DIR: &str = "pending";

/// Pending queue file name (inside PENDING_DIR).
const PENDING_FILE: &str = "queue.dat";

// ---------------------------------------------------------------------------
// BootstrapInfo
// ---------------------------------------------------------------------------

/// Returned after a successful bootstrap.
pub struct BootstrapInfo {
    /// Address the RPC server is listening on.
    pub rpc_addr: SocketAddr,
    /// Wallet address (hex, 64 chars).
    pub address: String,
    /// Formatted RPC endpoint URL for client connection.
    pub rpc_endpoint: String,
    /// Keeps the RPC server alive. Dropped on GUI exit.
    _rpc_shutdown_tx: watch::Sender<bool>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the wallet file path for a given data directory.
pub fn wallet_path(data_dir: &Path) -> PathBuf {
    data_dir.join(WALLET_FILE)
}

/// Returns `true` if a wallet file exists in the data directory.
pub fn wallet_exists_in(data_dir: &Path) -> bool {
    wallet_persistence::wallet_exists(&wallet_path(data_dir))
}

/// Bootstraps the full Bitevachat node stack.
///
/// # Parameters
///
/// - `data_dir` — root directory for wallet, storage, and pending queue.
/// - `mnemonic` — `Some(words)` for new wallet creation, `None` to
///   load an existing wallet from file.
/// - `passphrase` — encryption passphrase for the wallet.
///
/// # Flow
///
/// 1. Create data directory if needed.
/// 2. Create new wallet from mnemonic **or** load existing wallet.
/// 3. Unlock wallet with passphrase.
/// 4. Open encrypted storage engine.
/// 5. Create and start the node (network, event loop).
/// 6. Find a free port, start the gRPC server.
/// 7. Return bootstrap info for the GUI to connect.
pub async fn bootstrap_node(
    data_dir: &Path,
    mnemonic: Option<&str>,
    passphrase: &str,
) -> Result<BootstrapInfo, String> {
    // 1. Ensure directories exist.
    let storage_path = data_dir.join(STORAGE_DIR);
    let pending_dir = data_dir.join(PENDING_DIR);

    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("failed to create data directory: {e}"))?;
    std::fs::create_dir_all(&storage_path)
        .map_err(|e| format!("failed to create storage directory: {e}"))?;
    std::fs::create_dir_all(&pending_dir)
        .map_err(|e| format!("failed to create pending directory: {e}"))?;

    // PendingQueue::open expects a *file* path, not a directory.
    let pending_path = pending_dir.join(PENDING_FILE);

    // 2. Create or load wallet.
    let wp = wallet_path(data_dir);
    let mut wallet = match mnemonic {
        Some(words) => {
            tracing::info!("creating new wallet");
            let w = Wallet::create_wallet(words, passphrase)
                .map_err(|e| format!("wallet creation failed: {e}"))?;
            wallet_persistence::save_wallet(&wp, &w)
                .map_err(|e| format!("failed to save wallet: {e}"))?;
            w
        }
        None => {
            tracing::info!("loading existing wallet");
            wallet_persistence::load_wallet(&wp)?
        }
    };

    // 3. Unlock.
    wallet.unlock(passphrase)
        .map_err(|e| format!("failed to unlock wallet: {e}"))?;

    let address = wallet.address().to_string();
    tracing::info!(address = %address, "wallet unlocked");

    // 4. Open storage (public key bytes = encryption key).
    let storage = StorageEngine::open(&storage_path, wallet.public_key())
        .map_err(|e| format!("failed to open storage: {e}"))?;

    // 5. Create and start node.
    let app_config = AppConfig::default();
    let net_config = NetworkConfig::default();

    let mut node = Node::new(
        wallet,
        storage,
        &pending_path,
        app_config,
        net_config,
    )
    .await
    .map_err(|e| format!("node creation failed: {e}"))?;

    let command_tx = node.command_sender();

    let node_handle = node.start()
        .map_err(|e| format!("node start failed: {e}"))?;

    tracing::info!("node started");

    // 6. Find a free port and start RPC server.
    let rpc_addr = find_free_port()
        .map_err(|e| format!("no free port for RPC: {e}"))?;

    let (rpc_shutdown_tx, rpc_shutdown_rx) = watch::channel(false);

    let rpc_config = RpcConfig {
        mode: RpcMode::LocalTcp { addr: rpc_addr },
        api_token: None,
    };

    let _rpc_handle = RpcServer::start(
        rpc_config,
        command_tx,
        rpc_shutdown_rx,
    )
    .await
    .map_err(|e| format!("RPC server start failed: {e}"))?;

    let rpc_endpoint = format!("http://{}", rpc_addr);
    tracing::info!(%rpc_addr, "RPC server started");

    // Hold the node task handle in background.
    tokio::spawn(async move {
        let _ = node_handle.await;
        tracing::info!("node event loop exited");
    });

    // 7. Return info.
    Ok(BootstrapInfo {
        rpc_addr,
        address,
        rpc_endpoint,
        _rpc_shutdown_tx: rpc_shutdown_tx,
    })
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

/// Finds a free TCP port on localhost, starting from `RPC_PORT_START`.
///
/// Binds a TcpListener to each candidate port. If binding succeeds,
/// the listener is dropped (freeing the port) and the port number is
/// returned. There is a tiny TOCTOU window, but for a local dev tool
/// this is acceptable.
fn find_free_port() -> Result<SocketAddr, String> {
    for port in RPC_PORT_START..RPC_PORT_START + RPC_PORT_SCAN_RANGE {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        if TcpListener::bind(addr).is_ok() {
            return Ok(addr);
        }
    }
    Err(format!(
        "no free port found in range {}..{}",
        RPC_PORT_START,
        RPC_PORT_START + RPC_PORT_SCAN_RANGE,
    ))
}

// ---------------------------------------------------------------------------
// Platform-specific data directory
// ---------------------------------------------------------------------------

/// Returns the default data directory for the current platform.
///
/// - **Windows**: `%APPDATA%\Bitevachat`
/// - **Linux**: `$HOME/.bitevachat`
/// - **macOS**: `$HOME/Library/Application Support/Bitevachat`
pub fn default_data_dir() -> PathBuf {
    if cfg!(target_os = "linux") {
        if let Some(home) = dirs::home_dir() {
            return home.join(".bitevachat");
        }
    }

    if let Some(data) = dirs::data_dir() {
        return data.join("Bitevachat");
    }

    PathBuf::from("bitevachat-data")
}