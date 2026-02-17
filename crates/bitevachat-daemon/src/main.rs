//! Bitevachat Daemon -- headless node for servers and VPS.
//!
//! Usage:
//!
//!   bitevachat-daemon [OPTIONS]
//!
//! Options:
//!
//!   --data-dir <PATH>       Data directory (default: platform-specific)
//!   --listen <MULTIADDR>    P2P listen address (default: /ip4/0.0.0.0/tcp/9000)
//!   --rpc-port <PORT>       gRPC listen port (default: 50051)
//!   --relay-server          Enable relay server mode (for public nodes)
//!   --bootstrap <MULTIADDR> Add a bootstrap node (repeatable)
//!   --new-wallet            Create a new wallet on first run
//!   --config <PATH>         Load config from JSON file
//!
//! Environment:
//!
//!   BITEVACHAT_PASSPHRASE   Wallet passphrase (avoids interactive prompt)
//!
//! The daemon runs until interrupted with Ctrl+C (SIGINT/SIGTERM).

use std::net::SocketAddr;
use std::path::PathBuf;

use libp2p::Multiaddr;

use bitevachat_network::config::NetworkConfig;
use bitevachat_node::node::Node;
use bitevachat_rpc::config::{RpcConfig, RpcMode};
use bitevachat_rpc::server::RpcServer;
use bitevachat_storage::engine::StorageEngine;
use bitevachat_types::config::AppConfig;
use bitevachat_wallet::wallet::Wallet;
use tokio::sync::watch;

mod config;
mod wallet_io;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_DIR: &str = "storage";
const PENDING_DIR: &str = "pending";
const PENDING_FILE: &str = "queue.dat";
const WALLET_FILE: &str = "wallet.json";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Tracing / logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    print_banner();

    // Parse CLI arguments.
    let cli = config::CliArgs::parse_from_env();

    // Load or merge config file if provided.
    let daemon_config = match &cli.config_path {
        Some(path) => match config::DaemonConfig::load(path) {
            Ok(cfg) => cfg.merge_cli(&cli),
            Err(e) => {
                tracing::error!("failed to load config file: {e}");
                std::process::exit(1);
            }
        },
        None => config::DaemonConfig::from_cli(&cli),
    };

    // Run the daemon.
    if let Err(e) = run_daemon(daemon_config).await {
        tracing::error!("daemon error: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Daemon main logic
// ---------------------------------------------------------------------------

async fn run_daemon(cfg: config::DaemonConfig) -> Result<(), String> {
    let data_dir = &cfg.data_dir;

    // Ensure directories exist.
    let storage_path = data_dir.join(STORAGE_DIR);
    let pending_dir = data_dir.join(PENDING_DIR);
    let pending_path = pending_dir.join(PENDING_FILE);
    let wallet_path = data_dir.join(WALLET_FILE);

    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("failed to create data directory: {e}"))?;
    std::fs::create_dir_all(&storage_path)
        .map_err(|e| format!("failed to create storage directory: {e}"))?;
    std::fs::create_dir_all(&pending_dir)
        .map_err(|e| format!("failed to create pending directory: {e}"))?;

    tracing::info!(data_dir = %data_dir.display(), "data directory ready");

    // -----------------------------------------------------------------------
    // 1. Wallet
    // -----------------------------------------------------------------------

    let passphrase = cfg.passphrase.clone().unwrap_or_else(|| {
        read_passphrase("Enter wallet passphrase: ")
    });

    let mut wallet = if cfg.new_wallet || !wallet_path.exists() {
        if wallet_path.exists() && !cfg.new_wallet {
            // Load existing (returns locked wallet).
            tracing::info!("loading existing wallet");
            wallet_io::load_wallet(&wallet_path)?
        } else {
            // Create new.
            tracing::info!("creating new wallet");
            let mut entropy = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut entropy);
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
                .map_err(|e| format!("mnemonic generation failed: {e}"))?;
            let words = mnemonic.to_string();

            println!();
            println!("============================================================");
            println!("  NEW WALLET CREATED -- SAVE YOUR MNEMONIC!");
            println!("============================================================");
            println!();
            println!("  {words}");
            println!();
            println!("  Write these words down and store them safely.");
            println!("  You will need them to recover your wallet.");
            println!("============================================================");
            println!();

            let w = Wallet::create_wallet(&words, &passphrase)
                .map_err(|e| format!("wallet creation failed: {e}"))?;
            wallet_io::save_wallet(&wallet_path, &w)?;
            w
        }
    } else {
        tracing::info!("loading existing wallet");
        wallet_io::load_wallet(&wallet_path)?
    };

    // Unlock.
    wallet.unlock(&passphrase)
        .map_err(|e| format!("failed to unlock wallet: {e}"))?;

    let address = wallet.address().to_string();
    tracing::info!(%address, "wallet unlocked");

    // -----------------------------------------------------------------------
    // 2. Storage
    // -----------------------------------------------------------------------

    let storage = StorageEngine::open(&storage_path, wallet.public_key())
        .map_err(|e| format!("failed to open storage: {e}"))?;

    tracing::info!("storage engine opened");

    // -----------------------------------------------------------------------
    // 3. Network config
    // -----------------------------------------------------------------------

    let listen_addr = cfg.listen_addr.parse::<Multiaddr>()
        .map_err(|e| format!("invalid listen address '{}': {e}", cfg.listen_addr))?;

    let bootstrap_addrs: Vec<Multiaddr> = cfg
        .bootstrap_nodes
        .iter()
        .filter_map(|s| {
            s.parse::<Multiaddr>()
                .map_err(|e| tracing::warn!("invalid bootstrap addr '{}': {e}", s))
                .ok()
        })
        .collect();

    let net_config = NetworkConfig {
        listen_addr,
        bootstrap_nodes: bootstrap_addrs,
        enable_relay_server: cfg.relay_server,
        enable_mdns: cfg.enable_mdns,
        ..NetworkConfig::default()
    };

    tracing::info!(
        listen = %cfg.listen_addr,
        relay_server = cfg.relay_server,
        mdns = cfg.enable_mdns,
        bootstrap_count = net_config.bootstrap_nodes.len(),
        "network config"
    );

    // -----------------------------------------------------------------------
    // 4. Start node
    // -----------------------------------------------------------------------

    let app_config = AppConfig::default();

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

    let mut node_handle = node.start()
        .map_err(|e| format!("node start failed: {e}"))?;

    tracing::info!("node started");

    // -----------------------------------------------------------------------
    // 5. Start RPC server
    // -----------------------------------------------------------------------

    let rpc_addr: SocketAddr = ([127, 0, 0, 1], cfg.rpc_port).into();

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

    tracing::info!(%rpc_addr, "RPC server listening");

    // -----------------------------------------------------------------------
    // 6. Print status summary
    // -----------------------------------------------------------------------

    println!();
    println!("============================================================");
    println!("  Bitevachat Daemon running");
    println!("============================================================");
    println!("  Address:      {address}");
    println!("  P2P listen:   {}", cfg.listen_addr);
    println!("  RPC listen:   {rpc_addr}");
    println!("  Relay server: {}", if cfg.relay_server { "enabled" } else { "disabled" });
    println!("  mDNS:         {}", if cfg.enable_mdns { "enabled" } else { "disabled" });
    println!("  Data dir:     {}", cfg.data_dir.display());
    println!("============================================================");
    println!("  Press Ctrl+C to stop");
    println!("============================================================");
    println!();

    // -----------------------------------------------------------------------
    // 7. Wait for shutdown signal
    // -----------------------------------------------------------------------

    // IMPORTANT: `node` must stay alive here. If dropped, the
    // command channel closes and the event loop may exit.
    let _node = node;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, shutting down...");
                break;
            }
            result = &mut node_handle => {
                match result {
                    Ok(()) => {
                        tracing::error!("node event loop exited unexpectedly (no error)");
                        eprintln!();
                        eprintln!("[ERROR] Node event loop stopped unexpectedly.");
                        eprintln!("        Check the logs above for errors.");
                    }
                    Err(e) => {
                        tracing::error!(%e, "node event loop panicked");
                        eprintln!();
                        eprintln!("[ERROR] Node event loop panicked: {e}");
                    }
                }
                // Don't exit immediately -- give user time to read.
                eprintln!("        Shutting down in 5 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                break;
            }
        }
    }

    // Signal RPC server to stop.
    let _ = rpc_shutdown_tx.send(true);

    // Brief grace period for in-flight requests.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    tracing::info!("daemon stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_passphrase(prompt: &str) -> String {
    // Try env var first (for non-interactive / CI usage).
    if let Ok(pass) = std::env::var("BITEVACHAT_PASSPHRASE") {
        return pass;
    }

    // Interactive prompt (simple, no echo hiding).
    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read passphrase");
    input.trim().to_string()
}

fn print_banner() {
    println!(r#"
  ____  _ _                       _           _
 | __ )(_) |_ _____   ____ _  ___| |__   __ _| |_
 |  _ \| | __/ _ \ \ / / _` |/ __| '_ \ / _` | __|
 | |_) | | ||  __/\ V / (_| | (__| | | | (_| | |_
 |____/|_|\__\___| \_/ \__,_|\___|_| |_|\__,_|\__|
                                    daemon v{}
"#, env!("CARGO_PKG_VERSION"));
}