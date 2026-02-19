//! CLI argument parsing and config file support.
//!
//! The daemon can be configured via CLI flags, a JSON config file,
//! or a combination of both (CLI overrides config file).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CLI arguments (manual parsing, no clap dependency)
// ---------------------------------------------------------------------------

/// Parsed command-line arguments.
pub struct CliArgs {
    pub data_dir: Option<PathBuf>,
    pub listen_addr: Option<String>,
    pub rpc_port: Option<u16>,
    pub relay_server: bool,
    pub enable_mdns: Option<bool>,
    pub bootstrap_nodes: Vec<String>,
    pub new_wallet: bool,
    pub passphrase: Option<String>,
    pub config_path: Option<PathBuf>,
}

impl CliArgs {
    /// Parses CLI arguments from `std::env::args`.
    pub fn parse_from_env() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut cli = Self {
            data_dir: None,
            listen_addr: None,
            rpc_port: None,
            relay_server: true,
            enable_mdns: None,
            bootstrap_nodes: Vec::new(),
            new_wallet: false,
            passphrase: None,
            config_path: None,
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--data-dir" => {
                    i += 1;
                    cli.data_dir = args.get(i).map(PathBuf::from);
                }
                "--listen" => {
                    i += 1;
                    cli.listen_addr = args.get(i).cloned();
                }
                "--rpc-port" => {
                    i += 1;
                    cli.rpc_port = args.get(i).and_then(|s| s.parse().ok());
                }
                "--relay-server" => {
                    cli.relay_server = true;
                }
                "--no-mdns" => {
                    cli.enable_mdns = Some(false);
                }
                "--bootstrap" => {
                    i += 1;
                    if let Some(addr) = args.get(i) {
                        cli.bootstrap_nodes.push(addr.clone());
                    }
                }
                "--new-wallet" => {
                    cli.new_wallet = true;
                }
                "--passphrase" => {
                    i += 1;
                    cli.passphrase = args.get(i).cloned();
                }
                "--config" => {
                    i += 1;
                    cli.config_path = args.get(i).map(PathBuf::from);
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown argument: {other}");
                    eprintln!("use --help for usage information");
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        cli
    }
}

// ---------------------------------------------------------------------------
// Config file (JSON)
// ---------------------------------------------------------------------------

/// JSON config file format.
///
/// Example `daemon.json`:
/// ```json
/// {
///   "data_dir": "/opt/bitevachat/data",
///   "listen_addr": "/ip4/0.0.0.0/tcp/9000",
///   "rpc_port": 50051,
///   "relay_server": true,
///   "enable_mdns": false,
///   "bootstrap_nodes": [
///     "/ip4/203.0.113.1/tcp/9000/p2p/12D3KooW..."
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonConfigFile {
    pub data_dir: Option<String>,
    pub listen_addr: Option<String>,
    pub rpc_port: Option<u16>,
    pub relay_server: Option<bool>,
    pub enable_mdns: Option<bool>,
    pub bootstrap_nodes: Option<Vec<String>>,
    pub passphrase: Option<String>,
}

// ---------------------------------------------------------------------------
// Resolved config (all defaults applied)
// ---------------------------------------------------------------------------

/// Fully resolved daemon configuration with all defaults applied.
pub struct DaemonConfig {
    pub data_dir: PathBuf,
    pub listen_addr: String,
    pub rpc_port: u16,
    pub relay_server: bool,
    pub enable_mdns: bool,
    pub bootstrap_nodes: Vec<String>,
    pub new_wallet: bool,
    pub passphrase: Option<String>,
}

impl DaemonConfig {
    /// Build config purely from CLI args with defaults.
    pub fn from_cli(cli: &CliArgs) -> Self {
        Self {
            data_dir: cli.data_dir.clone().unwrap_or_else(default_data_dir),
            listen_addr: cli
                .listen_addr
                .clone()
                .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/9000".into()),
            rpc_port: cli.rpc_port.unwrap_or(50051),
            relay_server: cli.relay_server,
            enable_mdns: cli.enable_mdns.unwrap_or(true),
            bootstrap_nodes: cli.bootstrap_nodes.clone(),
            new_wallet: cli.new_wallet,
            passphrase: cli.passphrase.clone(),
        }
    }

    /// Load config from a JSON file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file: {e}"))?;

        let file: DaemonConfigFile = serde_json::from_str(&text)
            .map_err(|e| format!("invalid config JSON: {e}"))?;

        Ok(Self {
            data_dir: file
                .data_dir
                .map(PathBuf::from)
                .unwrap_or_else(default_data_dir),
            listen_addr: file
                .listen_addr
                .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/9000".into()),
            rpc_port: file.rpc_port.unwrap_or(50051),
            relay_server: file.relay_server.unwrap_or(false),
            enable_mdns: file.enable_mdns.unwrap_or(true),
            bootstrap_nodes: file.bootstrap_nodes.unwrap_or_default(),
            new_wallet: false,
            passphrase: file.passphrase,
        })
    }

    /// Merge CLI overrides onto a config-file base.
    pub fn merge_cli(mut self, cli: &CliArgs) -> Self {
        if let Some(ref dir) = cli.data_dir {
            self.data_dir = dir.clone();
        }
        if let Some(ref addr) = cli.listen_addr {
            self.listen_addr = addr.clone();
        }
        if let Some(port) = cli.rpc_port {
            self.rpc_port = port;
        }
        if cli.relay_server {
            self.relay_server = true;
        }
        if let Some(mdns) = cli.enable_mdns {
            self.enable_mdns = mdns;
        }
        if !cli.bootstrap_nodes.is_empty() {
            self.bootstrap_nodes.extend(cli.bootstrap_nodes.clone());
        }
        if cli.new_wallet {
            self.new_wallet = true;
        }
        if cli.passphrase.is_some() {
            self.passphrase = cli.passphrase.clone();
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Platform-specific default data directory.
fn default_data_dir() -> PathBuf {
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

fn print_help() {
    println!(
        r#"Bitevachat Daemon - headless P2P chat node

USAGE:
    bitevachat-daemon [OPTIONS]

OPTIONS:
    --data-dir <PATH>        Data directory (default: platform-specific)
    --listen <MULTIADDR>     P2P listen address (default: /ip4/0.0.0.0/tcp/9000)
    --rpc-port <PORT>        gRPC listen port (default: 50051)
    --relay-server           Enable relay server mode for public nodes
    --no-mdns                Disable mDNS local discovery
    --bootstrap <MULTIADDR>  Add a bootstrap node (repeatable)
    --new-wallet             Create a new wallet on first run
    --passphrase <PASS>      Wallet passphrase (or set BITEVACHAT_PASSPHRASE)
    --config <PATH>          Load settings from JSON config file
    -h, --help               Show this help

EXAMPLES:
    # First run: create wallet, listen on port 9000
    bitevachat-daemon --new-wallet --listen /ip4/0.0.0.0/tcp/9000

    # VPS bootstrap/relay node
    bitevachat-daemon --relay-server --no-mdns --listen /ip4/0.0.0.0/tcp/9000

    # Connect to existing bootstrap
    bitevachat-daemon --bootstrap /ip4/1.2.3.4/tcp/9000/p2p/12D3KooW...

    # Use config file
    bitevachat-daemon --config /etc/bitevachat/daemon.json

ENVIRONMENT:
    BITEVACHAT_PASSPHRASE    Wallet passphrase (avoids interactive prompt)
    RUST_LOG                 Log level filter (default: info)
"#
    );
}