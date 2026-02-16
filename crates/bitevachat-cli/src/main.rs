//! Bitevachat CLI client.
//!
//! Communicates with a running Bitevachat node via gRPC.

mod commands;
mod interactive;
mod output;
mod proto;
mod rpc_client;

use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Bitevachat — decentralized encrypted chat.
#[derive(Parser)]
#[command(name = "bitevachat", version, about)]
struct Cli {
    /// Output in JSON format (no colors, machine-readable).
    #[arg(long, global = true)]
    json: bool,

    /// gRPC endpoint of the Bitevachat node.
    #[arg(
        long,
        global = true,
        default_value = "http://127.0.0.1:50051"
    )]
    rpc_endpoint: String,

    /// Connection timeout in seconds.
    #[arg(long, global = true, default_value = "5")]
    timeout: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send and query messages.
    #[command(alias = "msg")]
    Message {
        #[command(subcommand)]
        action: commands::message::MessageAction,
    },
    /// Manage contacts.
    Contact {
        #[command(subcommand)]
        action: commands::contact::ContactAction,
    },
    /// Node operations and status.
    Node {
        #[command(subcommand)]
        action: commands::node::NodeAction,
    },
    /// Profile management.
    Profile {
        #[command(subcommand)]
        action: commands::profile::ProfileAction,
    },
    /// Wallet information (limited — most operations require local access).
    Wallet {
        #[command(subcommand)]
        action: commands::wallet::WalletAction,
    },
    /// Interactive chat mode (REPL).
    Interactive,
}

// ---------------------------------------------------------------------------
// Global options passed to every command handler
// ---------------------------------------------------------------------------

/// Shared options threaded into command handlers.
pub struct GlobalOpts {
    pub json: bool,
    pub rpc_endpoint: String,
    pub timeout_secs: u64,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let opts = GlobalOpts {
        json: cli.json,
        rpc_endpoint: cli.rpc_endpoint,
        timeout_secs: cli.timeout,
    };

    let result = dispatch(opts, cli.command).await;

    if let Err(e) = result {
        output::print_error(&e, cli.json);
        std::process::exit(1);
    }
}

async fn dispatch(opts: GlobalOpts, cmd: Commands) -> std::result::Result<(), String> {
    match cmd {
        Commands::Message { action } => commands::message::run(action, &opts).await,
        Commands::Contact { action } => commands::contact::run(action, &opts).await,
        Commands::Node { action } => commands::node::run(action, &opts).await,
        Commands::Profile { action } => commands::profile::run(action, &opts).await,
        Commands::Wallet { action } => commands::wallet::run(action, &opts).await,
        Commands::Interactive => interactive::run(&opts).await,
    }
}