//! Wallet commands.
//!
//! Most wallet operations (create, unlock, lock, backup, import)
//! require direct local access to the wallet file and cannot be
//! performed over RPC. Only `wallet address` is available remotely
//! (derived from the node status).

use clap::Subcommand;

use crate::output;
use crate::rpc_client::RpcClient;
use crate::GlobalOpts;

#[derive(Subcommand)]
pub enum WalletAction {
    /// Show the wallet address of the connected node.
    Address,
    /// Create a new wallet (requires local node access).
    Create,
    /// Unlock the wallet (requires local node access).
    Unlock,
    /// Lock the wallet (requires local node access).
    Lock,
    /// Show mnemonic backup (requires local node access).
    Backup,
    /// Import wallet from mnemonic (requires local node access).
    Import,
}

pub async fn run(action: WalletAction, opts: &GlobalOpts) -> std::result::Result<(), String> {
    match action {
        WalletAction::Address => address(opts).await,
        WalletAction::Create
        | WalletAction::Unlock
        | WalletAction::Lock
        | WalletAction::Backup
        | WalletAction::Import => {
            let name = match action {
                WalletAction::Create => "create",
                WalletAction::Unlock => "unlock",
                WalletAction::Lock => "lock",
                WalletAction::Backup => "backup",
                WalletAction::Import => "import",
                _ => "unknown",
            };
            Err(format!(
                "'wallet {name}' requires local access to the wallet file. \
                 This command is not available over RPC. \
                 Use the node's local CLI or API directly."
            ))
        }
    }
}

async fn address(opts: &GlobalOpts) -> std::result::Result<(), String> {
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.get_status().await?;

    if opts.json {
        let obj = serde_json::json!({ "address": resp.address });
        println!("{obj}");
    } else {
        output::print_kv("Address", &resp.address, false);
    }

    Ok(())
}