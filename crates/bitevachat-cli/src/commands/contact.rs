//! Contact commands: add, list, block, unblock.

use clap::Subcommand;

use crate::output;
use crate::rpc_client::RpcClient;
use crate::GlobalOpts;

#[derive(Subcommand)]
pub enum ContactAction {
    /// Add or update a contact alias.
    Add {
        /// Contact address (64 hex chars).
        address: String,
        /// Human-readable alias.
        #[arg(default_value = "")]
        alias: String,
    },
    /// List all contacts.
    List,
    /// Block an address.
    Block {
        /// Address to block (64 hex chars).
        address: String,
    },
    /// Unblock a previously blocked address.
    Unblock {
        /// Address to unblock (64 hex chars).
        address: String,
    },
}

pub async fn run(action: ContactAction, opts: &GlobalOpts) -> std::result::Result<(), String> {
    match action {
        ContactAction::Add { address, alias } => add(opts, &address, &alias).await,
        ContactAction::List => list(opts).await,
        ContactAction::Block { address } => block(opts, &address).await,
        ContactAction::Unblock { address } => unblock(opts, &address).await,
    }
}

async fn add(opts: &GlobalOpts, address: &str, alias: &str) -> std::result::Result<(), String> {
    output::validate_address(address)?;
    let alias = output::sanitize_alias(alias);

    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    client.add_contact(address, &alias).await?;

    let label = if alias.is_empty() {
        address.to_string()
    } else {
        format!("{alias} ({address})")
    };
    output::print_success(&format!("contact added: {label}"), opts.json);
    Ok(())
}

async fn list(opts: &GlobalOpts) -> std::result::Result<(), String> {
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.list_contacts().await?;

    if opts.json {
        let arr: Vec<serde_json::Value> = resp
            .contacts
            .iter()
            .map(|c| {
                serde_json::json!({
                    "address": c.address,
                    "alias": c.alias,
                    "blocked": c.blocked,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
    } else {
        let headers = &["ADDRESS", "ALIAS", "BLOCKED"];
        let rows: Vec<Vec<String>> = resp
            .contacts
            .iter()
            .map(|c| {
                vec![
                    c.address.clone(),
                    if c.alias.is_empty() {
                        "-".into()
                    } else {
                        c.alias.clone()
                    },
                    if c.blocked {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                ]
            })
            .collect();
        output::print_table(headers, &rows, false);
    }

    Ok(())
}

async fn block(opts: &GlobalOpts, address: &str) -> std::result::Result<(), String> {
    output::validate_address(address)?;
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    client.block_contact(address).await?;
    output::print_success(&format!("blocked {address}"), opts.json);
    Ok(())
}

async fn unblock(opts: &GlobalOpts, address: &str) -> std::result::Result<(), String> {
    output::validate_address(address)?;
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    client.unblock_contact(address).await?;
    output::print_success(&format!("unblocked {address}"), opts.json);
    Ok(())
}