//! Profile commands: get, update.

use clap::Subcommand;

use crate::output;
use crate::rpc_client::RpcClient;
use crate::GlobalOpts;

#[derive(Subcommand)]
pub enum ProfileAction {
    /// Retrieve a profile by address.
    Get {
        /// Address (64 hex chars). Omit to get own profile.
        #[arg(default_value = "")]
        address: String,
    },
    /// Update your profile.
    Update {
        /// Display name.
        #[arg(long)]
        name: Option<String>,
        /// Bio text.
        #[arg(long)]
        bio: Option<String>,
        /// Path to avatar image file.
        #[arg(long)]
        avatar: Option<String>,
        /// Remove current avatar.
        #[arg(long)]
        remove_avatar: bool,
    },
}

pub async fn run(action: ProfileAction, opts: &GlobalOpts) -> std::result::Result<(), String> {
    match action {
        ProfileAction::Get { address } => get(opts, &address).await,
        ProfileAction::Update {
            name,
            bio,
            avatar,
            remove_avatar,
        } => update(opts, name, bio, avatar, remove_avatar).await,
    }
}

async fn get(opts: &GlobalOpts, address: &str) -> std::result::Result<(), String> {
    // If address is empty, fetch own profile via node status first.
    let target_address = if address.is_empty() {
        let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
        let status = client.get_status().await?;
        status.address
    } else {
        output::validate_address(address)?;
        address.to_string()
    };

    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.get_profile(&target_address).await?;

    if !resp.found {
        if opts.json {
            println!("{{\"found\":false}}");
        } else {
            output::print_error("profile not found", false);
        }
        return Ok(());
    }

    match resp.profile {
        Some(p) => {
            let obj = serde_json::json!({
                "address": p.address,
                "name": p.name,
                "bio": p.bio,
                "avatar_cid": p.avatar_cid,
                "timestamp": p.timestamp,
                "version": p.version,
            });
            output::print_json_value(&obj, opts.json);
        }
        None => {
            if opts.json {
                println!("{{\"found\":false}}");
            } else {
                output::print_error("profile data missing", false);
            }
        }
    }

    Ok(())
}

async fn update(
    opts: &GlobalOpts,
    name: Option<String>,
    bio: Option<String>,
    avatar_path: Option<String>,
    remove_avatar: bool,
) -> std::result::Result<(), String> {
    let name = name.unwrap_or_default();
    let bio = bio.unwrap_or_default();

    // Read avatar file if provided.
    let avatar_bytes = match avatar_path {
        Some(path) => {
            tokio::task::spawn_blocking(move || std::fs::read(&path))
                .await
                .map_err(|e| format!("failed to spawn blocking task: {e}"))?
                .map_err(|e| format!("failed to read avatar file: {e}"))?
        }
        None => Vec::new(),
    };

    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client
        .update_profile(&name, &bio, avatar_bytes, remove_avatar)
        .await?;

    if opts.json {
        let obj = serde_json::json!({
            "status": "updated",
            "avatar_cid": resp.avatar_cid,
            "version": resp.version,
        });
        println!("{obj}");
    } else {
        output::print_success(
            &format!("profile updated (version {})", resp.version),
            false,
        );
        if !resp.avatar_cid.is_empty() {
            output::print_kv("Avatar CID", &resp.avatar_cid, false);
        }
    }

    Ok(())
}