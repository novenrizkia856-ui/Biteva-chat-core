//! Message commands: send, list, get.

use clap::Subcommand;

use crate::output;
use crate::rpc_client::RpcClient;
use crate::GlobalOpts;

#[derive(Subcommand)]
pub enum MessageAction {
    /// Send a message to an address.
    Send {
        /// Recipient address (64 hex chars).
        address: String,
        /// Message text.
        text: String,
    },
    /// List messages in a conversation.
    List {
        /// Conversation ID (64 hex chars) or peer address.
        convo_id: String,
        /// Maximum messages to return.
        #[arg(long, default_value = "50")]
        limit: u64,
        /// Pagination offset.
        #[arg(long, default_value = "0")]
        offset: u64,
    },
    /// Retrieve a single message by ID.
    Get {
        /// Message ID (64 hex chars).
        message_id: String,
    },
}

pub async fn run(action: MessageAction, opts: &GlobalOpts) -> std::result::Result<(), String> {
    match action {
        MessageAction::Send { address, text } => send(opts, &address, &text).await,
        MessageAction::List { convo_id, limit, offset } => {
            list(opts, &convo_id, limit, offset).await
        }
        MessageAction::Get { message_id } => get(opts, &message_id).await,
    }
}

async fn send(opts: &GlobalOpts, address: &str, text: &str) -> std::result::Result<(), String> {
    output::validate_address(address)?;

    if text.is_empty() {
        return Err("message text cannot be empty".into());
    }

    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;

    // NOTE: In a real implementation the CLI would perform E2E
    // encryption before sending. For now we send plaintext and a
    // zeroed shared_key, assuming the node or a future key-exchange
    // step handles encryption.
    let resp = client
        .send_message(address, text.as_bytes().to_vec(), "text", vec![0u8; 32])
        .await?;

    if opts.json {
        let obj = serde_json::json!({
            "status": "sent",
            "message_id": resp.message_id,
        });
        println!("{obj}");
    } else {
        output::print_success(
            &format!("message sent (id: {})", truncate_id(&resp.message_id)),
            false,
        );
    }

    Ok(())
}

async fn list(
    opts: &GlobalOpts,
    convo_id: &str,
    limit: u64,
    offset: u64,
) -> std::result::Result<(), String> {
    output::validate_address(convo_id)?;

    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.list_messages(convo_id, limit, offset).await?;

    if opts.json {
        let arr: Vec<serde_json::Value> = resp
            .messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "message_id": m.message_id,
                    "sender": m.sender,
                    "recipient": m.recipient,
                    "timestamp": m.timestamp,
                    "payload_type": m.payload_type,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
    } else {
        let headers = &["ID", "FROM", "TO", "TIME", "TYPE"];
        let rows: Vec<Vec<String>> = resp
            .messages
            .iter()
            .map(|m| {
                vec![
                    truncate_id(&m.message_id),
                    truncate_id(&m.sender),
                    truncate_id(&m.recipient),
                    m.timestamp.clone(),
                    m.payload_type.clone(),
                ]
            })
            .collect();
        output::print_table(headers, &rows, false);
    }

    Ok(())
}

async fn get(opts: &GlobalOpts, message_id: &str) -> std::result::Result<(), String> {
    output::validate_message_id(message_id)?;

    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.get_message(message_id).await?;

    match resp.message {
        Some(m) => {
            let obj = serde_json::json!({
                "message_id": m.message_id,
                "sender": m.sender,
                "recipient": m.recipient,
                "timestamp": m.timestamp,
                "payload_type": m.payload_type,
                "payload_size": m.payload_ciphertext.len(),
            });
            output::print_json_value(&obj, opts.json);
        }
        None => {
            if opts.json {
                println!("{{\"found\":false}}");
            } else {
                output::print_error("message not found", false);
            }
        }
    }

    Ok(())
}

/// Truncates a hex ID to first 12 chars + "…" for display.
fn truncate_id(id: &str) -> String {
    if id.len() > 16 {
        format!("{}...", &id[..12])
    } else {
        id.to_string()
    }
}