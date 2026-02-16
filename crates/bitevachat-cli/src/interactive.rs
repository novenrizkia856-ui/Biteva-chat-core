//! Interactive REPL chat mode.
//!
//! Connects to the node, shows status, then enters a read-eval-print
//! loop that allows sending messages to a selected peer.
//!
//! # Graceful shutdown
//!
//! Handles `SIGINT` (Ctrl+C) via `tokio::signal::ctrl_c`. The loop
//! exits cleanly without panic.

use colored::Colorize;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::output;
use crate::rpc_client::RpcClient;
use crate::GlobalOpts;

pub async fn run(opts: &GlobalOpts) -> std::result::Result<(), String> {
    // Connect to the node.
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;

    // Show banner and status.
    let status = client.get_status().await?;
    if !opts.json {
        println!(
            "\n{}",
            "╔══════════════════════════════════════╗"
                .bright_cyan()
        );
        println!(
            "{}",
            "║     Bitevachat Interactive Mode      ║"
                .bright_cyan()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════╝"
                .bright_cyan()
        );
        println!(
            "  Node:    {}",
            status.state.green()
        );
        println!(
            "  Address: {}",
            truncate_hex(&status.address, 16)
        );
        println!(
            "  Peers:   query with {}",
            "/peers".bold()
        );
        println!();
        println!(
            "Commands: {} {} {} {}",
            "/to <address>".bold(),
            "/status".bold(),
            "/peers".bold(),
            "/quit".bold(),
        );
        println!();
    }

    // REPL state.
    let mut current_recipient: Option<String> = None;
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    loop {
        // Print prompt.
        if !opts.json {
            let label = current_recipient
                .as_deref()
                .map(|a| truncate_hex(a, 8))
                .unwrap_or_else(|| "(no recipient)".dimmed().to_string());
            eprint!("{} > ", label);
        }

        // Read a line — race with Ctrl+C.
        let line = tokio::select! {
            result = lines.next_line() => {
                match result {
                    Ok(Some(line)) => line,
                    Ok(None) => {
                        // EOF (stdin closed).
                        break;
                    }
                    Err(e) => {
                        output::print_error(
                            &format!("failed to read input: {e}"),
                            opts.json,
                        );
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                if !opts.json {
                    println!("\n{}", "Exiting interactive mode.".dimmed());
                }
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Handle slash commands.
        if trimmed.starts_with('/') {
            match handle_slash_command(trimmed, &mut client, opts, &mut current_recipient).await {
                SlashResult::Continue => continue,
                SlashResult::Quit => break,
            }
        }

        // Send message to current recipient.
        let recipient = match &current_recipient {
            Some(r) => r.clone(),
            None => {
                output::print_error(
                    "no recipient set — use /to <address> first",
                    opts.json,
                );
                continue;
            }
        };

        match client
            .send_message(&recipient, trimmed.as_bytes().to_vec(), "text", vec![0u8; 32])
            .await
        {
            Ok(resp) => {
                if opts.json {
                    let obj = serde_json::json!({
                        "status": "sent",
                        "message_id": resp.message_id,
                    });
                    println!("{obj}");
                } else {
                    println!(
                        "  {} ({})",
                        "sent".green(),
                        truncate_hex(&resp.message_id, 8),
                    );
                }
            }
            Err(e) => {
                output::print_error(&e, opts.json);
            }
        }
    }

    if !opts.json {
        println!("{}", "Goodbye.".dimmed());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Slash commands
// ---------------------------------------------------------------------------

enum SlashResult {
    Continue,
    Quit,
}

async fn handle_slash_command(
    input: &str,
    client: &mut RpcClient,
    opts: &GlobalOpts,
    current_recipient: &mut Option<String>,
) -> SlashResult {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let cmd = parts[0];
    let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

    match cmd {
        "/quit" | "/exit" | "/q" => {
            return SlashResult::Quit;
        }

        "/to" => {
            if arg.is_empty() {
                output::print_error("usage: /to <address>", opts.json);
                return SlashResult::Continue;
            }
            if let Err(e) = output::validate_address(arg) {
                output::print_error(&e, opts.json);
                return SlashResult::Continue;
            }
            *current_recipient = Some(arg.to_string());
            if !opts.json {
                println!(
                    "  {} {}",
                    "recipient set:".green(),
                    truncate_hex(arg, 16),
                );
            }
        }

        "/status" => match client.get_status().await {
            Ok(resp) => {
                if opts.json {
                    let obj = serde_json::json!({
                        "state": resp.state,
                        "pending_count": resp.pending_count,
                    });
                    println!("{obj}");
                } else {
                    output::print_kv("State", &resp.state, false);
                    output::print_kv(
                        "Pending",
                        &resp.pending_count.to_string(),
                        false,
                    );
                }
            }
            Err(e) => {
                output::print_error(&e, opts.json);
            }
        },

        "/peers" => match client.list_peers().await {
            Ok(resp) => {
                if opts.json {
                    let arr: Vec<serde_json::Value> = resp
                        .peers
                        .iter()
                        .map(|p| serde_json::json!({ "peer_id": p.peer_id }))
                        .collect();
                    println!("{}", serde_json::Value::Array(arr));
                } else if resp.peers.is_empty() {
                    println!("  {}", "(no peers connected)".dimmed());
                } else {
                    for p in &resp.peers {
                        println!("  - {}", p.peer_id);
                    }
                }
            }
            Err(e) => {
                output::print_error(&e, opts.json);
            }
        },

        "/help" => {
            if !opts.json {
                println!("  /to <address>  — set message recipient");
                println!("  /status        — show node status");
                println!("  /peers         — list connected peers");
                println!("  /quit          — exit interactive mode");
            }
        }

        _ => {
            output::print_error(
                &format!("unknown command '{cmd}' — type /help"),
                opts.json,
            );
        }
    }

    SlashResult::Continue
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn truncate_hex(s: &str, max: usize) -> String {
    if s.len() > max + 3 {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}