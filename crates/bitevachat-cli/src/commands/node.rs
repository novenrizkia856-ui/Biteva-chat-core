//! Node commands: status, peers, shutdown.

use clap::Subcommand;

use crate::output;
use crate::rpc_client::RpcClient;
use crate::GlobalOpts;

#[derive(Subcommand)]
pub enum NodeAction {
    /// Show node status.
    Status,
    /// List connected peers.
    Peers,
    /// Shut down the node gracefully.
    Shutdown,
}

pub async fn run(action: NodeAction, opts: &GlobalOpts) -> std::result::Result<(), String> {
    match action {
        NodeAction::Status => status(opts).await,
        NodeAction::Peers => peers(opts).await,
        NodeAction::Shutdown => shutdown(opts).await,
    }
}

async fn status(opts: &GlobalOpts) -> std::result::Result<(), String> {
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.get_status().await?;

    if opts.json {
        let obj = serde_json::json!({
            "state": resp.state,
            "address": resp.address,
            "peer_id": resp.peer_id,
            "node_id": resp.node_id,
            "listeners": resp.listeners,
            "pending_count": resp.pending_count,
        });
        println!("{obj}");
    } else {
        output::print_kv("State", &resp.state, false);
        output::print_kv("Address", &resp.address, false);
        output::print_kv("Peer ID", &resp.peer_id, false);
        output::print_kv("Node ID", &resp.node_id, false);
        output::print_kv(
            "Listeners",
            &resp.listeners.join(", "),
            false,
        );
        output::print_kv(
            "Pending",
            &resp.pending_count.to_string(),
            false,
        );
    }

    Ok(())
}

async fn peers(opts: &GlobalOpts) -> std::result::Result<(), String> {
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    let resp = client.list_peers().await?;

    if opts.json {
        let arr: Vec<serde_json::Value> = resp
            .peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "peer_id": p.peer_id,
                    "node_id": p.node_id,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
    } else {
        let headers = &["PEER_ID", "NODE_ID"];
        let rows: Vec<Vec<String>> = resp
            .peers
            .iter()
            .map(|p| vec![p.peer_id.clone(), p.node_id.clone()])
            .collect();
        output::print_table(headers, &rows, false);
    }

    Ok(())
}

async fn shutdown(opts: &GlobalOpts) -> std::result::Result<(), String> {
    let mut client = RpcClient::connect(&opts.rpc_endpoint, opts.timeout_secs).await?;
    client.shutdown().await?;
    output::print_success("node shutdown initiated", opts.json);
    Ok(())
}