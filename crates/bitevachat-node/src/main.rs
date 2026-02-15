//! Bitevachat node binary.
//!
//! Orchestrates all subsystems: wallet, storage, network, protocol, RPC.
//! Runs the main event loop that processes network events, RPC commands,
//! pending delivery retries, and maintenance tasks.

// Re-export so the binary crate compiles against the library.
use bitevachat_node as _;

fn main() {
    eprintln!("bitevachat-node: not yet implemented — awaiting network layer");
    std::process::exit(1);
}