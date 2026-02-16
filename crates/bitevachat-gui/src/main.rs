//! Bitevachat Desktop GUI entry point.
//!
//! Architecture:
//!
//! ```text
//!                          ┌──────────────────────────────────────────┐
//!                          │         tokio runtime (bg thread)        │
//!                          │                                         │
//!  ┌──────────────┐  cmd   │  ┌───────────┐    ┌──────────────────┐  │
//!  │  eframe UI   │ ─────▶ │  │ RPC bridge │───▶│  embedded node   │  │
//!  │ (main thread) │ ◀───── │  │            │    │  + RPC server    │  │
//!  └──────────────┘  evt   │  └───────────┘    └──────────────────┘  │
//!                          └──────────────────────────────────────────┘
//! ```
//!
//! 1. User completes onboarding (create/import wallet or unlock).
//! 2. Bridge receives BootstrapNode → starts wallet, storage, node, RPC.
//! 3. Bridge auto-connects to embedded RPC as a gRPC client.
//! 4. GUI is fully operational — chat, contacts, profile, settings.

use eframe::egui;

use bitevachat_gui::app;
use bitevachat_gui::rpc_bridge;

fn main() {
    // Initialize tracing (logs to stderr).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tracing::info!("Bitevachat GUI starting");

    // Create bounded channels for UI ↔ bridge communication.
    let (cmd_tx, cmd_rx, evt_tx, evt_rx) = rpc_bridge::create_channels();

    // Spawn the tokio runtime in a dedicated background thread.
    // This thread owns the runtime and runs the RPC bridge + embedded node.
    // It exits when the UI drops cmd_tx on window close.
    std::thread::Builder::new()
        .name("bitevachat-runtime".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .thread_name("bitevachat-worker")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("failed to create tokio runtime: {e}");
                    return;
                }
            };

            rt.block_on(rpc_bridge::run_bridge(cmd_rx, evt_tx));
            tracing::info!("RPC bridge exited");
        })
        .ok();

    // Configure eframe window.
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Bitevachat")
            .with_inner_size([1024.0, 720.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };

    // Run the eframe app on the main thread (blocks until window closed).
    let result = eframe::run_native(
        "Bitevachat",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(app::BitevachatApp::new(cc, cmd_tx, evt_rx)))
        }),
    );

    if let Err(e) = result {
        tracing::error!("eframe error: {e}");
    }

    tracing::info!("Bitevachat GUI exited");
}