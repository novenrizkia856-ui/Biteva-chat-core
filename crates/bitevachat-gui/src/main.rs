//! Bitevachat Desktop GUI entry point.
//!
//! Architecture:
//!
//! ```text
//! ┌─────────────────┐       bounded mpsc        ┌─────────────────┐
//! │   eframe UI     │ ── UiCommand ──────────▶  │  tokio runtime  │
//! │   (main thread) │ ◀── UiEvent ───────────── │  (bg thread)    │
//! │                 │       bounded mpsc        │  RPC bridge     │
//! └─────────────────┘                           └─────────────────┘
//! ```
//!
//! The UI thread never blocks. The tokio runtime runs the RPC bridge
//! in a dedicated background thread.

use eframe::egui;

use bitevachat_gui::app;
use bitevachat_gui::rpc_bridge;

fn main() {
    // Create bounded channels.
    let (cmd_tx, cmd_rx, evt_tx, evt_rx) = rpc_bridge::create_channels();

    // Spawn the tokio runtime in a background thread.
    // This thread owns the runtime and runs until the bridge loop exits
    // (which happens when the UI drops cmd_tx on close).
    std::thread::Builder::new()
        .name("bitevachat-rpc".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("Failed to create tokio runtime: {e}");
                    return;
                }
            };

            rt.block_on(rpc_bridge::run_bridge(cmd_rx, evt_tx));
        })
        .ok(); // If thread spawn fails, the GUI runs without RPC.

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
        eprintln!("eframe error: {e}");
    }
}