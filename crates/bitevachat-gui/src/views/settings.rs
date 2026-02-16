//! Settings panel: retention, encryption, network, relay, passphrase, backup.

use eframe::egui;

use crate::theme;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct SettingsState {
    /// Data directory path.
    pub data_dir: String,
    /// RPC endpoint.
    pub rpc_endpoint: String,
    /// Message retention (messages per conversation).
    pub retention_messages: u64,
    /// Pending message TTL in days.
    pub pending_ttl_days: u64,
    /// Rate limit per minute.
    pub rate_limit_per_min: u32,
    /// PoW difficulty.
    pub pow_difficulty: u8,
    /// PoW enabled.
    pub pow_enabled: bool,
    /// Blocklist enabled.
    pub blocklist_enabled: bool,
    /// Relay mode toggle (future).
    pub relay_mode: bool,
    /// Show backup confirmation modal.
    pub show_backup_modal: bool,
    /// Show change passphrase dialog.
    pub show_passphrase_dialog: bool,
    /// Old passphrase input.
    pub old_passphrase: String,
    /// New passphrase input.
    pub new_passphrase: String,
    /// Confirm new passphrase.
    pub confirm_passphrase: String,
    /// Status message.
    pub status_msg: String,
    /// Whether status is an error.
    pub status_is_error: bool,
}

impl SettingsState {
    pub fn new() -> Self {
        Self {
            data_dir: String::new(),
            rpc_endpoint: "http://127.0.0.1:50051".into(),
            retention_messages: 1500,
            pending_ttl_days: 5,
            rate_limit_per_min: 10,
            pow_difficulty: 8,
            pow_enabled: true,
            blocklist_enabled: true,
            relay_mode: false,
            show_backup_modal: false,
            show_passphrase_dialog: false,
            old_passphrase: String::new(),
            new_passphrase: String::new(),
            confirm_passphrase: String::new(),
            status_msg: String::new(),
            status_is_error: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render(state: &mut SettingsState, ui: &mut egui::Ui) {
    ui.add_space(theme::PANEL_PADDING);
    ui.label(theme::header("Settings"));
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        // ---- Data Directory ----
        ui.add_space(theme::SECTION_SPACING);
        ui.label(
            egui::RichText::new("Data Directory")
                .size(theme::FONT_BODY)
                .strong(),
        );
        ui.add_space(theme::ITEM_SPACING);
        ui.label(theme::muted(&state.data_dir));

        // ---- Storage & Retention ----
        ui.add_space(theme::SECTION_SPACING);
        ui.label(
            egui::RichText::new("Storage & Retention")
                .size(theme::FONT_BODY)
                .strong(),
        );
        ui.add_space(theme::ITEM_SPACING);

        ui.horizontal(|ui| {
            ui.label("Messages per conversation:");
            ui.add(
                egui::DragValue::new(&mut state.retention_messages)
                    .speed(10)
                    .range(100..=100_000),
            );
        });

        ui.horizontal(|ui| {
            ui.label("Pending TTL (days):");
            ui.add(
                egui::DragValue::new(&mut state.pending_ttl_days)
                    .speed(1)
                    .range(1..=30),
            );
        });

        // ---- Anti-Spam ----
        ui.add_space(theme::SECTION_SPACING);
        ui.label(
            egui::RichText::new("Anti-Spam")
                .size(theme::FONT_BODY)
                .strong(),
        );
        ui.add_space(theme::ITEM_SPACING);

        ui.horizontal(|ui| {
            ui.label("Rate limit (msg/min):");
            ui.add(
                egui::DragValue::new(&mut state.rate_limit_per_min)
                    .speed(1)
                    .range(1..=100),
            );
        });

        ui.checkbox(&mut state.pow_enabled, "Require Proof-of-Work for unknown senders");
        if state.pow_enabled {
            ui.horizontal(|ui| {
                ui.label("  PoW difficulty (bits):");
                ui.add(
                    egui::DragValue::new(&mut state.pow_difficulty)
                        .speed(1)
                        .range(1..=24),
                );
            });
        }

        ui.checkbox(&mut state.blocklist_enabled, "Enable system blocklist");

        // ---- Encryption Info ----
        ui.add_space(theme::SECTION_SPACING);
        ui.label(
            egui::RichText::new("Encryption")
                .size(theme::FONT_BODY)
                .strong(),
        );
        ui.add_space(theme::ITEM_SPACING);

        ui.label(theme::muted("Algorithm: Ed25519 + X25519 + ChaCha20-Poly1305"));
        ui.label(theme::muted("Key derivation: Argon2id"));
        ui.label(theme::muted("Storage: encrypted at rest (sled + AEAD)"));

        // ---- Network ----
        ui.add_space(theme::SECTION_SPACING);
        ui.label(
            egui::RichText::new("Network")
                .size(theme::FONT_BODY)
                .strong(),
        );
        ui.add_space(theme::ITEM_SPACING);

        ui.horizontal(|ui| {
            ui.label("RPC endpoint:");
            ui.add(
                egui::TextEdit::singleline(&mut state.rpc_endpoint)
                    .desired_width(300.0),
            );
        });

        ui.checkbox(&mut state.relay_mode, "Relay mode (forward messages for others)");

        // ---- Security ----
        ui.add_space(theme::SECTION_SPACING);
        ui.label(
            egui::RichText::new("Security")
                .size(theme::FONT_BODY)
                .strong(),
        );
        ui.add_space(theme::ITEM_SPACING);

        if ui.button("Change Passphrase").clicked() {
            state.show_passphrase_dialog = true;
            state.old_passphrase.clear();
            state.new_passphrase.clear();
            state.confirm_passphrase.clear();
            state.status_msg.clear();
        }

        ui.add_space(theme::ITEM_SPACING);
        if ui.button("Export Wallet Backup").clicked() {
            state.show_backup_modal = true;
        }

        // Status message.
        if !state.status_msg.is_empty() {
            ui.add_space(theme::ITEM_SPACING);
            let color = if state.status_is_error {
                theme::DANGER
            } else {
                theme::SUCCESS
            };
            ui.colored_label(color, &state.status_msg);
        }
    });

    // ---- Modals ----
    render_passphrase_modal(state, ui);
    render_backup_modal(state, ui);
}

fn render_passphrase_modal(state: &mut SettingsState, ui: &mut egui::Ui) {
    if !state.show_passphrase_dialog {
        return;
    }

    egui::Window::new("Change Passphrase")
        .collapsible(false)
        .resizable(false)
        .show(ui.ctx(), |ui| {
            ui.label("Current passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut state.old_passphrase)
                    .password(true)
                    .desired_width(250.0),
            );

            ui.add_space(theme::ITEM_SPACING);
            ui.label("New passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut state.new_passphrase)
                    .password(true)
                    .desired_width(250.0),
            );

            ui.add_space(theme::ITEM_SPACING);
            ui.label("Confirm new passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut state.confirm_passphrase)
                    .password(true)
                    .desired_width(250.0),
            );

            if !state.status_msg.is_empty() {
                ui.colored_label(theme::DANGER, &state.status_msg);
            }

            ui.add_space(theme::ITEM_SPACING);
            ui.horizontal(|ui| {
                if theme::accent_button(ui, "Change").clicked() {
                    if state.new_passphrase.len() < 8 {
                        state.status_msg =
                            "New passphrase must be at least 8 characters.".into();
                        state.status_is_error = true;
                    } else if state.new_passphrase != state.confirm_passphrase {
                        state.status_msg = "Passphrases do not match.".into();
                        state.status_is_error = true;
                    } else {
                        // Passphrase change requires local wallet access.
                        // Clear sensitive inputs.
                        let len = state.old_passphrase.len();
                        state.old_passphrase = "0".repeat(len);
                        state.old_passphrase.clear();
                        let len = state.new_passphrase.len();
                        state.new_passphrase = "0".repeat(len);
                        state.new_passphrase.clear();
                        let len = state.confirm_passphrase.len();
                        state.confirm_passphrase = "0".repeat(len);
                        state.confirm_passphrase.clear();

                        state.status_msg = "Passphrase change queued (requires local wallet).".into();
                        state.status_is_error = false;
                        state.show_passphrase_dialog = false;
                    }
                }
                if ui.button("Cancel").clicked() {
                    state.show_passphrase_dialog = false;
                    state.status_msg.clear();
                }
            });
        });
}

fn render_backup_modal(state: &mut SettingsState, ui: &mut egui::Ui) {
    if !state.show_backup_modal {
        return;
    }

    egui::Window::new("Export Backup")
        .collapsible(false)
        .resizable(false)
        .show(ui.ctx(), |ui| {
            ui.label(
                egui::RichText::new("Are you sure you want to export your wallet backup?")
                    .color(theme::WARNING),
            );
            ui.add_space(theme::ITEM_SPACING);
            ui.label(theme::muted(
                "The backup file contains your encrypted private key.",
            ));
            ui.label(theme::muted(
                "Store it securely. Do not share it with anyone.",
            ));

            ui.add_space(theme::SECTION_SPACING);
            ui.horizontal(|ui| {
                if theme::accent_button(ui, "Confirm Export").clicked() {
                    state.show_backup_modal = false;
                    state.status_msg = "Backup export queued (requires local wallet).".into();
                    state.status_is_error = false;
                }
                if theme::danger_button(ui, "Cancel").clicked() {
                    state.show_backup_modal = false;
                }
            });
        });
}