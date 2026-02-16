//! Contact management view.

use eframe::egui;

use crate::rpc_bridge::{ContactItem, UiCommand};
use crate::theme;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct ContactState {
    pub contacts: Vec<ContactItem>,
    pub add_address: String,
    pub add_alias: String,
    pub error_msg: String,
    pub show_add_dialog: bool,
}

impl ContactState {
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
            add_address: String::new(),
            add_alias: String::new(),
            error_msg: String::new(),
            show_add_dialog: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render(
    state: &mut ContactState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    ui.add_space(theme::PANEL_PADDING);
    ui.horizontal(|ui| {
        ui.label(theme::header("Contacts"));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::accent_button(ui, "+ Add").clicked() {
                state.show_add_dialog = true;
                state.add_address.clear();
                state.add_alias.clear();
                state.error_msg.clear();
            }
            if ui.button("Refresh").clicked() {
                let _ = cmd_tx.try_send(UiCommand::ListContacts);
            }
        });
    });
    ui.separator();
    ui.add_space(theme::ITEM_SPACING);

    // Add contact dialog.
    if state.show_add_dialog {
        render_add_dialog(state, ui, cmd_tx);
        ui.separator();
        ui.add_space(theme::ITEM_SPACING);
    }

    // Contact list.
    egui::ScrollArea::vertical().show(ui, |ui| {
        if state.contacts.is_empty() {
            ui.label(theme::muted("No contacts. Add one to get started."));
            return;
        }

        for i in 0..state.contacts.len() {
            let contact = &state.contacts[i];
            let addr = contact.address.clone();
            let alias = contact.alias.clone();
            let blocked = contact.blocked;

            let frame = egui::Frame::none()
                .fill(if blocked {
                    egui::Color32::from_rgb(250, 240, 240)
                } else {
                    egui::Color32::TRANSPARENT
                })
                .inner_margin(egui::Margin::same(8.0))
                .rounding(theme::BUTTON_ROUNDING);

            frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Avatar placeholder.
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(32.0, 32.0),
                        egui::Sense::hover(),
                    );
                    let color = if blocked {
                        theme::TEXT_MUTED
                    } else {
                        theme::ACCENT
                    };
                    ui.painter().circle_filled(rect.center(), 16.0, color);

                    ui.vertical(|ui| {
                        if alias.is_empty() {
                            ui.label(theme::body(&theme::truncate_hex(&addr, 16)));
                        } else {
                            ui.label(theme::body(&alias));
                            ui.label(theme::muted(&theme::truncate_hex(&addr, 16)));
                        }
                    });

                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            if blocked {
                                if ui.button("Unblock").clicked() {
                                    let _ = cmd_tx.try_send(UiCommand::UnblockContact {
                                        address: addr.clone(),
                                    });
                                    let _ = cmd_tx.try_send(UiCommand::ListContacts);
                                }
                                ui.colored_label(theme::DANGER, "Blocked");
                            } else {
                                if theme::danger_button(ui, "Block").clicked() {
                                    let _ = cmd_tx.try_send(UiCommand::BlockContact {
                                        address: addr.clone(),
                                    });
                                    let _ = cmd_tx.try_send(UiCommand::ListContacts);
                                }
                            }
                        },
                    );
                });
            });
            ui.separator();
        }
    });
}

fn render_add_dialog(
    state: &mut ContactState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    let frame = egui::Frame::none()
        .fill(theme::BG_INPUT)
        .inner_margin(egui::Margin::same(12.0))
        .rounding(theme::BUTTON_ROUNDING);

    frame.show(ui, |ui| {
        ui.label(theme::body("Add Contact"));
        ui.add_space(theme::ITEM_SPACING);

        ui.label("Address (64 hex characters):");
        ui.add(
            egui::TextEdit::singleline(&mut state.add_address)
                .desired_width(500.0)
                .hint_text("e.g. ab01cd02..."),
        );

        ui.add_space(theme::ITEM_SPACING);
        ui.label("Alias (optional):");
        ui.add(
            egui::TextEdit::singleline(&mut state.add_alias)
                .desired_width(300.0)
                .hint_text("e.g. Alice"),
        );

        if !state.error_msg.is_empty() {
            ui.colored_label(theme::DANGER, &state.error_msg);
        }

        ui.add_space(theme::ITEM_SPACING);
        ui.horizontal(|ui| {
            let valid = validate_address(&state.add_address);
            ui.add_enabled_ui(valid, |ui| {
                if theme::accent_button(ui, "Add").clicked() {
                    let _ = cmd_tx.try_send(UiCommand::AddContact {
                        address: state.add_address.trim().to_string(),
                        alias: sanitize_alias(&state.add_alias),
                    });
                    state.show_add_dialog = false;
                    state.error_msg.clear();
                }
            });
            if !valid && !state.add_address.is_empty() {
                ui.colored_label(
                    theme::WARNING,
                    "Address must be 64 hex characters",
                );
            }
            if ui.button("Cancel").clicked() {
                state.show_add_dialog = false;
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_address(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

fn sanitize_alias(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}