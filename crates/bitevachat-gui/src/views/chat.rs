//! Chat view: sidebar, message list, input area.
//!
//! No blocking calls. All data comes from the app state which is
//! updated asynchronously via the RPC bridge.

use eframe::egui;

use crate::rpc_bridge::{MessageItem, UiCommand};
use crate::theme;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct ChatState {
    /// Known conversation IDs (peer addresses).
    pub conversations: Vec<ConversationEntry>,
    /// Currently selected conversation.
    pub selected_convo: Option<String>,
    /// Messages for the selected conversation.
    pub messages: Vec<MessageItem>,
    /// Text input buffer.
    pub input_text: String,
    /// Our own address (for determining bubble side).
    pub my_address: String,
    /// Whether to auto-scroll to bottom.
    pub scroll_to_bottom: bool,
    /// Message that was just sent (for feedback).
    pub last_sent_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ConversationEntry {
    pub peer_address: String,
    pub alias: Option<String>,
    pub last_message_time: String,
    pub unread: bool,
}

impl ChatState {
    pub fn new() -> Self {
        Self {
            conversations: Vec::new(),
            selected_convo: None,
            messages: Vec::new(),
            input_text: String::new(),
            my_address: String::new(),
            scroll_to_bottom: false,
            last_sent_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Renders the full chat view. Returns an optional command to send.
pub fn render(
    state: &mut ChatState,
    ctx: &egui::Context,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    // Sidebar: conversation list.
    egui::SidePanel::left("chat_sidebar")
        .exact_width(theme::SIDEBAR_WIDTH)
        .show(ctx, |ui| {
            ui.painter().rect_filled(
                ui.available_rect_before_wrap(),
                0.0,
                theme::BG_SIDEBAR,
            );
            render_sidebar(state, ui, cmd_tx);
        });

    // Main panel: messages + input.
    egui::CentralPanel::default().show(ctx, |ui| {
        match &state.selected_convo {
            Some(_convo) => {
                render_messages(state, ui);
                ui.separator();
                render_input(state, ui, cmd_tx);
            }
            None => {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.label(theme::muted("Select a conversation to start chatting"));
                });
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

fn render_sidebar(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    ui.add_space(theme::PANEL_PADDING);
    ui.label(theme::header("Chats"));
    ui.add_space(theme::ITEM_SPACING);
    ui.separator();
    ui.add_space(theme::ITEM_SPACING);

    egui::ScrollArea::vertical().show(ui, |ui| {
        if state.conversations.is_empty() {
            ui.label(theme::muted("No conversations yet"));
            ui.add_space(theme::ITEM_SPACING);
            ui.label(theme::muted("Send a message to start one"));
        }

        let selected = state.selected_convo.clone();
        for entry in &state.conversations {
            let is_selected = selected
                .as_ref()
                .map(|s| s == &entry.peer_address)
                .unwrap_or(false);

            let truncated_addr = theme::truncate_hex(&entry.peer_address, 12);
            let display_name = entry
                .alias
                .as_deref()
                .unwrap_or(&truncated_addr);

            let frame = egui::Frame::none()
                .fill(if is_selected {
                    theme::SELECTED
                } else {
                    egui::Color32::TRANSPARENT
                })
                .inner_margin(egui::Margin::same(8.0))
                .rounding(theme::BUTTON_ROUNDING);

            let resp = frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Avatar placeholder (circle).
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(theme::AVATAR_SIZE, theme::AVATAR_SIZE),
                        egui::Sense::hover(),
                    );
                    ui.painter().circle_filled(
                        rect.center(),
                        theme::AVATAR_SIZE / 2.0,
                        theme::ACCENT,
                    );
                    let initial = display_name
                        .chars()
                        .next()
                        .unwrap_or('?')
                        .to_uppercase()
                        .to_string();
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        initial,
                        egui::FontId::proportional(14.0),
                        egui::Color32::WHITE,
                    );

                    ui.vertical(|ui| {
                        let name_text = if entry.unread {
                            egui::RichText::new(display_name).strong()
                        } else {
                            egui::RichText::new(display_name)
                        };
                        ui.label(name_text);
                        if !entry.last_message_time.is_empty() {
                            ui.label(theme::muted(&entry.last_message_time));
                        }
                    });
                });
            });

            if resp.response.interact(egui::Sense::click()).clicked() {
                state.selected_convo = Some(entry.peer_address.clone());
                state.scroll_to_bottom = true;
                // Request messages for this conversation.
                let _ = cmd_tx.try_send(UiCommand::ListMessages {
                    convo_id: entry.peer_address.clone(),
                    limit: 100,
                    offset: 0,
                });
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Message list
// ---------------------------------------------------------------------------

fn render_messages(state: &mut ChatState, ui: &mut egui::Ui) {
    let scroll_id = egui::Id::new("chat_scroll");
    let mut scroll = egui::ScrollArea::vertical()
        .id_source(scroll_id)
        .auto_shrink([false, false])
        .stick_to_bottom(true);

    if state.scroll_to_bottom {
        scroll = scroll.scroll_offset(egui::vec2(0.0, f32::MAX));
        state.scroll_to_bottom = false;
    }

    scroll.show(ui, |ui| {
        ui.add_space(theme::PANEL_PADDING);

        if state.messages.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(theme::muted("No messages yet"));
            });
            return;
        }

        for msg in &state.messages {
            let is_mine = msg.sender == state.my_address;
            render_bubble(ui, msg, is_mine);
            ui.add_space(4.0);
        }

        ui.add_space(theme::PANEL_PADDING);
    });
}

fn render_bubble(ui: &mut egui::Ui, msg: &MessageItem, is_mine: bool) {
    let max_width = ui.available_width() * 0.7;

    let layout = if is_mine {
        egui::Layout::right_to_left(egui::Align::TOP)
    } else {
        egui::Layout::left_to_right(egui::Align::TOP)
    };

    ui.with_layout(layout, |ui| {
        let fill = if is_mine {
            theme::BUBBLE_SENT
        } else {
            theme::BUBBLE_RECV
        };

        let frame = egui::Frame::none()
            .fill(fill)
            .inner_margin(egui::Margin::same(10.0))
            .rounding(theme::BUBBLE_ROUNDING);

        frame.show(ui, |ui| {
            ui.set_max_width(max_width);

            // Decode payload as UTF-8 text, fallback to hex length.
            let text = String::from_utf8(msg.payload_ciphertext.clone())
                .unwrap_or_else(|_| {
                    format!("[encrypted: {} bytes]", msg.payload_ciphertext.len())
                });

            ui.label(theme::body(&text));

            // Timestamp (small, muted).
            if !msg.timestamp.is_empty() {
                // Show only time portion if available.
                let time_display = msg
                    .timestamp
                    .find('T')
                    .map(|idx| &msg.timestamp[idx + 1..])
                    .and_then(|t| t.find('+').map(|end| &t[..end]))
                    .unwrap_or(&msg.timestamp);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    ui.label(
                        egui::RichText::new(time_display)
                            .size(theme::FONT_TINY)
                            .color(theme::TEXT_MUTED),
                    );
                });
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Input area
// ---------------------------------------------------------------------------

fn render_input(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    let frame = egui::Frame::none()
        .fill(theme::BG_INPUT)
        .inner_margin(egui::Margin::same(8.0));

    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.input_text)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text("Type a message..."),
            );

            let enter_pressed =
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let send_clicked = theme::accent_button(ui, "Send").clicked();

            if (enter_pressed || send_clicked) && !state.input_text.trim().is_empty() {
                if let Some(ref recipient) = state.selected_convo {
                    let text = state.input_text.trim().to_string();
                    let _ = cmd_tx.try_send(UiCommand::SendMessage {
                        recipient: recipient.clone(),
                        text,
                    });
                    state.input_text.clear();
                    state.scroll_to_bottom = true;
                    // Re-request focus on the text field.
                    resp.request_focus();
                }
            }
        });
    });
}