//! Chat view: sidebar, message list, input area.
//!
//! WhatsApp-like flow:
//! - Left sidebar shows all conversations (contacts)
//! - Click a contact → opens chat panel on the right with textbox + Send
//! - "+ New" opens inline dialog to add a peer address
//! - Own address displayed with copy button for sharing

use eframe::egui;

use crate::rpc_bridge::{MessageItem, UiCommand};
use crate::theme;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct ChatState {
    /// Known conversations (one per contact).
    pub conversations: Vec<ConversationEntry>,
    /// Currently selected conversation (peer address).
    pub selected_convo: Option<String>,
    /// Messages for the selected conversation.
    pub messages: Vec<MessageItem>,
    /// Text input buffer.
    pub input_text: String,
    /// Our own address (for bubble side determination).
    pub my_address: String,
    /// Auto-scroll to bottom on next render.
    pub scroll_to_bottom: bool,
    /// Last sent message ID (for feedback).
    pub last_sent_id: Option<String>,
    /// "New Chat" dialog visible.
    pub show_new_chat: bool,
    /// Address input in new chat dialog.
    pub new_chat_address: String,
    /// Alias input in new chat dialog.
    pub new_chat_alias: String,
    /// Error in new chat dialog.
    pub new_chat_error: String,
    /// Copy-to-clipboard feedback timer.
    pub copy_feedback_until: Option<std::time::Instant>,
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
            show_new_chat: false,
            new_chat_address: String::new(),
            new_chat_alias: String::new(),
            new_chat_error: String::new(),
            copy_feedback_until: None,
        }
    }

    /// Select a conversation and fetch its messages.
    pub fn select_conversation(
        &mut self,
        addr: String,
        cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
    ) {
        tracing::info!(address = %addr, "selecting conversation");
        self.selected_convo = Some(addr.clone());
        self.messages.clear();
        self.scroll_to_bottom = true;
        let _ = cmd_tx.try_send(UiCommand::ListMessages {
            convo_id: addr,
            limit: 100,
            offset: 0,
        });
    }

    /// Ensure a conversation entry exists for the given address.
    pub fn ensure_conversation(&mut self, address: &str, alias: Option<&str>) {
        if !self.conversations.iter().any(|c| c.peer_address == address) {
            self.conversations.push(ConversationEntry {
                peer_address: address.to_string(),
                alias: alias.map(|s| s.to_string()),
                last_message_time: String::new(),
                unread: false,
            });
            tracing::info!(address, "conversation added locally");
        }
    }
}

// ---------------------------------------------------------------------------
// Main render
// ---------------------------------------------------------------------------

pub fn render(
    state: &mut ChatState,
    ctx: &egui::Context,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    // Sidebar first (sets selected_convo on click).
    egui::SidePanel::left("chat_sidebar")
        .exact_width(theme::SIDEBAR_WIDTH)
        .show(ctx, |ui| {
            render_sidebar(state, ui, cmd_tx);
        });

    // Central panel: shows chat if a conversation is selected,
    // otherwise shows empty state.
    egui::CentralPanel::default().show(ctx, |ui| {
        let has_convo = state.selected_convo.is_some();
        if has_convo {
            render_chat_panel(state, ui, cmd_tx);
        } else {
            render_empty_state(state, ui);
        }
    });
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

fn render_empty_state(state: &ChatState, ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.label(theme::muted("Select a conversation or start a new chat"));
        ui.add_space(theme::SECTION_SPACING);

        if !state.my_address.is_empty() {
            ui.label(theme::body("Your address:"));
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(&state.my_address)
                    .monospace()
                    .size(theme::FONT_SMALL),
            );
            ui.add_space(4.0);
            ui.label(theme::muted("Share this address with your chat partner"));
        }
    });
}

// ---------------------------------------------------------------------------
// Chat panel (header + messages + input) — ONLY shown when convo selected
// ---------------------------------------------------------------------------

fn render_chat_panel(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    // Header: shows who you're chatting with.
    if let Some(ref convo) = state.selected_convo {
        let convo_clone = convo.clone();
        let alias = state
            .conversations
            .iter()
            .find(|c| c.peer_address == convo_clone)
            .and_then(|c| c.alias.clone());

        egui::Frame::none()
            .fill(theme::BG_SIDEBAR)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Avatar circle.
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(36.0, 36.0),
                        egui::Sense::hover(),
                    );
                    let initial_char = alias
                        .as_deref()
                        .and_then(|s| s.chars().next())
                        .unwrap_or('?')
                        .to_uppercase()
                        .to_string();
                    ui.painter()
                        .circle_filled(rect.center(), 18.0, theme::ACCENT);
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        &initial_char,
                        egui::FontId::proportional(16.0),
                        egui::Color32::WHITE,
                    );

                    ui.vertical(|ui| {
                        if let Some(ref name) = alias {
                            ui.label(
                                egui::RichText::new(name)
                                    .size(theme::FONT_BODY)
                                    .strong(),
                            );
                        }
                        ui.label(theme::muted(&theme::truncate_hex(
                            &convo_clone,
                            20,
                        )));
                    });
                });
            });
    }

    ui.separator();

    // Calculate how much vertical space remains for messages.
    // Reserve fixed height for: separator (2) + input bar (~46) + padding.
    let input_reserved = 56.0;
    let available_height = ui.available_height() - input_reserved;
    let messages_height = available_height.max(80.0);

    // Messages area: constrain height so input bar is ALWAYS visible.
    render_messages(state, ui, messages_height);

    ui.separator();

    // Input area: textbox + Send button — guaranteed visible.
    render_input(state, ui, cmd_tx);
}

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

fn render_sidebar(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    // Paint sidebar background.
    let bg_rect = ui.available_rect_before_wrap();
    ui.painter()
        .rect_filled(bg_rect, 0.0, theme::BG_SIDEBAR);

    ui.add_space(theme::PANEL_PADDING);

    // ---- Own address with copy button ----
    if !state.my_address.is_empty() {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(215, 225, 235))
            .inner_margin(egui::Margin::same(8.0))
            .rounding(theme::BUTTON_ROUNDING)
            .show(ui, |ui| {
                ui.label(theme::muted("My Address:"));
                ui.horizontal(|ui| {
                    let short = theme::truncate_hex(&state.my_address, 20);
                    ui.label(
                        egui::RichText::new(short)
                            .monospace()
                            .size(theme::FONT_SMALL),
                    );

                    let showing_feedback = state
                        .copy_feedback_until
                        .map(|t| t > std::time::Instant::now())
                        .unwrap_or(false);

                    if showing_feedback {
                        ui.colored_label(theme::SUCCESS, "Copied!");
                    } else if ui.small_button("Copy").clicked() {
                        ui.output_mut(|o| {
                            o.copied_text = state.my_address.clone();
                        });
                        state.copy_feedback_until = Some(
                            std::time::Instant::now()
                                + std::time::Duration::from_secs(2),
                        );
                    }
                });
            });

        ui.add_space(theme::ITEM_SPACING);
    }

    // ---- Header + New Chat button ----
    ui.horizontal(|ui| {
        ui.label(theme::header("Chats"));
        ui.with_layout(
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                if theme::accent_button(ui, "+ New").clicked() {
                    state.show_new_chat = true;
                    state.new_chat_address.clear();
                    state.new_chat_alias.clear();
                    state.new_chat_error.clear();
                }
            },
        );
    });

    ui.separator();
    ui.add_space(theme::ITEM_SPACING);

    // ---- New chat dialog (inline) ----
    if state.show_new_chat {
        render_new_chat_dialog(state, ui, cmd_tx);
        ui.separator();
        ui.add_space(theme::ITEM_SPACING);
    }

    // ---- Conversation list ----
    render_conversation_list(state, ui, cmd_tx);
}

// ---------------------------------------------------------------------------
// Conversation list — uses allocate_exact_size for RELIABLE click handling
// ---------------------------------------------------------------------------

fn render_conversation_list(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    if state.conversations.is_empty() {
        ui.label(theme::muted("No conversations yet"));
        ui.add_space(theme::ITEM_SPACING);
        ui.label(theme::muted("Click \"+ New\" to start a chat"));
        return;
    }

    // PHASE 1: Render each entry and collect click result.
    //
    // We use allocate_exact_size + Sense::click() which is the
    // lowest-level click handling in egui — GUARANTEED to register.
    let mut clicked_addr: Option<String> = None;

    let convo_count = state.conversations.len();
    for i in 0..convo_count {
        let entry = &state.conversations[i];
        let is_selected = state
            .selected_convo
            .as_ref()
            .map(|s| s == &entry.peer_address)
            .unwrap_or(false);

        let truncated_addr = theme::truncate_hex(&entry.peer_address, 12);
        let display_name = entry
            .alias
            .as_deref()
            .unwrap_or(&truncated_addr)
            .to_string();

        let initial = display_name
            .chars()
            .next()
            .unwrap_or('?')
            .to_uppercase()
            .to_string();

        // Allocate a clickable rect for the entire row.
        let row_width = ui.available_width();
        let row_height = 48.0;
        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(row_width, row_height),
            egui::Sense::click(),
        );

        // Paint background (selected, hovered, or normal).
        let bg = if is_selected {
            theme::SELECTED
        } else if response.hovered() {
            egui::Color32::from_rgb(218, 228, 236)
        } else {
            egui::Color32::TRANSPARENT
        };
        ui.painter()
            .rect_filled(rect, theme::BUTTON_ROUNDING, bg);

        // Paint avatar circle.
        let avatar_center =
            egui::pos2(rect.left() + 12.0 + 16.0, rect.center().y);
        ui.painter()
            .circle_filled(avatar_center, 16.0, theme::ACCENT);
        ui.painter().text(
            avatar_center,
            egui::Align2::CENTER_CENTER,
            &initial,
            egui::FontId::proportional(13.0),
            egui::Color32::WHITE,
        );

        // Paint display name.
        let text_pos =
            egui::pos2(rect.left() + 12.0 + 36.0 + 8.0, rect.center().y);
        ui.painter().text(
            text_pos,
            egui::Align2::LEFT_CENTER,
            &display_name,
            egui::FontId::proportional(theme::FONT_BODY),
            theme::TEXT_NORMAL,
        );

        // Detect click.
        if response.clicked() {
            clicked_addr = Some(entry.peer_address.clone());
        }

        // Small separator line.
        let sep_y = rect.bottom();
        ui.painter().line_segment(
            [
                egui::pos2(rect.left() + 12.0, sep_y),
                egui::pos2(rect.right() - 4.0, sep_y),
            ],
            egui::Stroke::new(0.5, theme::SEPARATOR),
        );
    }

    // PHASE 2: Apply click (after iteration to avoid borrow conflict).
    if let Some(addr) = clicked_addr {
        state.select_conversation(addr, cmd_tx);
    }
}

// ---------------------------------------------------------------------------
// New Chat dialog
// ---------------------------------------------------------------------------

fn render_new_chat_dialog(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    egui::Frame::none()
        .fill(theme::BG_INPUT)
        .inner_margin(egui::Margin::same(10.0))
        .rounding(theme::BUTTON_ROUNDING)
        .show(ui, |ui| {
            ui.label(theme::body("New Chat"));
            ui.add_space(4.0);

            ui.label(theme::muted("Peer address (64 hex):"));
            ui.add(
                egui::TextEdit::singleline(&mut state.new_chat_address)
                    .desired_width(ui.available_width() - 8.0)
                    .hint_text("Paste peer address here"),
            );

            ui.add_space(4.0);
            ui.label(theme::muted("Alias (optional):"));
            ui.add(
                egui::TextEdit::singleline(&mut state.new_chat_alias)
                    .desired_width(ui.available_width() - 8.0)
                    .hint_text("e.g. Alice"),
            );

            if !state.new_chat_error.is_empty() {
                ui.colored_label(theme::DANGER, &state.new_chat_error);
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if theme::accent_button(ui, "Start Chat").clicked() {
                    let addr = state.new_chat_address.trim().to_string();
                    if addr.len() != 64
                        || !addr.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        state.new_chat_error =
                            "Address must be 64 hex characters.".into();
                    } else if addr == state.my_address {
                        state.new_chat_error =
                            "Cannot chat with yourself.".into();
                    } else {
                        let alias = state.new_chat_alias.trim().to_string();

                        // 1) Send AddContact to bridge (RPC).
                        let _ = cmd_tx.try_send(UiCommand::AddContact {
                            address: addr.clone(),
                            alias: alias.clone(),
                        });

                        // 2) Add locally for INSTANT feedback.
                        state.ensure_conversation(
                            &addr,
                            if alias.is_empty() {
                                None
                            } else {
                                Some(&alias)
                            },
                        );

                        // 3) Select the conversation → opens chat panel.
                        state.select_conversation(addr, cmd_tx);

                        // 4) Close dialog.
                        state.show_new_chat = false;
                        state.new_chat_error.clear();
                    }
                }
                if ui.button("Cancel").clicked() {
                    state.show_new_chat = false;
                }
            });
        });
}

// ---------------------------------------------------------------------------
// Message list
// ---------------------------------------------------------------------------

fn render_messages(state: &mut ChatState, ui: &mut egui::Ui, max_height: f32) {
    let scroll_id = egui::Id::new("chat_messages_scroll");
    let mut scroll = egui::ScrollArea::vertical()
        .id_source(scroll_id)
        .max_height(max_height)
        .auto_shrink([false, false])
        .stick_to_bottom(true);

    if state.scroll_to_bottom {
        scroll = scroll.scroll_offset(egui::vec2(0.0, f32::MAX));
        state.scroll_to_bottom = false;
    }

    scroll.show(ui, |ui: &mut egui::Ui| {
        ui.add_space(theme::PANEL_PADDING);

        if state.messages.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(theme::muted("No messages yet. Say hello!"));
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

        egui::Frame::none()
            .fill(fill)
            .inner_margin(egui::Margin::same(10.0))
            .rounding(theme::BUBBLE_ROUNDING)
            .show(ui, |ui| {
                ui.set_max_width(max_width);

                let text =
                    String::from_utf8(msg.payload_ciphertext.clone())
                        .unwrap_or_else(|_| {
                            format!(
                                "[encrypted: {} bytes]",
                                msg.payload_ciphertext.len()
                            )
                        });

                ui.label(theme::body(&text));

                if !msg.timestamp.is_empty() {
                    let time_display = extract_time(&msg.timestamp);
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::TOP),
                        |ui| {
                            ui.label(
                                egui::RichText::new(time_display)
                                    .size(theme::FONT_TINY)
                                    .color(theme::TEXT_MUTED),
                            );
                        },
                    );
                }
            });
    });
}

/// Extract time portion from an ISO timestamp.
fn extract_time(ts: &str) -> &str {
    ts.find('T')
        .map(|idx| &ts[idx + 1..])
        .and_then(|t| {
            t.find('+')
                .or_else(|| t.find('Z'))
                .map(|end| &t[..end])
        })
        .unwrap_or(ts)
}

// ---------------------------------------------------------------------------
// Input area — textbox + Send button
// ---------------------------------------------------------------------------

fn render_input(
    state: &mut ChatState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    egui::Frame::none()
        .fill(theme::BG_INPUT)
        .inner_margin(egui::Margin::same(8.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.input_text)
                        .desired_width(ui.available_width() - 80.0)
                        .hint_text("Type a message..."),
                );

                let enter_pressed = resp.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let send_clicked =
                    theme::accent_button(ui, "Send").clicked();

                if (enter_pressed || send_clicked)
                    && !state.input_text.trim().is_empty()
                {
                    if let Some(ref recipient) = state.selected_convo {
                        let text = state.input_text.trim().to_string();
                        let _ = cmd_tx.try_send(UiCommand::SendMessage {
                            recipient: recipient.clone(),
                            text,
                        });
                        state.input_text.clear();
                        state.scroll_to_bottom = true;
                        resp.request_focus();
                    }
                }
            });
        });
}