//! Application state and main update loop.
//!
//! Startup flow:
//! 1. Onboarding (detect wallet / create / import / unlock)
//! 2. Send `BootstrapNode` to bridge -> node starts automatically
//! 3. Bridge auto-connects to embedded RPC -> Chat view

use std::time::{Duration, Instant};

use eframe::egui;
use tokio::sync::mpsc;

use crate::views::{chat, contacts, onboarding, profile, settings};
use crate::{rpc_bridge, theme};
use crate::rpc_bridge::{UiCommand, UiEvent};

// ---------------------------------------------------------------------------
// View enum
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Onboarding,
    Chat,
    Contacts,
    Settings,
    Profile,
}

// ---------------------------------------------------------------------------
// Toast notification
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Toast {
    pub message: String,
    pub level: ToastLevel,
    pub created_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub enum ToastLevel {
    Info,
    Success,
    Error,
}

const TOAST_DURATION: Duration = Duration::from_secs(4);

// ---------------------------------------------------------------------------
// BitevachatApp
// ---------------------------------------------------------------------------

pub struct BitevachatApp {
    current_view: View,
    connected: bool,
    onboarding: onboarding::OnboardingState,
    bootstrap_sent: bool,
    chat: chat::ChatState,
    contact: contacts::ContactState,
    setting: settings::SettingsState,
    prof: profile::ProfileState,
    node_status: Option<rpc_bridge::NodeStatus>,
    cmd_tx: mpsc::Sender<UiCommand>,
    evt_rx: mpsc::Receiver<UiEvent>,
    toasts: Vec<Toast>,
    poll_timer: Instant,
    initial_fetch_done: bool,
    /// Tracks whether a ListMessages request is currently in-flight
    /// to avoid duplicate requests that cause flickering.
    messages_request_pending: bool,
}

impl BitevachatApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        cmd_tx: mpsc::Sender<UiCommand>,
        evt_rx: mpsc::Receiver<UiEvent>,
    ) -> Self {
        theme::apply_theme(&cc.egui_ctx);

        Self {
            current_view: View::Onboarding,
            connected: false,
            onboarding: onboarding::OnboardingState::new(),
            bootstrap_sent: false,
            chat: chat::ChatState::new(),
            contact: contacts::ContactState::new(),
            setting: settings::SettingsState::new(),
            prof: profile::ProfileState::new(),
            node_status: None,
            cmd_tx,
            evt_rx,
            toasts: Vec::new(),
            poll_timer: Instant::now(),
            initial_fetch_done: false,
            messages_request_pending: false,
        }
    }

    // -----------------------------------------------------------------------
    // Event processing
    // -----------------------------------------------------------------------

    fn process_events(&mut self, ctx: &egui::Context) {
        loop {
            match self.evt_rx.try_recv() {
                Ok(event) => self.handle_event(event, ctx),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.connected = false;
                    break;
                }
            }
        }
    }

    fn handle_event(&mut self, event: UiEvent, ctx: &egui::Context) {
        match event {
            UiEvent::NodeStarted { address, rpc_endpoint } => {
                tracing::info!(
                    address = %address,
                    endpoint = %rpc_endpoint,
                    "node started"
                );
                self.chat.my_address = address.clone();
                self.prof.profile.address = address;
                self.setting.rpc_endpoint = rpc_endpoint;
                self.add_toast("Node started", ToastLevel::Success);
            }

            UiEvent::Connected => {
                tracing::info!("RPC connected, switching to Chat view");
                self.connected = true;
                self.current_view = View::Chat;
                self.add_toast("Connected", ToastLevel::Success);
                let _ = self.cmd_tx.try_send(UiCommand::GetStatus);
                let _ = self.cmd_tx.try_send(UiCommand::ListContacts);
            }

            UiEvent::Disconnected(reason) => {
                tracing::warn!(reason = %reason, "disconnected");
                self.connected = false;
                self.add_toast(
                    &format!("Disconnected: {reason}"),
                    ToastLevel::Error,
                );
            }

            UiEvent::Status(status) => {
                self.chat.my_address = status.address.clone();
                self.prof.profile.address = status.address.clone();
                self.node_status = Some(status);

                if !self.initial_fetch_done {
                    self.initial_fetch_done = true;
                    let addr = self.chat.my_address.clone();
                    if !addr.is_empty() {
                        let _ = self.cmd_tx.try_send(UiCommand::GetProfile {
                            address: addr,
                        });
                    }
                }
            }

            UiEvent::MessageSent { message_id } => {
                self.chat.last_sent_id = Some(message_id);
                self.chat.scroll_to_bottom = true;
                // Fetch updated message list.
                self.request_messages();
            }

            UiEvent::Messages(msgs) => {
                // Clear in-flight flag so next poll can request again.
                self.messages_request_pending = false;

                // Clear switching flag -- fresh messages have arrived.
                self.chat.switching_convo = false;

                // FIX: Only update messages if content actually changed.
                // This prevents flicker from identical poll responses.
                if !messages_equal(&self.chat.messages, &msgs) {
                    let had_fewer = msgs.len() > self.chat.messages.len();
                    self.chat.messages = msgs;

                    // FIX: Only auto-scroll when NEW messages arrive,
                    // not on every identical poll response.
                    if had_fewer {
                        self.chat.scroll_to_bottom = true;
                    }
                }
            }

            // ----- IMMEDIATE: single contact added -----
            UiEvent::ContactAdded(contact) => {
                tracing::info!(
                    address = %contact.address,
                    alias = %contact.alias,
                    "ContactAdded event"
                );

                // Add to contacts list if not already present.
                if !self
                    .contact
                    .contacts
                    .iter()
                    .any(|c| c.address == contact.address)
                {
                    self.contact.contacts.push(contact.clone());
                }

                // Add to chat conversations if not blocked.
                if !contact.blocked {
                    self.chat.ensure_conversation(
                        &contact.address,
                        if contact.alias.is_empty() {
                            None
                        } else {
                            Some(&contact.alias)
                        },
                    );
                }
            }

            // ----- FULL LIST: merge with local state -----
            UiEvent::ContactList(server_contacts) => {
                tracing::info!(
                    count = server_contacts.len(),
                    "ContactList received"
                );

                // Update contacts tab with server data.
                self.contact.contacts = server_contacts.clone();

                // Build conversations from server contacts,
                // but PRESERVE any locally-added entries.
                let mut new_convos: Vec<chat::ConversationEntry> =
                    server_contacts
                        .iter()
                        .filter(|c| !c.blocked)
                        .map(|c| {
                            let existing = self
                                .chat
                                .conversations
                                .iter()
                                .find(|conv| conv.peer_address == c.address);
                            chat::ConversationEntry {
                                peer_address: c.address.clone(),
                                alias: if c.alias.is_empty() {
                                    None
                                } else {
                                    Some(c.alias.clone())
                                },
                                last_message_time: existing
                                    .map(|e| e.last_message_time.clone())
                                    .unwrap_or_default(),
                                unread: existing
                                    .map(|e| e.unread)
                                    .unwrap_or(false),
                            }
                        })
                        .collect();

                // Keep locally-added conversations not yet in server.
                for local_convo in &self.chat.conversations {
                    let in_server = new_convos
                        .iter()
                        .any(|c| c.peer_address == local_convo.peer_address);
                    if !in_server {
                        new_convos.push(local_convo.clone());
                    }
                }

                self.chat.conversations = new_convos;

                tracing::info!(
                    convo_count = self.chat.conversations.len(),
                    "conversations after merge"
                );
            }

            UiEvent::PeerList(_peers) => {}

            UiEvent::Profile(data) => {
                self.prof.profile = data;
            }

            UiEvent::ProfileUpdated { avatar_cid, version } => {
                self.prof.profile.avatar_cid = avatar_cid;
                self.prof.profile.version = version;
                self.prof.status_msg =
                    "Profile updated successfully.".into();
                self.prof.status_is_error = false;
            }

            UiEvent::AvatarLoaded { cid: _, data } => {
                self.prof.load_avatar_texture(ctx, &data);
            }

            UiEvent::Notification {
                event_type,
                message_id: _,
                sender: _,
                convo_id: _,
            } => match event_type.as_str() {
                "message_received" => {
                    self.add_toast("New message received", ToastLevel::Info);
                    // FIX: Only request if not already pending.
                    self.request_messages();
                }
                "peer_connected" => {
                    self.add_toast("Peer connected", ToastLevel::Info);
                }
                _ => {}
            },

            UiEvent::Error(msg) => {
                tracing::error!(error = %msg, "bridge error");
                self.add_toast(&msg, ToastLevel::Error);
                if self.current_view == View::Onboarding
                    && self.bootstrap_sent
                {
                    self.bootstrap_sent = false;
                    self.onboarding.step =
                        onboarding::OnboardingStep::Detect;
                    self.onboarding.result = None;
                }
            }
        }
    }

    fn add_toast(&mut self, msg: &str, level: ToastLevel) {
        self.toasts.push(Toast {
            message: msg.to_string(),
            level,
            created_at: Instant::now(),
        });
        if self.toasts.len() > 10 {
            self.toasts.remove(0);
        }
    }

    // -----------------------------------------------------------------------
    // Deduplicated message request
    // -----------------------------------------------------------------------

    /// Sends a ListMessages request ONLY if one is not already in-flight.
    /// Prevents duplicate requests from poll + notification + send
    /// that cause flickering.
    fn request_messages(&mut self) {
        if self.messages_request_pending {
            return;
        }
        if let Some(ref convo) = self.chat.selected_convo {
            let _ = self.cmd_tx.try_send(UiCommand::ListMessages {
                convo_id: convo.clone(),
                limit: 100,
                offset: 0,
            });
            self.messages_request_pending = true;
        }
    }

    // -----------------------------------------------------------------------
    // Periodic polling
    // -----------------------------------------------------------------------

    fn maybe_poll(&mut self) {
        if !self.connected {
            return;
        }
        if self.poll_timer.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.poll_timer = Instant::now();
        let _ = self.cmd_tx.try_send(UiCommand::GetStatus);

        // FIX: Use deduplicated request instead of direct send.
        self.request_messages();
    }

    // -----------------------------------------------------------------------
    // Bootstrap trigger
    // -----------------------------------------------------------------------

    fn try_send_bootstrap(&mut self) {
        if self.bootstrap_sent {
            return;
        }
        if let Some(result) = self.onboarding.result.take() {
            let cmd = UiCommand::BootstrapNode {
                data_dir: result.data_dir.clone(),
                mnemonic: result.mnemonic,
                passphrase: result.passphrase,
            };
            let _ = self.cmd_tx.try_send(cmd);
            self.bootstrap_sent = true;
            self.setting.data_dir =
                result.data_dir.to_string_lossy().to_string();
        }
    }

    // -----------------------------------------------------------------------
    // Handle "open chat" request from Contacts tab
    // -----------------------------------------------------------------------

    fn check_contacts_open_chat(&mut self) {
        if let Some(addr) = self.contact.open_chat_addr.take() {
            let alias = self.contact.open_chat_alias.take();
            tracing::info!(
                address = %addr,
                "contacts tab -> opening chat"
            );

            // Ensure conversation exists.
            self.chat.ensure_conversation(
                &addr,
                alias.as_deref(),
            );

            // Select conversation.
            self.chat
                .select_conversation(addr, &self.cmd_tx);

            // Switch to Chat view.
            self.current_view = View::Chat;
        }
    }
}

// ---------------------------------------------------------------------------
// Message equality check (avoids unnecessary re-renders)
// ---------------------------------------------------------------------------

/// Compares two message lists by message_id to detect actual changes.
/// Much cheaper than deep comparison and prevents flicker from
/// identical poll responses.
fn messages_equal(
    a: &[rpc_bridge::MessageItem],
    b: &[rpc_bridge::MessageItem],
) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.message_id == y.message_id)
}

// ---------------------------------------------------------------------------
// eframe::App
// ---------------------------------------------------------------------------

impl eframe::App for BitevachatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1) Process async events from bridge.
        self.process_events(ctx);

        // 2) Periodic poll.
        self.maybe_poll();

        // 3) Schedule next repaint.
        ctx.request_repaint_after(Duration::from_millis(250));

        // 4) Render toasts.
        render_toasts(&mut self.toasts, ctx);

        // 5) Onboarding.
        if self.current_view == View::Onboarding {
            egui::CentralPanel::default().show(ctx, |ui| {
                let done =
                    onboarding::render(&mut self.onboarding, ui);
                if done {
                    self.try_send_bootstrap();
                }
            });
            return;
        }

        // 6) Navigation bar.
        egui::TopBottomPanel::top("nav_bar").show(ctx, |ui| {
            render_nav_bar(
                ui,
                &mut self.current_view,
                self.connected,
                &self.node_status,
                &self.cmd_tx,
                &self.setting.rpc_endpoint,
            );
        });

        // 7) Render current view.
        match self.current_view {
            View::Chat => {
                chat::render(&mut self.chat, ctx, &self.cmd_tx);
            }
            View::Contacts => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    contacts::render(
                        &mut self.contact,
                        ui,
                        &self.cmd_tx,
                    );
                });
                // Check if contacts tab wants to open a chat.
                self.check_contacts_open_chat();
            }
            View::Settings => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    settings::render(&mut self.setting, ui);
                });
            }
            View::Profile => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    profile::render(&mut self.prof, ui, &self.cmd_tx);
                });
            }
            View::Onboarding => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Navigation bar
// ---------------------------------------------------------------------------

fn render_nav_bar(
    ui: &mut egui::Ui,
    current: &mut View,
    connected: bool,
    status: &Option<rpc_bridge::NodeStatus>,
    cmd_tx: &mpsc::Sender<UiCommand>,
    rpc_endpoint: &str,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Bitevachat")
                .size(theme::FONT_HEADER)
                .color(theme::ACCENT)
                .strong(),
        );

        ui.separator();

        let tabs = [
            (View::Chat, "Chat"),
            (View::Contacts, "Contacts"),
            (View::Profile, "Profile"),
            (View::Settings, "Settings"),
        ];

        for (view, label) in &tabs {
            let selected = *current == *view;
            let text = if selected {
                egui::RichText::new(*label)
                    .strong()
                    .color(theme::ACCENT)
            } else {
                egui::RichText::new(*label)
            };
            if ui.selectable_label(selected, text).clicked() {
                *current = *view;
                match view {
                    View::Contacts => {
                        let _ =
                            cmd_tx.try_send(UiCommand::ListContacts);
                    }
                    View::Profile => {
                        let _ =
                            cmd_tx.try_send(UiCommand::GetStatus);
                    }
                    _ => {}
                }
            }
        }

        ui.with_layout(
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                if connected {
                    let state_str = status
                        .as_ref()
                        .map(|s| s.state.as_str())
                        .unwrap_or("connected");
                    ui.colored_label(theme::SUCCESS, state_str);

                    let pending = status
                        .as_ref()
                        .map(|s| s.pending_count)
                        .unwrap_or(0);
                    if pending > 0 {
                        ui.label(theme::muted(&format!(
                            "({pending} pending)"
                        )));
                    }
                } else {
                    ui.colored_label(theme::DANGER, "disconnected");
                    if ui.small_button("Reconnect").clicked() {
                        let _ = cmd_tx.try_send(UiCommand::Connect {
                            endpoint: rpc_endpoint.to_string(),
                        });
                    }
                }
            },
        );
    });
}

// ---------------------------------------------------------------------------
// Toast rendering
// ---------------------------------------------------------------------------

fn render_toasts(toasts: &mut Vec<Toast>, ctx: &egui::Context) {
    toasts.retain(|t| t.created_at.elapsed() < TOAST_DURATION);

    if toasts.is_empty() {
        return;
    }

    egui::Area::new("toasts".into())
        .fixed_pos(egui::pos2(20.0, 50.0))
        .show(ctx, |ui| {
            for toast in toasts.iter() {
                let color = match toast.level {
                    ToastLevel::Info => theme::ACCENT,
                    ToastLevel::Success => theme::SUCCESS,
                    ToastLevel::Error => theme::DANGER,
                };
                let frame = egui::Frame::none()
                    .fill(color)
                    .inner_margin(egui::Margin::same(8.0))
                    .rounding(theme::BUTTON_ROUNDING);

                frame.show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(&toast.message)
                            .color(egui::Color32::WHITE)
                            .size(theme::FONT_SMALL),
                    );
                });
                ui.add_space(4.0);
            }
        });
}