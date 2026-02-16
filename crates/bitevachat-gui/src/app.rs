//! Application state and main update loop.
//!
//! All heavy work is done in the RPC bridge. The `update()` method
//! only polls for events, mutates state, and renders the current view.

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
}

impl BitevachatApp {
    /// Creates the app. Called from the eframe creator closure.
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
        }
    }

    // -----------------------------------------------------------------------
    // Event processing (non-blocking)
    // -----------------------------------------------------------------------

    fn process_events(&mut self, ctx: &egui::Context) {
        // Drain all pending events.
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
            UiEvent::Connected => {
                self.connected = true;
                self.add_toast("Connected to node", ToastLevel::Success);
                // Trigger initial data fetch.
                let _ = self.cmd_tx.try_send(UiCommand::GetStatus);
                let _ = self.cmd_tx.try_send(UiCommand::ListContacts);
            }

            UiEvent::Disconnected(reason) => {
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

                // First status → fetch own profile.
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
                // Re-fetch messages for current conversation.
                if let Some(ref convo) = self.chat.selected_convo {
                    let _ = self.cmd_tx.try_send(UiCommand::ListMessages {
                        convo_id: convo.clone(),
                        limit: 100,
                        offset: 0,
                    });
                }
            }

            UiEvent::Messages(msgs) => {
                self.chat.messages = msgs;
                self.chat.scroll_to_bottom = true;
            }

            UiEvent::ContactList(contacts) => {
                self.contact.contacts = contacts.clone();

                // Update chat conversation list from contacts.
                self.chat.conversations = contacts
                    .iter()
                    .filter(|c| !c.blocked)
                    .map(|c| chat::ConversationEntry {
                        peer_address: c.address.clone(),
                        alias: if c.alias.is_empty() {
                            None
                        } else {
                            Some(c.alias.clone())
                        },
                        last_message_time: String::new(),
                        unread: false,
                    })
                    .collect();
            }

            UiEvent::PeerList(_peers) => {
                // Peer list can be shown in a future "Network" tab.
            }

            UiEvent::Profile(data) => {
                self.prof.profile = data;
            }

            UiEvent::ProfileUpdated { avatar_cid, version } => {
                self.prof.profile.avatar_cid = avatar_cid;
                self.prof.profile.version = version;
                self.prof.status_msg = "Profile updated successfully.".into();
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
            } => {
                match event_type.as_str() {
                    "message_received" => {
                        self.add_toast("New message received", ToastLevel::Info);
                        // Re-fetch current conversation.
                        if let Some(ref convo) = self.chat.selected_convo {
                            let _ = self.cmd_tx.try_send(UiCommand::ListMessages {
                                convo_id: convo.clone(),
                                limit: 100,
                                offset: 0,
                            });
                        }
                    }
                    "peer_connected" => {
                        self.add_toast("Peer connected", ToastLevel::Info);
                    }
                    _ => {}
                }
            }

            UiEvent::Error(msg) => {
                self.add_toast(&msg, ToastLevel::Error);
            }
        }
    }

    fn add_toast(&mut self, msg: &str, level: ToastLevel) {
        self.toasts.push(Toast {
            message: msg.to_string(),
            level,
            created_at: Instant::now(),
        });
        // Cap toast list.
        if self.toasts.len() > 10 {
            self.toasts.remove(0);
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

        // Refresh current conversation messages.
        if let Some(ref convo) = self.chat.selected_convo {
            let _ = self.cmd_tx.try_send(UiCommand::ListMessages {
                convo_id: convo.clone(),
                limit: 100,
                offset: 0,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// eframe::App
// ---------------------------------------------------------------------------

impl eframe::App for BitevachatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1) Process async events.
        self.process_events(ctx);

        // 2) Periodic poll.
        self.maybe_poll();

        // 3) Schedule next repaint.
        ctx.request_repaint_after(Duration::from_millis(250));

        // 4) Render toasts.
        render_toasts(&mut self.toasts, ctx);

        // 5) Render current view.
        if self.current_view == View::Onboarding {
            egui::CentralPanel::default().show(ctx, |ui| {
                let done = onboarding::render(&mut self.onboarding, ui);
                if done {
                    self.current_view = View::Chat;
                    // Auto-connect.
                    let endpoint = self.setting.rpc_endpoint.clone();
                    let _ = self.cmd_tx.try_send(UiCommand::Connect { endpoint });
                }
            });
            return;
        }

        // Top bar with navigation.
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

        // View-specific content.
        match self.current_view {
            View::Chat => {
                chat::render(&mut self.chat, ctx, &self.cmd_tx);
            }
            View::Contacts => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    contacts::render(&mut self.contact, ui, &self.cmd_tx);
                });
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
            View::Onboarding => {
                // Handled above.
            }
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
                egui::RichText::new(*label).strong().color(theme::ACCENT)
            } else {
                egui::RichText::new(*label)
            };
            if ui.selectable_label(selected, text).clicked() {
                *current = *view;

                // Fetch data for the view being switched to.
                match view {
                    View::Contacts => {
                        let _ = cmd_tx.try_send(UiCommand::ListContacts);
                    }
                    View::Profile => {
                        let _ = cmd_tx.try_send(UiCommand::GetStatus);
                    }
                    _ => {}
                }
            }
        }

        // Connection indicator (right side).
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if connected {
                let state_str = status
                    .as_ref()
                    .map(|s| s.state.as_str())
                    .unwrap_or("connected");
                ui.colored_label(theme::SUCCESS, state_str);

                let pending = status.as_ref().map(|s| s.pending_count).unwrap_or(0);
                if pending > 0 {
                    ui.label(theme::muted(&format!("({pending} pending)")));
                }
            } else {
                ui.colored_label(theme::DANGER, "disconnected");
                if ui.small_button("Connect").clicked() {
                    let _ = cmd_tx.try_send(UiCommand::Connect {
                        endpoint: rpc_endpoint.to_string(),
                    });
                }
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Toast rendering
// ---------------------------------------------------------------------------

fn render_toasts(toasts: &mut Vec<Toast>, ctx: &egui::Context) {
    // Remove expired toasts.
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