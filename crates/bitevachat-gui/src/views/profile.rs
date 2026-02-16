//! Profile editor: name, bio, avatar, signed profile preview.

use eframe::egui;

use crate::rpc_bridge::{ProfileData, UiCommand};
use crate::theme;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct ProfileState {
    pub profile: ProfileData,
    pub edit_name: String,
    pub edit_bio: String,
    pub avatar_path: String,
    pub avatar_bytes: Vec<u8>,
    pub avatar_texture: Option<egui::TextureHandle>,
    pub remove_avatar: bool,
    pub status_msg: String,
    pub status_is_error: bool,
    pub editing: bool,
}

impl ProfileState {
    pub fn new() -> Self {
        Self {
            profile: ProfileData::default(),
            edit_name: String::new(),
            edit_bio: String::new(),
            avatar_path: String::new(),
            avatar_bytes: Vec::new(),
            avatar_texture: None,
            remove_avatar: false,
            status_msg: String::new(),
            status_is_error: false,
            editing: false,
        }
    }

    /// Loads an avatar image from bytes into an egui texture.
    pub fn load_avatar_texture(
        &mut self,
        ctx: &egui::Context,
        data: &[u8],
    ) {
        // Attempt to decode the image. If it fails, silently ignore
        // (corrupted avatar is non-critical).
        let decoded = image::load_from_memory(data);
        let img = match decoded {
            Ok(img) => img.to_rgba8(),
            Err(_) => return,
        };

        let size = [img.width() as usize, img.height() as usize];
        let pixels = img.as_flat_samples();
        let color_image = egui::ColorImage::from_rgba_unmultiplied(
            size,
            pixels.as_slice(),
        );
        self.avatar_texture = Some(ctx.load_texture(
            "profile_avatar",
            color_image,
            egui::TextureOptions::LINEAR,
        ));
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render(
    state: &mut ProfileState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    ui.add_space(theme::PANEL_PADDING);
    ui.label(theme::header("Profile"));
    ui.separator();
    ui.add_space(theme::ITEM_SPACING);

    if !state.editing {
        render_view(state, ui, cmd_tx);
    } else {
        render_edit(state, ui, cmd_tx);
    }
}

fn render_view(
    state: &mut ProfileState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    ui.horizontal(|ui| {
        // Avatar display.
        match &state.avatar_texture {
            Some(tex) => {
                let size = egui::vec2(80.0, 80.0);
                ui.image(egui::load::SizedTexture::new(tex.id(), size));
            }
            None => {
                let (rect, _) = ui.allocate_exact_size(
                    egui::vec2(80.0, 80.0),
                    egui::Sense::hover(),
                );
                ui.painter()
                    .circle_filled(rect.center(), 40.0, theme::ACCENT);
                let initial = state
                    .profile
                    .name
                    .chars()
                    .next()
                    .unwrap_or('?')
                    .to_uppercase()
                    .to_string();
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    initial,
                    egui::FontId::proportional(28.0),
                    egui::Color32::WHITE,
                );
            }
        }

        ui.vertical(|ui| {
            if state.profile.name.is_empty() {
                ui.label(theme::muted("(no name set)"));
            } else {
                ui.label(
                    egui::RichText::new(&state.profile.name)
                        .size(theme::FONT_HEADER),
                );
            }

            if !state.profile.bio.is_empty() {
                ui.label(theme::body(&state.profile.bio));
            }

            ui.add_space(theme::ITEM_SPACING);
            ui.label(theme::muted(&format!(
                "Address: {}",
                theme::truncate_hex(&state.profile.address, 16),
            )));

            if !state.profile.avatar_cid.is_empty() {
                ui.label(theme::muted(&format!(
                    "Avatar CID: {}",
                    theme::truncate_hex(&state.profile.avatar_cid, 16),
                )));
            }

            if state.profile.version > 0 {
                ui.label(theme::muted(&format!(
                    "Version: {} | Updated: {}",
                    state.profile.version,
                    state.profile.timestamp,
                )));
            }
        });
    });

    ui.add_space(theme::SECTION_SPACING);

    ui.horizontal(|ui| {
        if theme::accent_button(ui, "Edit Profile").clicked() {
            state.editing = true;
            state.edit_name = state.profile.name.clone();
            state.edit_bio = state.profile.bio.clone();
            state.avatar_path.clear();
            state.avatar_bytes.clear();
            state.remove_avatar = false;
            state.status_msg.clear();
        }
        if ui.button("Refresh").clicked() {
            let addr = state.profile.address.clone();
            if !addr.is_empty() {
                let _ = cmd_tx.try_send(UiCommand::GetProfile { address: addr });
            }
        }
    });

    if !state.status_msg.is_empty() {
        ui.add_space(theme::ITEM_SPACING);
        let color = if state.status_is_error {
            theme::DANGER
        } else {
            theme::SUCCESS
        };
        ui.colored_label(color, &state.status_msg);
    }
}

fn render_edit(
    state: &mut ProfileState,
    ui: &mut egui::Ui,
    cmd_tx: &tokio::sync::mpsc::Sender<UiCommand>,
) {
    ui.label("Display name:");
    ui.add(
        egui::TextEdit::singleline(&mut state.edit_name)
            .desired_width(300.0)
            .hint_text("Your name"),
    );

    ui.add_space(theme::ITEM_SPACING);
    ui.label("Bio:");
    ui.add(
        egui::TextEdit::multiline(&mut state.edit_bio)
            .desired_width(400.0)
            .desired_rows(3)
            .hint_text("Tell something about yourself..."),
    );

    ui.add_space(theme::ITEM_SPACING);
    ui.label("Avatar image (PNG or JPEG):");
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.avatar_path)
                .desired_width(300.0)
                .hint_text("/path/to/avatar.png"),
        );
        if ui.button("Load").clicked() && !state.avatar_path.is_empty() {
            let path = state.avatar_path.clone();
            match std::fs::read(&path) {
                Ok(data) => {
                    state.avatar_bytes = data;
                    state.status_msg = "Avatar loaded.".into();
                    state.status_is_error = false;
                }
                Err(e) => {
                    state.status_msg = format!("Failed to read file: {e}");
                    state.status_is_error = true;
                }
            }
        }
    });

    ui.checkbox(&mut state.remove_avatar, "Remove current avatar");

    if !state.status_msg.is_empty() {
        let color = if state.status_is_error {
            theme::DANGER
        } else {
            theme::SUCCESS
        };
        ui.colored_label(color, &state.status_msg);
    }

    ui.add_space(theme::SECTION_SPACING);
    ui.horizontal(|ui| {
        if theme::accent_button(ui, "Save").clicked() {
            let _ = cmd_tx.try_send(UiCommand::UpdateProfile {
                name: state.edit_name.trim().to_string(),
                bio: state.edit_bio.trim().to_string(),
                avatar: state.avatar_bytes.clone(),
                remove_avatar: state.remove_avatar,
            });
            state.editing = false;
            state.status_msg = "Profile update sent.".into();
            state.status_is_error = false;
        }
        if ui.button("Cancel").clicked() {
            state.editing = false;
            state.status_msg.clear();
        }
    });
}