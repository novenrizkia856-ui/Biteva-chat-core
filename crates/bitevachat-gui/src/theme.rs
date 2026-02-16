//! Visual theme for the Bitevachat desktop GUI.
//!
//! Classic, muted palette. Not overly modern.

use eframe::egui;

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

/// Background for the main window.
pub const BG_PRIMARY: egui::Color32 = egui::Color32::from_rgb(240, 237, 231);

/// Background for side panels.
pub const BG_SIDEBAR: egui::Color32 = egui::Color32::from_rgb(225, 221, 214);

/// Background for the chat input area.
pub const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(250, 248, 245);

/// Sent message bubble.
pub const BUBBLE_SENT: egui::Color32 = egui::Color32::from_rgb(200, 218, 230);

/// Received message bubble.
pub const BUBBLE_RECV: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);

/// Primary accent (buttons, links).
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(70, 110, 140);

/// Success indicator.
pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(80, 140, 80);

/// Error / danger indicator.
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(170, 60, 60);

/// Warning indicator.
pub const WARNING: egui::Color32 = egui::Color32::from_rgb(190, 150, 50);

/// Muted text.
pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(140, 135, 128);

/// Normal text.
pub const TEXT_NORMAL: egui::Color32 = egui::Color32::from_rgb(50, 48, 44);

/// Header text.
pub const TEXT_HEADER: egui::Color32 = egui::Color32::from_rgb(30, 28, 26);

/// Selected item in a list.
pub const SELECTED: egui::Color32 = egui::Color32::from_rgb(210, 225, 235);

/// Separator line.
pub const SEPARATOR: egui::Color32 = egui::Color32::from_rgb(200, 196, 190);

// ---------------------------------------------------------------------------
// Spacing
// ---------------------------------------------------------------------------

pub const PANEL_PADDING: f32 = 12.0;
pub const ITEM_SPACING: f32 = 6.0;
pub const SECTION_SPACING: f32 = 16.0;
pub const SIDEBAR_WIDTH: f32 = 260.0;
pub const BUBBLE_ROUNDING: f32 = 8.0;
pub const BUTTON_ROUNDING: f32 = 4.0;
pub const AVATAR_SIZE: f32 = 36.0;

// ---------------------------------------------------------------------------
// Font sizes
// ---------------------------------------------------------------------------

pub const FONT_HEADER: f32 = 18.0;
pub const FONT_BODY: f32 = 14.0;
pub const FONT_SMALL: f32 = 12.0;
pub const FONT_TINY: f32 = 10.0;

// ---------------------------------------------------------------------------
// Theme application
// ---------------------------------------------------------------------------

/// Applies the Bitevachat classic theme to an egui context.
pub fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    // Rounded buttons and frames.
    style.visuals.widgets.noninteractive.rounding =
        egui::Rounding::same(BUTTON_ROUNDING);
    style.visuals.widgets.inactive.rounding =
        egui::Rounding::same(BUTTON_ROUNDING);
    style.visuals.widgets.hovered.rounding =
        egui::Rounding::same(BUTTON_ROUNDING);
    style.visuals.widgets.active.rounding =
        egui::Rounding::same(BUTTON_ROUNDING);

    // Background colors.
    style.visuals.window_fill = BG_PRIMARY;
    style.visuals.panel_fill = BG_PRIMARY;
    style.visuals.faint_bg_color = BG_SIDEBAR;

    // Spacing.
    style.spacing.item_spacing = egui::vec2(ITEM_SPACING, ITEM_SPACING);
    style.spacing.window_margin = egui::Margin::same(PANEL_PADDING);

    // Text color.
    style.visuals.override_text_color = Some(TEXT_NORMAL);

    ctx.set_style(style);
}

/// Header label.
pub fn header(text: &str) -> egui::RichText {
    egui::RichText::new(text)
        .size(FONT_HEADER)
        .color(TEXT_HEADER)
        .strong()
}

/// Muted small text.
pub fn muted(text: &str) -> egui::RichText {
    egui::RichText::new(text)
        .size(FONT_SMALL)
        .color(TEXT_MUTED)
}

/// Body text.
pub fn body(text: &str) -> egui::RichText {
    egui::RichText::new(text).size(FONT_BODY)
}

/// Accent-colored button.
pub fn accent_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let button = egui::Button::new(
        egui::RichText::new(label).color(egui::Color32::WHITE),
    )
    .fill(ACCENT)
    .rounding(BUTTON_ROUNDING);
    ui.add(button)
}

/// Danger-colored button.
pub fn danger_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let button = egui::Button::new(
        egui::RichText::new(label).color(egui::Color32::WHITE),
    )
    .fill(DANGER)
    .rounding(BUTTON_ROUNDING);
    ui.add(button)
}

/// Truncates a hex string for display: first 8 chars + "...".
pub fn truncate_hex(s: &str, max_chars: usize) -> String {
    if s.len() > max_chars + 3 {
        format!("{}...", &s[..max_chars])
    } else {
        s.to_string()
    }
}