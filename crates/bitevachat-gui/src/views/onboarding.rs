//! Wallet onboarding and unlock flow.
//!
//! Scenarios:
//! - **No wallet file** → full onboarding (create or import).
//! - **Wallet file exists** → passphrase unlock screen.
//!
//! Seed words are displayed once, then cleared from memory.
//! No seed data is written to logs.

use std::path::PathBuf;

use eframe::egui;
use zeroize::Zeroize;

use crate::embedded;
use crate::theme;

// ---------------------------------------------------------------------------
// Onboarding result (consumed by app.rs)
// ---------------------------------------------------------------------------

/// Produced when onboarding completes. Contains everything needed
/// to bootstrap the embedded node.
pub struct OnboardingResult {
    pub data_dir: PathBuf,
    /// `Some(mnemonic)` for new wallets, `None` for existing.
    pub mnemonic: Option<String>,
    pub passphrase: String,
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnboardingStep {
    /// Detect wallet: if exists → UnlockExisting, else → Welcome.
    Detect,
    /// Passphrase prompt for an existing wallet.
    UnlockExisting,
    /// Choose: create or import.
    Welcome,
    /// About to generate seed.
    CreateSeed,
    /// Displaying the 24 words.
    DisplaySeed,
    /// Confirm 4 selected words.
    ConfirmSeed,
    /// Set passphrase (new wallet).
    SetPassphrase,
    /// Import: enter 24 words.
    ImportEnterWords,
    /// Import: set passphrase.
    ImportPassphrase,
    /// Starting node (progress indicator).
    Starting,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct OnboardingState {
    pub step: OnboardingStep,
    /// Data directory path (user-editable).
    pub data_dir: String,
    /// Generated or imported seed words (cleared after use).
    seed_words: Vec<String>,
    /// Confirmation input.
    confirm_input: String,
    /// Import text area.
    import_input: String,
    /// Passphrase inputs.
    passphrase: String,
    passphrase_confirm: String,
    /// Checkboxes.
    check_written: bool,
    check_understand: bool,
    /// Error message.
    error_msg: String,
    /// Completed result — consumed by app.rs.
    pub result: Option<OnboardingResult>,
}

impl OnboardingState {
    pub fn new() -> Self {
        let default_dir = embedded::default_data_dir();
        let data_dir_str = default_dir.to_string_lossy().to_string();

        Self {
            step: OnboardingStep::Detect,
            data_dir: data_dir_str,
            seed_words: Vec::new(),
            confirm_input: String::new(),
            import_input: String::new(),
            passphrase: String::new(),
            passphrase_confirm: String::new(),
            check_written: false,
            check_understand: false,
            error_msg: String::new(),
            result: None,
        }
    }

    /// Clears all sensitive data from memory.
    fn clear_sensitive(&mut self) {
        for word in &mut self.seed_words {
            let len = word.len();
            *word = "\0".repeat(len);
        }
        self.seed_words.clear();

        zeroize_string(&mut self.passphrase);
        zeroize_string(&mut self.passphrase_confirm);
        zeroize_string(&mut self.confirm_input);
        zeroize_string(&mut self.import_input);
    }

    /// Generates 24 BIP39 seed words using the `bip39` crate.
    fn generate_seed(&mut self) -> Result<(), String> {
        use rand::RngCore;
        let mut entropy = [0u8; 32]; // 256 bits → 24 words
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| format!("mnemonic generation failed: {e}"))?;
        let phrase = mnemonic.to_string();
        self.seed_words = phrase
            .split_whitespace()
            .map(String::from)
            .collect();
        Ok(())
    }
}

fn zeroize_string(s: &mut String) {
    // Overwrite with zeros before clearing.
    let bytes = unsafe { s.as_bytes_mut() };
    bytes.zeroize();
    s.clear();
}

// ---------------------------------------------------------------------------
// Render — returns true when result is ready
// ---------------------------------------------------------------------------

pub fn render(state: &mut OnboardingState, ui: &mut egui::Ui) -> bool {
    ui.vertical_centered(|ui| {
        ui.add_space(theme::SECTION_SPACING);
        ui.label(theme::header("Bitevachat"));
        ui.add_space(4.0);
        ui.label(theme::muted("Decentralized Encrypted Chat"));
        ui.add_space(theme::SECTION_SPACING * 2.0);

        match state.step.clone() {
            OnboardingStep::Detect => render_detect(state, ui),
            OnboardingStep::UnlockExisting => render_unlock_existing(state, ui),
            OnboardingStep::Welcome => render_welcome(state, ui),
            OnboardingStep::CreateSeed => render_create_seed(state, ui),
            OnboardingStep::DisplaySeed => render_display_seed(state, ui),
            OnboardingStep::ConfirmSeed => render_confirm_seed(state, ui),
            OnboardingStep::SetPassphrase => render_set_passphrase(state, ui),
            OnboardingStep::ImportEnterWords => render_import_words(state, ui),
            OnboardingStep::ImportPassphrase => render_import_passphrase(state, ui),
            OnboardingStep::Starting => render_starting(state, ui),
        }
    });

    state.result.is_some()
}

// ---------------------------------------------------------------------------
// Step: Detect
// ---------------------------------------------------------------------------

fn render_detect(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Checking for existing wallet..."));
    ui.add_space(theme::SECTION_SPACING);

    // Data directory selector.
    render_data_dir_picker(state, ui);
    ui.add_space(theme::SECTION_SPACING);

    if theme::accent_button(ui, "Continue").clicked() {
        let dir = PathBuf::from(&state.data_dir);
        if embedded::wallet_exists_in(&dir) {
            state.step = OnboardingStep::UnlockExisting;
        } else {
            state.step = OnboardingStep::Welcome;
        }
        state.error_msg.clear();
    }
}

// ---------------------------------------------------------------------------
// Step: Unlock existing wallet
// ---------------------------------------------------------------------------

fn render_unlock_existing(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Wallet found. Enter your passphrase to unlock:"));
    ui.add_space(theme::SECTION_SPACING);

    render_data_dir_picker(state, ui);
    ui.add_space(theme::ITEM_SPACING);

    ui.label("Passphrase:");
    let resp = ui.add(
        egui::TextEdit::singleline(&mut state.passphrase)
            .password(true)
            .desired_width(300.0)
            .hint_text("Enter your wallet passphrase"),
    );

    if !state.error_msg.is_empty() {
        ui.colored_label(theme::DANGER, &state.error_msg);
    }

    ui.add_space(theme::SECTION_SPACING);

    let enter = resp.lost_focus()
        && ui.input(|i| i.key_pressed(egui::Key::Enter));
    let clicked = theme::accent_button(ui, "Unlock & Start").clicked();

    if (enter || clicked) && !state.passphrase.is_empty() {
        let passphrase = state.passphrase.clone();
        let data_dir = PathBuf::from(&state.data_dir);

        state.result = Some(OnboardingResult {
            data_dir,
            mnemonic: None, // existing wallet
            passphrase,
        });
        state.step = OnboardingStep::Starting;
    }

    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Use different wallet directory").clicked() {
        state.step = OnboardingStep::Detect;
    }
    if ui.button("Create new wallet instead").clicked() {
        state.step = OnboardingStep::Welcome;
    }
}

// ---------------------------------------------------------------------------
// Step: Welcome (new wallet)
// ---------------------------------------------------------------------------

fn render_welcome(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("No wallet found. Create a new wallet or import an existing one."));
    ui.add_space(theme::SECTION_SPACING);

    render_data_dir_picker(state, ui);
    ui.add_space(theme::SECTION_SPACING);

    if theme::accent_button(ui, "Create New Wallet").clicked() {
        state.step = OnboardingStep::CreateSeed;
    }
    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Import Existing Wallet").clicked() {
        state.step = OnboardingStep::ImportEnterWords;
    }
}

// ---------------------------------------------------------------------------
// Step: Create seed
// ---------------------------------------------------------------------------

fn render_create_seed(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body(
        "A new wallet will be generated. You will be shown 24 seed words.",
    ));
    ui.add_space(4.0);
    ui.label(theme::body(
        "Write them down on paper. Do NOT save digitally.",
    ));
    ui.add_space(theme::SECTION_SPACING);

    if !state.error_msg.is_empty() {
        ui.colored_label(theme::DANGER, &state.error_msg);
    }

    if theme::accent_button(ui, "Generate Seed").clicked() {
        match state.generate_seed() {
            Ok(()) => {
                state.error_msg.clear();
                state.step = OnboardingStep::DisplaySeed;
            }
            Err(e) => {
                state.error_msg = e;
            }
        }
    }
    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Back").clicked() {
        state.step = OnboardingStep::Welcome;
    }
}

// ---------------------------------------------------------------------------
// Step: Display seed
// ---------------------------------------------------------------------------

fn render_display_seed(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Write down these 24 words in order:"));
    ui.add_space(theme::SECTION_SPACING);

    egui::Grid::new("seed_grid")
        .num_columns(4)
        .spacing([20.0, 8.0])
        .show(ui, |ui| {
            for (i, word) in state.seed_words.iter().enumerate() {
                let label = format!("{}. {}", i + 1, word);
                ui.label(
                    egui::RichText::new(label)
                        .size(theme::FONT_BODY)
                        .monospace(),
                );
                if (i + 1) % 4 == 0 {
                    ui.end_row();
                }
            }
        });

    ui.add_space(theme::SECTION_SPACING);
    ui.checkbox(&mut state.check_written, "I have written down all 24 words");
    ui.checkbox(
        &mut state.check_understand,
        "I understand these words cannot be recovered if lost",
    );

    ui.add_space(theme::SECTION_SPACING);
    let can_proceed = state.check_written && state.check_understand;
    ui.add_enabled_ui(can_proceed, |ui| {
        if theme::accent_button(ui, "Continue").clicked() {
            state.step = OnboardingStep::ConfirmSeed;
            state.error_msg.clear();
        }
    });
}

// ---------------------------------------------------------------------------
// Step: Confirm seed
// ---------------------------------------------------------------------------

fn render_confirm_seed(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Enter word #1, #6, #12, and #24 to confirm:"));
    ui.add_space(theme::SECTION_SPACING);

    ui.label(theme::muted("Format: word1 word6 word12 word24"));
    let response = ui.add(
        egui::TextEdit::singleline(&mut state.confirm_input)
            .desired_width(400.0)
            .hint_text("Enter the 4 words separated by spaces"),
    );

    if !state.error_msg.is_empty() {
        ui.colored_label(theme::DANGER, &state.error_msg);
    }

    ui.add_space(theme::SECTION_SPACING);
    let clicked = theme::accent_button(ui, "Verify").clicked();
    let enter = response.lost_focus()
        && ui.input(|i| i.key_pressed(egui::Key::Enter));

    if clicked || enter {
        let parts: Vec<&str> = state.confirm_input.trim().split_whitespace().collect();
        if parts.len() == 4 {
            let expected = [
                state.seed_words.get(0).map(|s| s.as_str()).unwrap_or(""),
                state.seed_words.get(5).map(|s| s.as_str()).unwrap_or(""),
                state.seed_words.get(11).map(|s| s.as_str()).unwrap_or(""),
                state.seed_words.get(23).map(|s| s.as_str()).unwrap_or(""),
            ];
            if parts[0] == expected[0]
                && parts[1] == expected[1]
                && parts[2] == expected[2]
                && parts[3] == expected[3]
            {
                state.error_msg.clear();
                state.step = OnboardingStep::SetPassphrase;
            } else {
                state.error_msg = "Words do not match. Please try again.".into();
            }
        } else {
            state.error_msg = "Enter exactly 4 words separated by spaces.".into();
        }
    }

    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Back (show seed again)").clicked() {
        state.step = OnboardingStep::DisplaySeed;
    }
}

// ---------------------------------------------------------------------------
// Step: Set passphrase (new wallet)
// ---------------------------------------------------------------------------

fn render_set_passphrase(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Set a passphrase to encrypt your wallet:"));
    ui.add_space(theme::SECTION_SPACING);

    ui.label("Passphrase (min 8 characters):");
    ui.add(
        egui::TextEdit::singleline(&mut state.passphrase)
            .password(true)
            .desired_width(300.0),
    );

    ui.add_space(theme::ITEM_SPACING);
    ui.label("Confirm passphrase:");
    ui.add(
        egui::TextEdit::singleline(&mut state.passphrase_confirm)
            .password(true)
            .desired_width(300.0),
    );

    if !state.error_msg.is_empty() {
        ui.colored_label(theme::DANGER, &state.error_msg);
    }

    ui.add_space(theme::SECTION_SPACING);
    if theme::accent_button(ui, "Create Wallet & Start").clicked() {
        if state.passphrase.len() < 8 {
            state.error_msg = "Passphrase must be at least 8 characters.".into();
        } else if state.passphrase != state.passphrase_confirm {
            state.error_msg = "Passphrases do not match.".into();
        } else {
            state.error_msg.clear();
            // Build the mnemonic string.
            let mnemonic = state.seed_words.join(" ");
            let passphrase = state.passphrase.clone();
            let data_dir = PathBuf::from(&state.data_dir);

            state.result = Some(OnboardingResult {
                data_dir,
                mnemonic: Some(mnemonic),
                passphrase,
            });
            state.clear_sensitive();
            state.step = OnboardingStep::Starting;
        }
    }
}

// ---------------------------------------------------------------------------
// Step: Import words
// ---------------------------------------------------------------------------

fn render_import_words(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Enter your 24 seed words separated by spaces:"));
    ui.add_space(theme::SECTION_SPACING);

    ui.add(
        egui::TextEdit::multiline(&mut state.import_input)
            .desired_width(500.0)
            .desired_rows(4)
            .hint_text("abandon ability able about ..."),
    );

    if !state.error_msg.is_empty() {
        ui.colored_label(theme::DANGER, &state.error_msg);
    }

    ui.add_space(theme::SECTION_SPACING);
    if theme::accent_button(ui, "Validate & Continue").clicked() {
        let words: Vec<&str> = state.import_input.trim().split_whitespace().collect();
        if words.len() != 24 {
            state.error_msg = format!("Expected 24 words, got {}.", words.len());
        } else {
            state.error_msg.clear();
            state.seed_words = words.iter().map(|w| w.to_string()).collect();
            state.step = OnboardingStep::ImportPassphrase;
        }
    }

    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Back").clicked() {
        state.step = OnboardingStep::Welcome;
    }
}

// ---------------------------------------------------------------------------
// Step: Import passphrase
// ---------------------------------------------------------------------------

fn render_import_passphrase(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Set a passphrase to encrypt the imported wallet:"));
    ui.add_space(theme::SECTION_SPACING);

    ui.label("Passphrase (min 8 characters):");
    ui.add(
        egui::TextEdit::singleline(&mut state.passphrase)
            .password(true)
            .desired_width(300.0),
    );

    ui.add_space(theme::ITEM_SPACING);
    ui.label("Confirm passphrase:");
    ui.add(
        egui::TextEdit::singleline(&mut state.passphrase_confirm)
            .password(true)
            .desired_width(300.0),
    );

    if !state.error_msg.is_empty() {
        ui.colored_label(theme::DANGER, &state.error_msg);
    }

    ui.add_space(theme::SECTION_SPACING);
    if theme::accent_button(ui, "Import Wallet & Start").clicked() {
        if state.passphrase.len() < 8 {
            state.error_msg = "Passphrase must be at least 8 characters.".into();
        } else if state.passphrase != state.passphrase_confirm {
            state.error_msg = "Passphrases do not match.".into();
        } else {
            state.error_msg.clear();
            let mnemonic = state.seed_words.join(" ");
            let passphrase = state.passphrase.clone();
            let data_dir = PathBuf::from(&state.data_dir);

            state.result = Some(OnboardingResult {
                data_dir,
                mnemonic: Some(mnemonic),
                passphrase,
            });
            state.clear_sensitive();
            state.step = OnboardingStep::Starting;
        }
    }

    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Back").clicked() {
        state.step = OnboardingStep::ImportEnterWords;
    }
}

// ---------------------------------------------------------------------------
// Step: Starting (progress indicator)
// ---------------------------------------------------------------------------

fn render_starting(_state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("Starting node...")
            .size(theme::FONT_HEADER)
            .color(theme::ACCENT),
    );
    ui.add_space(theme::SECTION_SPACING);
    ui.spinner();
    ui.add_space(theme::ITEM_SPACING);
    ui.label(theme::muted("Initializing wallet, storage, and network. This may take a moment."));
}

// ---------------------------------------------------------------------------
// Data directory picker (shared widget)
// ---------------------------------------------------------------------------

fn render_data_dir_picker(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Data directory:");
        ui.add(
            egui::TextEdit::singleline(&mut state.data_dir)
                .desired_width(400.0)
                .hint_text("Path to store wallet and data"),
        );
    });
    ui.label(theme::muted("Wallet, storage, and configuration will be saved here."));
}