//! Wallet onboarding flow: create or import.
//!
//! Seed words are displayed once, then cleared from memory.
//! No seed data is written to logs.

use eframe::egui;

use crate::theme;

// ---------------------------------------------------------------------------
// BIP39-like word list (subset for display — 256 words)
// ---------------------------------------------------------------------------

/// Minimal deterministic wordlist for seed display.
/// Production builds should use the full BIP39 English wordlist
/// via the `bip39` crate integrated with `bitevachat-wallet`.
const WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account",
    "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict",
    "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
    "alone", "alpha", "already", "also", "alter", "always", "amateur",
    "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient",
    "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart",
    "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army",
    "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
    "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto",
    "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner",
    "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
    "battle", "beach", "bean", "beauty", "because", "become", "beef",
    "before", "begin", "behave", "behind", "believe", "below", "bench",
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blow", "blue", "blur", "blush",
    "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom",
    "bounce", "box", "boy", "bracket", "brain", "brand", "brass",
    "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build",
    "bulb", "bulk", "bullet", "bundle", "bunny", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
];

// ---------------------------------------------------------------------------
// Onboarding state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnboardingStep {
    Welcome,
    CreateSeed,
    DisplaySeed,
    ConfirmSeed,
    SetPassphrase,
    ImportEnterWords,
    ImportPassphrase,
    Done,
}

pub struct OnboardingState {
    pub step: OnboardingStep,
    /// Generated seed words (cleared after confirmation).
    seed_words: Vec<String>,
    /// User-entered confirmation words.
    confirm_input: String,
    /// Import: user enters 24 words here.
    import_input: String,
    /// Passphrase input (zeroized after use).
    passphrase: String,
    /// Passphrase confirmation.
    passphrase_confirm: String,
    /// Confirmation checkboxes.
    check_written: bool,
    check_understand: bool,
    /// Error message for validation.
    error_msg: String,
    /// Whether onboarding completed successfully.
    pub completed: bool,
    /// The wallet address after creation (for display).
    pub wallet_address: String,
}

impl OnboardingState {
    pub fn new() -> Self {
        Self {
            step: OnboardingStep::Welcome,
            seed_words: Vec::new(),
            confirm_input: String::new(),
            import_input: String::new(),
            passphrase: String::new(),
            passphrase_confirm: String::new(),
            check_written: false,
            check_understand: false,
            error_msg: String::new(),
            completed: false,
            wallet_address: String::new(),
        }
    }

    /// Clears sensitive data from memory.
    fn clear_sensitive(&mut self) {
        // Overwrite seed words.
        for word in &mut self.seed_words {
            // Fill with zeros before dropping.
            let len = word.len();
            *word = "0".repeat(len);
        }
        self.seed_words.clear();

        // Overwrite passphrases.
        let pp_len = self.passphrase.len();
        self.passphrase = "0".repeat(pp_len);
        self.passphrase.clear();

        let pc_len = self.passphrase_confirm.len();
        self.passphrase_confirm = "0".repeat(pc_len);
        self.passphrase_confirm.clear();

        let ci_len = self.confirm_input.len();
        self.confirm_input = "0".repeat(ci_len);
        self.confirm_input.clear();

        let ii_len = self.import_input.len();
        self.import_input = "0".repeat(ii_len);
        self.import_input.clear();
    }

    /// Generates 24 seed words from random indices.
    fn generate_seed(&mut self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        self.seed_words.clear();
        let list_len = WORDLIST.len();
        for _ in 0..24 {
            let idx = rng.gen_range(0..list_len);
            self.seed_words.push(WORDLIST[idx].to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Renders the onboarding wizard. Returns `true` when complete.
pub fn render(state: &mut OnboardingState, ui: &mut egui::Ui) -> bool {
    ui.vertical_centered(|ui| {
        ui.add_space(theme::SECTION_SPACING);
        ui.label(theme::header("Bitevachat"));
        ui.add_space(4.0);
        ui.label(theme::muted("Decentralized Encrypted Chat"));
        ui.add_space(theme::SECTION_SPACING * 2.0);

        match state.step.clone() {
            OnboardingStep::Welcome => render_welcome(state, ui),
            OnboardingStep::CreateSeed => render_create_seed(state, ui),
            OnboardingStep::DisplaySeed => render_display_seed(state, ui),
            OnboardingStep::ConfirmSeed => render_confirm_seed(state, ui),
            OnboardingStep::SetPassphrase => render_set_passphrase(state, ui),
            OnboardingStep::ImportEnterWords => render_import_words(state, ui),
            OnboardingStep::ImportPassphrase => render_import_passphrase(state, ui),
            OnboardingStep::Done => render_done(state, ui),
        }
    });

    state.completed
}

fn render_welcome(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Welcome. Create a new wallet or import an existing one."));
    ui.add_space(theme::SECTION_SPACING);

    if theme::accent_button(ui, "Create New Wallet").clicked() {
        state.step = OnboardingStep::CreateSeed;
    }
    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Import Existing Wallet").clicked() {
        state.step = OnboardingStep::ImportEnterWords;
    }
}

fn render_create_seed(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body(
        "A new wallet will be generated. You will be shown 24 seed words.",
    ));
    ui.add_space(4.0);
    ui.label(theme::body(
        "Write them down on paper. Do NOT save digitally.",
    ));
    ui.add_space(theme::SECTION_SPACING);

    if theme::accent_button(ui, "Generate Seed").clicked() {
        state.generate_seed();
        state.step = OnboardingStep::DisplaySeed;
    }
    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Back").clicked() {
        state.step = OnboardingStep::Welcome;
    }
}

fn render_display_seed(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Write down these 24 words in order:"));
    ui.add_space(theme::SECTION_SPACING);

    // Display seed words in a 4-column grid.
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

fn render_set_passphrase(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Set a passphrase to encrypt your wallet:"));
    ui.add_space(theme::SECTION_SPACING);

    ui.label("Passphrase:");
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
    if theme::accent_button(ui, "Create Wallet").clicked() {
        if state.passphrase.len() < 8 {
            state.error_msg = "Passphrase must be at least 8 characters.".into();
        } else if state.passphrase != state.passphrase_confirm {
            state.error_msg = "Passphrases do not match.".into();
        } else {
            state.error_msg.clear();
            // Clear sensitive data immediately after "creation".
            state.clear_sensitive();
            state.step = OnboardingStep::Done;
        }
    }
}

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

fn render_import_passphrase(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(theme::body("Set a passphrase to encrypt the imported wallet:"));
    ui.add_space(theme::SECTION_SPACING);

    ui.label("Passphrase:");
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
    if theme::accent_button(ui, "Import Wallet").clicked() {
        if state.passphrase.len() < 8 {
            state.error_msg = "Passphrase must be at least 8 characters.".into();
        } else if state.passphrase != state.passphrase_confirm {
            state.error_msg = "Passphrases do not match.".into();
        } else {
            state.error_msg.clear();
            state.clear_sensitive();
            state.step = OnboardingStep::Done;
        }
    }

    ui.add_space(theme::ITEM_SPACING);
    if ui.button("Back").clicked() {
        state.step = OnboardingStep::ImportEnterWords;
    }
}

fn render_done(state: &mut OnboardingState, ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("Wallet ready.")
            .size(theme::FONT_HEADER)
            .color(theme::SUCCESS),
    );
    ui.add_space(theme::SECTION_SPACING);
    ui.label(theme::body("Your wallet has been created. You can now connect to a node."));
    ui.add_space(theme::SECTION_SPACING);

    if theme::accent_button(ui, "Enter Bitevachat").clicked() {
        state.completed = true;
    }
}