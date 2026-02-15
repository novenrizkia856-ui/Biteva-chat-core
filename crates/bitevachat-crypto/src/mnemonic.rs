//! BIP39 mnemonic generation, validation, and seed derivation.
//!
//! Implements the full BIP39 specification for 24-word (256-bit entropy)
//! mnemonics:
//!
//! 1. **Generation**: 256-bit entropy → SHA-256 checksum (8 bits) →
//!    264 bits split into 24 × 11-bit indices → 24 BIP39 words.
//! 2. **Validation**: Reconstruct entropy from words, recompute and
//!    verify the checksum.
//! 3. **Seed derivation**: PBKDF2-HMAC-SHA512 with 2048 rounds,
//!    salt = `"mnemonic" + passphrase`, producing a 64-byte seed.
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

use bitevachat_types::{BitevachatError, Result};
use hmac::Hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::wordlist::{index_to_word, word_to_index, WORDLIST};

// ---------------------------------------------------------------------------
// Mnemonic
// ---------------------------------------------------------------------------

/// A BIP39 mnemonic phrase (24 space-separated words).
///
/// The inner string is zeroized on drop to prevent sensitive data from
/// lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic(String);

impl Mnemonic {
    /// Returns the mnemonic phrase as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the individual words as a vector of string slices.
    pub fn words(&self) -> Vec<&str> {
        self.0.split_whitespace().collect()
    }

    /// Returns the number of words in the mnemonic.
    pub fn word_count(&self) -> usize {
        self.0.split_whitespace().count()
    }
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

/// A 64-byte seed derived from a BIP39 mnemonic via PBKDF2-HMAC-SHA512.
///
/// This seed is the input to SLIP-0010 HD key derivation. Automatically
/// zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl Seed {
    /// Fixed byte length of a BIP39 seed.
    pub const LEN: usize = 64;

    /// Creates a [`Seed`] from a raw 64-byte array.
    ///
    /// Use this for reconstructing a seed from stored data or test
    /// vectors. For normal operation, use [`mnemonic_to_seed`].
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 64-byte seed.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

// Seed does not implement Clone/Debug to prevent leakage.

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generates a new random 24-word BIP39 mnemonic.
///
/// # Process (BIP39 spec)
///
/// 1. Generate 256 bits (32 bytes) of entropy from OS-level CSPRNG.
/// 2. Compute `SHA-256(entropy)` and take the first 8 bits as checksum.
/// 3. Concatenate: 256 entropy bits + 8 checksum bits = 264 bits.
/// 4. Split into 24 groups of 11 bits.
/// 5. Each 11-bit value is an index into the BIP39 English wordlist.
/// 6. Return the 24 words joined by spaces.
pub fn generate_mnemonic() -> Result<Mnemonic> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let result = entropy_to_mnemonic(&entropy);

    entropy.zeroize();
    result
}

/// Converts raw 256-bit entropy into a 24-word BIP39 mnemonic.
///
/// This is the deterministic core of mnemonic generation. Exposed for
/// testing with known test vectors.
pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> Result<Mnemonic> {
    // Step 1: SHA-256 checksum — take first byte (8 bits for 256-bit entropy).
    let checksum_full = Sha256::digest(entropy);
    let checksum_byte = checksum_full[0];

    // Step 2: Build 264-bit sequence as individual bits.
    //   264 = 256 (entropy) + 8 (checksum)
    //   24 words × 11 bits = 264 bits
    let mut bits = Vec::with_capacity(264);

    // Entropy bits (256).
    for byte in entropy.iter() {
        for j in (0..8).rev() {
            bits.push((byte >> j) & 1);
        }
    }

    // Checksum bits (8).
    for j in (0..8).rev() {
        bits.push((checksum_byte >> j) & 1);
    }

    // Step 3: Split into 24 groups of 11 bits → word indices.
    let mut words = Vec::with_capacity(24);

    for i in 0..24 {
        let mut idx: u16 = 0;
        for j in 0..11 {
            idx = (idx << 1) | (bits[i * 11 + j] as u16);
        }

        let word = index_to_word(idx).ok_or_else(|| BitevachatError::CryptoError {
            reason: format!("BIP39 word index {idx} out of range"),
        })?;

        words.push(word);
    }

    Ok(Mnemonic(words.join(" ")))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates a BIP39 mnemonic phrase.
///
/// # Checks performed
///
/// 1. Exactly 24 words.
/// 2. Every word exists in the BIP39 English wordlist.
/// 3. Reconstruct entropy from the 11-bit indices.
/// 4. Recompute `SHA-256(entropy)` and verify the 8-bit checksum matches.
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if any check fails.
pub fn validate_mnemonic(words: &str) -> Result<()> {
    let word_list: Vec<&str> = words.split_whitespace().collect();

    // Check 1: exactly 24 words.
    if word_list.len() != 24 {
        return Err(BitevachatError::CryptoError {
            reason: format!(
                "BIP39 mnemonic must be 24 words, got {}",
                word_list.len()
            ),
        });
    }

    // Check 2 & 3: all words valid, reconstruct 264 bits.
    let mut bits = Vec::with_capacity(264);

    for word in &word_list {
        let idx = word_to_index(word).ok_or_else(|| BitevachatError::CryptoError {
            reason: format!("word '{word}' not in BIP39 wordlist"),
        })?;

        // Emit 11 bits (MSB first).
        for j in (0..11).rev() {
            bits.push(((idx >> j) & 1) as u8);
        }
    }

    // Check 3: reconstruct entropy (first 256 bits).
    let mut entropy = [0u8; 32];
    for i in 0..256 {
        if bits[i] == 1 {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    // Check 3: extract provided checksum (last 8 bits).
    let mut provided_checksum: u8 = 0;
    for i in 0..8 {
        if bits[256 + i] == 1 {
            provided_checksum |= 1 << (7 - i);
        }
    }

    // Check 4: recompute checksum and compare.
    let expected_checksum = Sha256::digest(&entropy)[0];

    entropy.zeroize();

    if provided_checksum != expected_checksum {
        return Err(BitevachatError::CryptoError {
            reason: "BIP39 mnemonic checksum mismatch".into(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Seed derivation
// ---------------------------------------------------------------------------

/// Derives a 64-byte seed from a BIP39 mnemonic and optional passphrase.
///
/// # Process (BIP39 spec)
///
/// - **Password**: the mnemonic sentence (UTF-8 NFKD normalized, though
///   the BIP39 English wordlist uses only ASCII so NFKD is a no-op).
/// - **Salt**: `"mnemonic"` concatenated with `passphrase`.
/// - **Algorithm**: PBKDF2-HMAC-SHA512.
/// - **Rounds**: 2048 (fixed per BIP39).
/// - **Output**: 64 bytes.
///
/// # Parameters
///
/// - `mnemonic` — the 24-word mnemonic string.
/// - `passphrase` — optional passphrase (use `""` for no passphrase).
///
/// # Errors
///
/// Returns [`BitevachatError::CryptoError`] if PBKDF2 computation fails.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<Seed> {
    let password = mnemonic.as_bytes();

    // Salt = "mnemonic" + passphrase (BIP39 spec).
    let mut salt = Vec::with_capacity(8 + passphrase.len());
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase.as_bytes());

    let mut output = [0u8; 64];

    // PBKDF2-HMAC-SHA512, 2048 rounds, 64-byte output.
    pbkdf2::pbkdf2::<Hmac<Sha512>>(password, &salt, 2048, &mut output).map_err(|e| {
        BitevachatError::CryptoError {
            reason: format!("PBKDF2-HMAC-SHA512 failed: {e}"),
        }
    })?;

    salt.zeroize();

    Ok(Seed(output))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_words() -> std::result::Result<(), BitevachatError> {
        let mnemonic = generate_mnemonic()?;
        assert_eq!(mnemonic.word_count(), 24);
        Ok(())
    }

    #[test]
    fn generated_mnemonic_validates() -> std::result::Result<(), BitevachatError> {
        let mnemonic = generate_mnemonic()?;
        validate_mnemonic(mnemonic.as_str())?;
        Ok(())
    }

    #[test]
    fn all_words_in_wordlist() -> std::result::Result<(), BitevachatError> {
        let mnemonic = generate_mnemonic()?;
        for word in mnemonic.words() {
            assert!(
                WORDLIST.binary_search(&word).is_ok(),
                "word '{word}' not in BIP39 wordlist"
            );
        }
        Ok(())
    }

    /// BIP39 test vector: 256 bits of 0x00.
    /// Expected mnemonic: "abandon" × 23 + "art".
    #[test]
    fn entropy_all_zeros() -> std::result::Result<(), BitevachatError> {
        let entropy = [0x00u8; 32];
        let mnemonic = entropy_to_mnemonic(&entropy)?;
        let words = mnemonic.words();
        assert_eq!(words.len(), 24);
        for word in &words[..23] {
            assert_eq!(*word, "abandon");
        }
        assert_eq!(words[23], "art");
        Ok(())
    }

    /// BIP39 test vector: 256 bits of 0xFF.
    /// Expected mnemonic: "zoo" × 23 + "vote".
    #[test]
    fn entropy_all_ff() -> std::result::Result<(), BitevachatError> {
        let entropy = [0xFFu8; 32];
        let mnemonic = entropy_to_mnemonic(&entropy)?;
        let words = mnemonic.words();
        assert_eq!(words.len(), 24);
        for word in &words[..23] {
            assert_eq!(*word, "zoo");
        }
        // Last word depends on SHA-256 checksum of [0xFF; 32].
        assert_eq!(words[23], "vote");
        Ok(())
    }

    /// BIP39 test vector: 256 bits of 0x7F.
    #[test]
    fn entropy_all_7f() -> std::result::Result<(), BitevachatError> {
        let entropy = [0x7Fu8; 32];
        let mnemonic = entropy_to_mnemonic(&entropy)?;
        let expected = "legal winner thank year wave sausage worth useful \
                        legal winner thank year wave sausage worth useful \
                        legal winner thank year wave sausage worth title";
        assert_eq!(mnemonic.as_str(), expected);
        Ok(())
    }

    #[test]
    fn validate_rejects_wrong_word_count() {
        let result = validate_mnemonic("abandon abandon abandon");
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_invalid_word() {
        let mut words = vec!["abandon"; 24];
        words[5] = "notaword";
        let phrase = words.join(" ");
        assert!(validate_mnemonic(&phrase).is_err());
    }

    #[test]
    fn validate_rejects_bad_checksum() {
        // 23 × "abandon" + "abandon" has wrong checksum (should be "art").
        let words = vec!["abandon"; 24];
        let phrase = words.join(" ");
        assert!(validate_mnemonic(&phrase).is_err());
    }

    /// TREZOR BIP39 test vector: all-zero entropy + passphrase "TREZOR".
    #[test]
    fn seed_derivation_trezor_vector() -> std::result::Result<(), BitevachatError> {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";

        let seed = mnemonic_to_seed(mnemonic, "TREZOR")?;

        let expected_hex = "bda85446c68413707090a52022edd26a1c946229\
                            5029f2e60cd7c4f2bbd3097170af7a4d73245caf\
                            a9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d6\
                            8f92fcc8";
        let expected = hex_to_bytes(expected_hex)?;
        assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
        Ok(())
    }

    /// TREZOR BIP39 test vector: all-0x7F entropy + passphrase "TREZOR".
    #[test]
    fn seed_derivation_trezor_7f() -> std::result::Result<(), BitevachatError> {
        let mnemonic = "legal winner thank year wave sausage worth useful \
                        legal winner thank year wave sausage worth useful \
                        legal winner thank year wave sausage worth title";

        let seed = mnemonic_to_seed(mnemonic, "TREZOR")?;

        let expected_hex = "bc09fca1804f7e69da93c2f2028eb238c227f2e9\
                            dda30cd63699232578480a4021b146ad717fbb7e\
                            451ce9eb835f43620bf5c514db0f8add49f5d121\
                            449d3e87";
        let expected = hex_to_bytes(expected_hex)?;
        assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn seed_with_empty_passphrase_differs() -> std::result::Result<(), BitevachatError> {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";

        let seed_no_pass = mnemonic_to_seed(mnemonic, "")?;
        let seed_with_pass = mnemonic_to_seed(mnemonic, "TREZOR")?;
        assert_ne!(seed_no_pass.as_bytes(), seed_with_pass.as_bytes());
        Ok(())
    }

    #[test]
    fn seed_is_deterministic() -> std::result::Result<(), BitevachatError> {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";

        let s1 = mnemonic_to_seed(mnemonic, "test")?;
        let s2 = mnemonic_to_seed(mnemonic, "test")?;
        assert_eq!(s1.as_bytes(), s2.as_bytes());
        Ok(())
    }

    // --- Test utility ---

    fn hex_to_bytes(hex: &str) -> std::result::Result<Vec<u8>, BitevachatError> {
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() % 2 != 0 {
            return Err(BitevachatError::CryptoError {
                reason: "odd-length hex string".into(),
            });
        }
        let mut bytes = Vec::with_capacity(clean.len() / 2);
        for i in (0..clean.len()).step_by(2) {
            let byte = u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| {
                BitevachatError::CryptoError {
                    reason: format!("invalid hex: {e}"),
                }
            })?;
            bytes.push(byte);
        }
        Ok(bytes)
    }
}