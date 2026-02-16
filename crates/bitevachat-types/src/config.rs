//! Application configuration with sensible defaults.
//!
//! All operational parameters are centralized here. Every value has a
//! documented default matching the Bitevachat specification.

use serde::{Deserialize, Serialize};

use crate::{BitevachatError, Result};

/// Global application configuration.
///
/// All values are configurable via settings file or runtime API.
/// Defaults match the Bitevachat specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    /// Time-to-live for pending (undelivered) messages, in days.
    /// Messages older than this are purged from the pending queue.
    pub pending_ttl_days: u64,

    /// Maximum number of messages retained per conversation.
    /// Oldest messages are pruned when the limit is exceeded.
    pub db_retention_messages: u64,

    /// Maximum number of messages a single sender can send per minute.
    pub rate_limit_per_min: u32,

    /// Maximum number of pending messages per recipient.
    /// Prevents a single offline recipient from consuming unbounded storage.
    pub pending_max: usize,

    /// Size of the nonce replay cache (number of recent nonces tracked).
    /// Used to detect and reject replayed messages.
    pub nonce_cache_size: usize,

    // ----- Anti-spam settings ---------------------------------------------

    /// Proof-of-work difficulty in leading zero bits.
    ///
    /// Required for senders with `Unknown` trust level. Capped at
    /// [`bitevachat_protocol::pow::MAX_DIFFICULTY`] (24).
    pub pow_difficulty: u8,

    /// Whether proof-of-work is required for unknown senders.
    ///
    /// When `false`, PoW checks are skipped entirely.
    pub enable_pow: bool,

    /// Number of successful interactions required for trust promotion.
    ///
    /// - `Unknown` → `Seen`: `trust_threshold` interactions.
    /// - `Seen` → `Trusted`: `trust_threshold * 3` interactions.
    pub trust_threshold: u32,

    /// Whether the system-level blocklist is enabled.
    ///
    /// When `false`, blocklist checks are skipped (all senders pass).
    pub blocklist_enabled: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            pending_ttl_days: 5,
            db_retention_messages: 1500,
            rate_limit_per_min: 10,
            pending_max: 500,
            nonce_cache_size: 10_000,
            pow_difficulty: 8,
            enable_pow: true,
            trust_threshold: 3,
            blocklist_enabled: true,
        }
    }
}

impl AppConfig {
    /// Validates all configuration values.
    ///
    /// Returns an error if any value is outside its acceptable range.
    pub fn validate(&self) -> Result<()> {
        if self.pending_ttl_days == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "pending_ttl_days must be greater than 0".into(),
            });
        }

        if self.db_retention_messages == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "db_retention_messages must be greater than 0".into(),
            });
        }

        if self.rate_limit_per_min == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "rate_limit_per_min must be greater than 0".into(),
            });
        }

        if self.pending_max == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "pending_max must be greater than 0".into(),
            });
        }

        if self.nonce_cache_size == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "nonce_cache_size must be greater than 0".into(),
            });
        }

        if self.pow_difficulty > 24 {
            return Err(BitevachatError::ConfigError {
                reason: "pow_difficulty must be 0..=24".into(),
            });
        }

        if self.trust_threshold == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "trust_threshold must be greater than 0".into(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_values_match_spec() {
        let config = AppConfig::default();
        assert_eq!(config.pending_ttl_days, 5);
        assert_eq!(config.db_retention_messages, 1500);
        assert_eq!(config.rate_limit_per_min, 10);
        assert_eq!(config.pending_max, 500);
        assert_eq!(config.nonce_cache_size, 10_000);
        assert_eq!(config.pow_difficulty, 8);
        assert!(config.enable_pow);
        assert_eq!(config.trust_threshold, 3);
        assert!(config.blocklist_enabled);
    }

    #[test]
    fn zero_pending_ttl_rejected() {
        let config = AppConfig {
            pending_ttl_days: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_retention_rejected() {
        let config = AppConfig {
            db_retention_messages: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_rate_limit_rejected() {
        let config = AppConfig {
            rate_limit_per_min: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_pending_max_rejected() {
        let config = AppConfig {
            pending_max: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_nonce_cache_rejected() {
        let config = AppConfig {
            nonce_cache_size: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn pow_difficulty_exceeds_max_rejected() {
        let config = AppConfig {
            pow_difficulty: 25,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_trust_threshold_rejected() {
        let config = AppConfig {
            trust_threshold: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn pow_disabled_is_valid() {
        let config = AppConfig {
            enable_pow: false,
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn blocklist_disabled_is_valid() {
        let config = AppConfig {
            blocklist_enabled: false,
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_serde_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config)?;
        let parsed: AppConfig = serde_json::from_str(&json)?;
        assert_eq!(config.pending_ttl_days, parsed.pending_ttl_days);
        assert_eq!(config.db_retention_messages, parsed.db_retention_messages);
        assert_eq!(config.rate_limit_per_min, parsed.rate_limit_per_min);
        assert_eq!(config.pending_max, parsed.pending_max);
        assert_eq!(config.nonce_cache_size, parsed.nonce_cache_size);
        assert_eq!(config.pow_difficulty, parsed.pow_difficulty);
        assert_eq!(config.enable_pow, parsed.enable_pow);
        assert_eq!(config.trust_threshold, parsed.trust_threshold);
        assert_eq!(config.blocklist_enabled, parsed.blocklist_enabled);
        Ok(())
    }
}