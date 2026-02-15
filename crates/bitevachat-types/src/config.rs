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
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            pending_ttl_days: 5,
            db_retention_messages: 1500,
            rate_limit_per_min: 10,
            pending_max: 500,
            nonce_cache_size: 10_000,
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
    fn config_serde_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config)?;
        let parsed: AppConfig = serde_json::from_str(&json)?;
        assert_eq!(config.pending_ttl_days, parsed.pending_ttl_days);
        assert_eq!(config.db_retention_messages, parsed.db_retention_messages);
        assert_eq!(config.rate_limit_per_min, parsed.rate_limit_per_min);
        assert_eq!(config.pending_max, parsed.pending_max);
        assert_eq!(config.nonce_cache_size, parsed.nonce_cache_size);
        Ok(())
    }
}
