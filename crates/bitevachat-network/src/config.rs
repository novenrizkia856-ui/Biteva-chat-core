//! Network configuration for the Bitevachat libp2p layer.
//!
//! All values have documented defaults. Validation ensures no
//! zero-valued timeouts or invalid protocol names at startup.
//!
//! This config lives in `bitevachat-network` rather than
//! `bitevachat-types` to avoid pulling `libp2p::Multiaddr` into the
//! shared types crate. The existing `AppConfig` in
//! `bitevachat-types` is not modified.

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

use bitevachat_types::{BitevachatError, Result};

/// Network-layer configuration.
///
/// Controls listening addresses, bootstrap peers, connection
/// limits, and timeout durations for the libp2p swarm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Multiaddr on which this node listens for incoming connections.
    ///
    /// Default: `/ip4/0.0.0.0/tcp/0` (OS-assigned port on all interfaces).
    #[serde(with = "multiaddr_serde")]
    pub listen_addr: Multiaddr,

    /// Bootstrap nodes to connect to on startup.
    ///
    /// Each entry must be a fully-qualified multiaddr containing a
    /// `/p2p/<peer_id>` component, e.g.:
    /// `/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...`
    #[serde(with = "multiaddr_vec_serde")]
    pub bootstrap_nodes: Vec<Multiaddr>,

    /// Maximum number of simultaneous established connections.
    pub max_connections: usize,

    /// Seconds before an idle connection is closed by the swarm.
    pub idle_timeout_secs: u64,

    /// Seconds before an outbound dial attempt is aborted.
    pub dial_timeout_secs: u64,

    /// Custom Kademlia protocol name for network isolation.
    ///
    /// Nodes using different protocol names will not exchange
    /// Kademlia messages. Default: `/bitevachat/kad/1.0.0`.
    pub kad_protocol: String,

    /// Kademlia replication factor — number of closest peers to
    /// which records are replicated.
    pub kad_replication_factor: usize,

    /// Seconds before a Kademlia query times out.
    pub kad_query_timeout_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // Construct the default listen address without parsing to avoid
        // expect()/unwrap() per project rules.
        let mut listen_addr = Multiaddr::empty();
        listen_addr.push(Protocol::Ip4(std::net::Ipv4Addr::UNSPECIFIED));
        listen_addr.push(Protocol::Tcp(0));

        Self {
            listen_addr,
            bootstrap_nodes: Vec::new(),
            max_connections: 128,
            idle_timeout_secs: 60,
            dial_timeout_secs: 10,
            kad_protocol: "/bitevachat/kad/1.0.0".into(),
            kad_replication_factor: 20,
            kad_query_timeout_secs: 30,
        }
    }
}

impl NetworkConfig {
    /// Validates all configuration values.
    ///
    /// Returns `Err(BitevachatError::ConfigError)` if any value is
    /// outside its acceptable range.
    pub fn validate(&self) -> Result<()> {
        if self.max_connections == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "max_connections must be greater than 0".into(),
            });
        }
        if self.idle_timeout_secs == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "idle_timeout_secs must be greater than 0".into(),
            });
        }
        if self.dial_timeout_secs == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "dial_timeout_secs must be greater than 0".into(),
            });
        }
        if self.kad_protocol.is_empty() {
            return Err(BitevachatError::ConfigError {
                reason: "kad_protocol must not be empty".into(),
            });
        }
        if !self.kad_protocol.starts_with('/') {
            return Err(BitevachatError::ConfigError {
                reason: "kad_protocol must start with '/'".into(),
            });
        }
        if self.kad_replication_factor == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "kad_replication_factor must be greater than 0".into(),
            });
        }
        if self.kad_query_timeout_secs == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "kad_query_timeout_secs must be greater than 0".into(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Serde helpers — Multiaddr does not implement Serialize/Deserialize
// ---------------------------------------------------------------------------

mod multiaddr_serde {
    use libp2p::Multiaddr;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(addr: &Multiaddr, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Multiaddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

mod multiaddr_vec_serde {
    use libp2p::Multiaddr;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(addrs: &[Multiaddr], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(addrs.len()))?;
        for addr in addrs {
            seq.serialize_element(&addr.to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<Multiaddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = NetworkConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_max_connections_rejected() {
        let config = NetworkConfig {
            max_connections: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_idle_timeout_rejected() {
        let config = NetworkConfig {
            idle_timeout_secs: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_dial_timeout_rejected() {
        let config = NetworkConfig {
            dial_timeout_secs: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_kad_protocol_rejected() {
        let config = NetworkConfig {
            kad_protocol: String::new(),
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn kad_protocol_without_slash_rejected() {
        let config = NetworkConfig {
            kad_protocol: "bitevachat/kad/1.0.0".into(),
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_replication_factor_rejected() {
        let config = NetworkConfig {
            kad_replication_factor: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_query_timeout_rejected() {
        let config = NetworkConfig {
            kad_query_timeout_secs: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }
}