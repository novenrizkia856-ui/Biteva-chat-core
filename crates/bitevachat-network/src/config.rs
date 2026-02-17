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

// ---------------------------------------------------------------------------
// Well-known bootstrap nodes
// ---------------------------------------------------------------------------

/// Default bootstrap nodes for the Bitevachat network.
///
/// These are community-run nodes that serve as initial entry points
/// to the Bitevachat Kademlia DHT.  They are NOT central servers —
/// once a node has discovered peers through the DHT, it no longer
/// needs them.  This is the same model Bitcoin uses with its DNS
/// seed nodes.
///
/// Anyone can run a bootstrap node by:
/// 1. Running a Bitevachat node on a machine with a public IP.
/// 2. Setting `enable_relay_server: true` in their config.
/// 3. Sharing their multiaddr for inclusion in this list.
///
/// Format: `/ip4/<ip>/tcp/<port>/p2p/<peer_id>`
///    or:  `/dns4/<domain>/tcp/<port>/p2p/<peer_id>`
///
/// If this list is empty, the node relies on mDNS (LAN only) or
/// manually-configured `bootstrap_nodes` in the user's config file.
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    "/ip4/82.25.62.154/tcp/9000/p2p/12D3KooWJdorLfGhEBJeEYKnfox4ppPBMD6CCzvX1GB73NqgAc7A",
];


/// Network-layer configuration.
///
/// Controls listening addresses, bootstrap peers, connection
/// limits, timeout durations, and NAT traversal settings for the
/// libp2p swarm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    // -----------------------------------------------------------------------
    // Core networking
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Kademlia DHT
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Local discovery
    // -----------------------------------------------------------------------

    /// Enable mDNS for automatic peer discovery on the local network.
    ///
    /// When enabled, the node broadcasts its presence via multicast
    /// DNS and automatically connects to other Bitevachat nodes on
    /// the same LAN. Essential for local P2P testing.
    ///
    /// Default: `true`.
    pub enable_mdns: bool,

    // -----------------------------------------------------------------------
    // NAT traversal
    // -----------------------------------------------------------------------

    /// Enable AutoNAT for automatic NAT status detection.
    ///
    /// When enabled, the node periodically probes connected peers
    /// to determine whether it is publicly reachable.
    ///
    /// Default: `true`.
    pub enable_autonat: bool,

    /// Number of AutoNAT confirmations before status is considered
    /// stable.
    ///
    /// Higher values reduce false positives but increase detection
    /// latency. Default: `3`.
    pub autonat_confidence_max: usize,

    /// Enable relay client mode.
    ///
    /// When enabled, the node can connect to peers through relay
    /// nodes when direct connections fail. Required for DCUtR hole
    /// punching.
    ///
    /// Default: `true`.
    pub enable_relay_client: bool,

    /// Enable relay server mode.
    ///
    /// When enabled, this node can serve as a relay for other peers
    /// that are behind NATs. Only enable on nodes with public IP
    /// addresses and sufficient bandwidth.
    ///
    /// Default: `false`.
    pub enable_relay_server: bool,

    /// Relay-only mode.
    ///
    /// When enabled, direct dials are disabled and all outbound
    /// connections go through relay nodes. Useful for nodes on
    /// highly restricted networks.
    ///
    /// Default: `false`.
    pub relay_only: bool,

    /// Relay server addresses.
    ///
    /// Multiaddrs of known relay nodes. Must include `/p2p/<peer_id>`
    /// component. The node will attempt to reserve slots on these
    /// relays when behind a NAT.
    #[serde(with = "multiaddr_vec_serde")]
    pub relay_servers: Vec<Multiaddr>,

    /// Enable TURN fallback.
    ///
    /// TURN is a last-resort fallback for nodes that cannot be
    /// reached via direct, hole-punch, or relay. Currently a stub.
    ///
    /// Default: `false`.
    pub enable_turn: bool,

    /// TURN server URLs.
    ///
    /// Format: `turn:<host>:<port>`. Credentials are provided
    /// separately at runtime.
    pub turn_servers: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // Construct the default listen address without parsing to avoid
        // expect()/unwrap() per project rules.
        let mut listen_addr = Multiaddr::empty();
        listen_addr.push(Protocol::Ip6(std::net::Ipv6Addr::UNSPECIFIED));
        listen_addr.push(Protocol::Tcp(27300));

        Self {
            listen_addr,
            bootstrap_nodes: Vec::new(),
            max_connections: 128,
            idle_timeout_secs: 60,
            dial_timeout_secs: 10,
            kad_protocol: "/bitevachat/kad/1.0.0".into(),
            kad_replication_factor: 20,
            kad_query_timeout_secs: 30,
            // Local discovery
            enable_mdns: true,
            // NAT traversal defaults
            enable_autonat: true,
            autonat_confidence_max: 3,
            enable_relay_client: true,
            enable_relay_server: true,
            relay_only: false,
            relay_servers: Vec::new(),
            enable_turn: false,
            turn_servers: Vec::new(),
        }
    }
}

impl NetworkConfig {
    /// Returns the effective list of bootstrap nodes: hardcoded
    /// defaults merged with user-configured nodes (deduplicated).
    ///
    /// Hardcoded defaults from [`DEFAULT_BOOTSTRAP_NODES`] are
    /// always included.  User-configured `bootstrap_nodes` are
    /// appended.  Duplicates are removed.
    pub fn effective_bootstrap_nodes(&self) -> Vec<Multiaddr> {
        let mut nodes: Vec<Multiaddr> = DEFAULT_BOOTSTRAP_NODES
            .iter()
            .filter_map(|s| s.parse::<Multiaddr>().ok())
            .collect();

        for addr in &self.bootstrap_nodes {
            if !nodes.iter().any(|existing| existing == addr) {
                nodes.push(addr.clone());
            }
        }

        nodes
    }

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

        // NAT traversal validation
        if self.autonat_confidence_max == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "autonat_confidence_max must be greater than 0".into(),
            });
        }
        if self.relay_only && !self.enable_relay_client {
            return Err(BitevachatError::ConfigError {
                reason: "relay_only requires enable_relay_client to be true".into(),
            });
        }
        if self.relay_only && self.relay_servers.is_empty() {
            return Err(BitevachatError::ConfigError {
                reason: "relay_only requires at least one relay_server".into(),
            });
        }
        if self.enable_turn && self.turn_servers.is_empty() {
            return Err(BitevachatError::ConfigError {
                reason: "enable_turn requires at least one turn_server".into(),
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

    // NAT traversal config tests

    #[test]
    fn zero_autonat_confidence_rejected() {
        let config = NetworkConfig {
            autonat_confidence_max: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn relay_only_without_client_rejected() {
        let config = NetworkConfig {
            relay_only: true,
            enable_relay_client: false,
            relay_servers: vec!["/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".parse().unwrap()],
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn relay_only_without_servers_rejected() {
        let config = NetworkConfig {
            relay_only: true,
            enable_relay_client: true,
            relay_servers: Vec::new(),
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn turn_enabled_without_servers_rejected() {
        let config = NetworkConfig {
            enable_turn: true,
            turn_servers: Vec::new(),
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn valid_nat_config() {
        let config = NetworkConfig {
            enable_autonat: true,
            enable_relay_client: true,
            enable_relay_server: true,
            relay_only: false,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn effective_bootstrap_nodes_empty_by_default() {
        let config = NetworkConfig::default();
        // DEFAULT_BOOTSTRAP_NODES is currently empty, so
        // effective list should also be empty.
        let nodes = config.effective_bootstrap_nodes();
        assert!(nodes.is_empty());
    }

    #[test]
    fn effective_bootstrap_nodes_includes_user_configured() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".parse().unwrap();
        let config = NetworkConfig {
            bootstrap_nodes: vec![addr.clone()],
            ..NetworkConfig::default()
        };
        let nodes = config.effective_bootstrap_nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0], addr);
    }
}