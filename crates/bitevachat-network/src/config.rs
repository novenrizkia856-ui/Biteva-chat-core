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
// DNS seed discovery
// ---------------------------------------------------------------------------

/// Default DNS seed domain for discovering bootstrap nodes.
///
/// On startup, the node queries SRV records at
/// `_bitevachat._tcp.<domain>` to discover the IP addresses of
/// public seed nodes.  All seed nodes listen on port 39812.
///
/// This replaces the old hardcoded `DEFAULT_BOOTSTRAP_NODES` list.
/// Updating the DNS zone file is enough to add or remove seed
/// nodes — no binary rebuild or config push required.
///
/// The DNS seed is **not a central server**.  It only provides
/// initial peer addresses for joining the Kademlia DHT.  Once
/// connected to the DHT, the node discovers additional peers
/// through normal DHT operations.
pub const DEFAULT_SEED_DOMAIN: &str = "seed.bitevacapital.id";

/// Hardcoded fallback bootstrap nodes.
///
/// Used when DNS resolution fails (timeout, NXDOMAIN, network
/// error).  These should be long-lived, well-known public nodes
/// with stable PeerIds (persisted keypairs).
///
/// Format: `/ip4/<ip>/tcp/<port>` (without `/p2p/<peer_id>`
/// for peerless dials, or with `/p2p/<peer_id>` if known).
pub const FALLBACK_BOOTSTRAP_NODES: &[&str] = &[
    "/ip4/82.25.62.154/tcp/39812",
];


/// Network-layer configuration.
///
/// Controls listening addresses, bootstrap peers, connection
/// limits, timeout durations, NAT traversal settings, and
/// store-and-forward mailbox parameters for the libp2p swarm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    // -----------------------------------------------------------------------
    // Core networking
    // -----------------------------------------------------------------------

    /// Multiaddr on which this node listens for incoming connections.
    ///
    /// Default: `/ip6/::/tcp/39812`.
    #[serde(with = "multiaddr_serde")]
    pub listen_addr: Multiaddr,

    /// DNS seed domain for discovering bootstrap nodes.
    ///
    /// On startup, the node queries SRV records at
    /// `_bitevachat._tcp.<domain>` to find public seed node IPs.
    /// Set to an empty string to disable DNS seeding.
    ///
    /// Default: `seed.bitevacapital.id`.
    pub dns_seed_domain: String,

    /// Enable DNS-based seed discovery.
    ///
    /// When disabled, only `bootstrap_nodes` and hardcoded fallbacks
    /// are used.
    ///
    /// Default: `true`.
    pub dns_seed_enabled: bool,

    /// Additional bootstrap nodes to connect to on startup.
    ///
    /// These are merged with nodes discovered via DNS seeding.
    /// Each entry should be a multiaddr, optionally with a
    /// `/p2p/<peer_id>` component:
    /// `/ip4/1.2.3.4/tcp/39812` or `/ip4/1.2.3.4/tcp/39812/p2p/12D3KooW...`
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

    // -----------------------------------------------------------------------
    // Store-and-forward mailbox
    // -----------------------------------------------------------------------

    /// Maximum messages stored per recipient in the mailbox.
    ///
    /// When exceeded, the oldest message for that recipient is
    /// evicted (FIFO). This prevents a single address from
    /// consuming all mailbox capacity.
    ///
    /// Default: `256`.
    pub mailbox_max_per_recipient: usize,

    /// Maximum total messages across all recipients in the mailbox.
    ///
    /// When reached, new messages are rejected. The sender's
    /// pending queue will handle retries.
    ///
    /// Default: `10_000`.
    pub mailbox_max_total: usize,

    /// Time-to-live (in seconds) for mailbox entries.
    ///
    /// Messages older than this are purged during the maintenance
    /// tick. The sender's pending queue will retry if needed.
    ///
    /// Default: `3600` (1 hour).
    pub mailbox_ttl_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // Construct the default listen address without parsing to avoid
        // expect()/unwrap() per project rules.
        let mut listen_addr = Multiaddr::empty();
        listen_addr.push(Protocol::Ip6(std::net::Ipv6Addr::UNSPECIFIED));
        listen_addr.push(Protocol::Tcp(39812));

        Self {
            listen_addr,
            dns_seed_domain: DEFAULT_SEED_DOMAIN.into(),
            dns_seed_enabled: true,
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
            // Store-and-forward mailbox defaults
            mailbox_max_per_recipient: 256,
            mailbox_max_total: 10_000,
            mailbox_ttl_secs: 3600,
        }
    }
}

impl NetworkConfig {
    /// Returns the synchronous (non-DNS) bootstrap node list.
    ///
    /// Merges hardcoded fallback nodes with user-configured
    /// `bootstrap_nodes`.  This does NOT include DNS-resolved seeds.
    ///
    /// For the full list including DNS seeds, use
    /// [`resolve_bootstrap_nodes`](Self::resolve_bootstrap_nodes).
    pub fn fallback_bootstrap_nodes(&self) -> Vec<Multiaddr> {
        let mut nodes: Vec<Multiaddr> = FALLBACK_BOOTSTRAP_NODES
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

    /// Resolves the complete bootstrap node list: DNS seeds merged
    /// with fallback/config nodes.
    ///
    /// # Resolution order
    ///
    /// 1. Query DNS SRV records at `_bitevachat._tcp.<dns_seed_domain>`.
    /// 2. Merge with hardcoded `FALLBACK_BOOTSTRAP_NODES`.
    /// 3. Merge with user-configured `bootstrap_nodes`.
    /// 4. Deduplicate and cap at 64.
    ///
    /// If DNS resolution fails, only fallback + config nodes are
    /// returned.  DNS failure is never fatal.
    pub async fn resolve_bootstrap_nodes(&self) -> Vec<Multiaddr> {
        let fallback = self.fallback_bootstrap_nodes();

        if !self.dns_seed_enabled || self.dns_seed_domain.is_empty() {
            tracing::debug!("DNS seeding disabled, using fallback nodes only");
            return fallback;
        }

        crate::dns_seed::resolve_and_merge(
            Some(&self.dns_seed_domain),
            &fallback,
        )
        .await
    }

    /// Legacy synchronous accessor.
    ///
    /// **Deprecated** — use [`resolve_bootstrap_nodes`](Self::resolve_bootstrap_nodes)
    /// instead.  This exists for backward compatibility and returns
    /// only the fallback/config nodes (no DNS seeds).
    pub fn effective_bootstrap_nodes(&self) -> Vec<Multiaddr> {
        self.fallback_bootstrap_nodes()
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

        // Mailbox validation
        if self.mailbox_max_per_recipient == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "mailbox_max_per_recipient must be greater than 0".into(),
            });
        }
        if self.mailbox_max_total == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "mailbox_max_total must be greater than 0".into(),
            });
        }
        if self.mailbox_ttl_secs == 0 {
            return Err(BitevachatError::ConfigError {
                reason: "mailbox_ttl_secs must be greater than 0".into(),
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
    fn fallback_bootstrap_nodes_includes_hardcoded() {
        let config = NetworkConfig::default();
        let nodes = config.fallback_bootstrap_nodes();
        // FALLBACK_BOOTSTRAP_NODES has at least one hardcoded entry.
        assert!(!nodes.is_empty());
        assert!(nodes[0].to_string().contains("39812"));
    }

    #[test]
    fn fallback_bootstrap_nodes_includes_user_configured() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/39812".parse().unwrap();
        let config = NetworkConfig {
            bootstrap_nodes: vec![addr.clone()],
            ..NetworkConfig::default()
        };
        let nodes = config.fallback_bootstrap_nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0], addr);
    }

    #[test]
    fn default_dns_seed_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.dns_seed_domain, "seed.bitevacapital.id");
        assert!(config.dns_seed_enabled);
    }

    #[test]
    fn default_listen_port_is_39812() {
        let config = NetworkConfig::default();
        let addr_str = config.listen_addr.to_string();
        assert!(
            addr_str.contains("39812"),
            "default listen port should be 39812, got: {}",
            addr_str,
        );
    }

    // Mailbox config tests

    #[test]
    fn zero_mailbox_per_recipient_rejected() {
        let config = NetworkConfig {
            mailbox_max_per_recipient: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_mailbox_max_total_rejected() {
        let config = NetworkConfig {
            mailbox_max_total: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_mailbox_ttl_rejected() {
        let config = NetworkConfig {
            mailbox_ttl_secs: 0,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn custom_mailbox_config_valid() {
        let config = NetworkConfig {
            mailbox_max_per_recipient: 512,
            mailbox_max_total: 20_000,
            mailbox_ttl_secs: 7200,
            ..NetworkConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_mailbox_values() {
        let config = NetworkConfig::default();
        assert_eq!(config.mailbox_max_per_recipient, 256);
        assert_eq!(config.mailbox_max_total, 10_000);
        assert_eq!(config.mailbox_ttl_secs, 3600);
    }
}