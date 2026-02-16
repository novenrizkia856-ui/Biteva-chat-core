//! DHT-based peer discovery for the Bitevachat network.
//!
//! Wraps Kademlia and Identify into a single [`NetworkBehaviour`] that
//! provides:
//!
//! - **Address publishing** — Store `Address → PeerId` mappings in the DHT
//!   so other nodes can find a peer by its Bitevachat address.
//! - **Peer lookup** — Query the DHT to resolve a Bitevachat `Address`
//!   to a libp2p `PeerId`.
//! - **Bootstrap** — Seed the Kademlia routing table with known peers.
//! - **Identify** — Exchange peer metadata (listen addresses, protocol
//!   versions) on every new connection, which Kademlia uses to populate
//!   its routing table.

use std::num::NonZeroUsize;
use std::time::Duration;

use libp2p::identity;
use libp2p::kad;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, Multiaddr, PeerId, StreamProtocol};

use bitevachat_types::{Address, BitevachatError};

use crate::config::NetworkConfig;

/// Local alias so we never shadow `std::result::Result` (which the
/// `#[derive(NetworkBehaviour)]` macro needs).
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Combined NetworkBehaviour
// ---------------------------------------------------------------------------

/// Combined network behaviour providing Kademlia DHT and Identify.
///
/// The `NetworkBehaviour` derive macro auto-generates a
/// `DiscoveryBehaviourEvent` enum with one variant per field.
#[derive(NetworkBehaviour)]
pub struct DiscoveryBehaviour {
    /// Kademlia DHT for distributed record storage and peer routing.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,

    /// Identify protocol — exchanges peer info (addresses, protocols)
    /// on every new connection.
    pub identify: identify::Behaviour,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Builds a [`DiscoveryBehaviour`] from the given identity and config.
///
/// # Errors
///
/// Returns `BitevachatError::ConfigError` if the Kademlia replication
/// factor is zero, or `BitevachatError::NetworkError` if the protocol
/// name is invalid.
pub fn build_discovery_behaviour(
    keypair: &identity::Keypair,
    config: &NetworkConfig,
) -> BResult<DiscoveryBehaviour> {
    // --- Kademlia -----------------------------------------------------------

    let local_peer_id = PeerId::from(keypair.public());

    let replication_factor = NonZeroUsize::new(config.kad_replication_factor).ok_or_else(
        || BitevachatError::ConfigError {
            reason: "kad_replication_factor must be greater than 0".into(),
        },
    )?;

    let protocol = StreamProtocol::try_from_owned(config.kad_protocol.clone()).map_err(
        |e| BitevachatError::NetworkError {
            reason: format!("invalid Kademlia protocol name '{}': {e}", config.kad_protocol),
        },
    )?;

    // Use Config::new(protocol) which replaces the deprecated
    // Config::default() + set_protocol_names() pattern.
    let mut kad_config = kad::Config::new(protocol);
    kad_config.set_query_timeout(Duration::from_secs(config.kad_query_timeout_secs));
    kad_config.set_replication_factor(replication_factor);

    let store = kad::store::MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

    // --- Identify -----------------------------------------------------------

    let identify_config = identify::Config::new(
        "/bitevachat/id/1.0.0".into(),
        keypair.public(),
    )
    .with_agent_version(format!("bitevachat-node/{}", env!("CARGO_PKG_VERSION")));

    let identify = identify::Behaviour::new(identify_config);

    Ok(DiscoveryBehaviour { kademlia, identify })
}

// ---------------------------------------------------------------------------
// DHT operations
// ---------------------------------------------------------------------------

impl DiscoveryBehaviour {
    /// Publishes an `Address → PeerId` mapping in the Kademlia DHT.
    ///
    /// Other nodes can later call [`find_peer`](Self::find_peer) with the
    /// same address to discover this peer's `PeerId`.
    ///
    /// # Returns
    ///
    /// The `QueryId` of the DHT put operation. The result is delivered
    /// asynchronously via `DiscoveryBehaviourEvent::Kademlia` in the
    /// swarm event loop.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if the DHT put operation
    /// cannot be initiated (e.g. no known peers in the routing table).
    pub fn publish_address(
        &mut self,
        address: &Address,
        peer_id: &PeerId,
    ) -> BResult<kad::QueryId> {
        let key = kad::RecordKey::new(address.as_bytes());
        let record = kad::Record {
            key,
            value: peer_id.to_bytes(),
            publisher: None,
            expires: None,
        };

        self.kademlia
            .put_record(record, kad::Quorum::One)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to publish address to DHT: {e}"),
            })
    }

    /// Initiates a DHT lookup for the `PeerId` associated with a
    /// Bitevachat address.
    ///
    /// # Returns
    ///
    /// The `QueryId` of the DHT get operation. The actual `PeerId`
    /// result is delivered asynchronously via
    /// `DiscoveryBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { .. })`
    /// in the swarm event loop. Use [`parse_peer_id_from_record`] to
    /// extract the `PeerId` from a successful query result.
    pub fn find_peer(&mut self, address: &Address) -> kad::QueryId {
        let key = kad::RecordKey::new(address.as_bytes());
        self.kademlia.get_record(key)
    }

    /// Adds bootstrap nodes to the Kademlia routing table.
    ///
    /// Each multiaddr must contain a `/p2p/<peer_id>` component.
    /// Addresses without a peer ID are skipped with a warning.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if no valid bootstrap
    /// addresses could be parsed.
    pub fn add_bootstrap_nodes(&mut self, nodes: &[Multiaddr]) -> BResult<()> {
        let mut added = 0usize;

        for addr in nodes {
            match extract_peer_id(addr) {
                Some((peer_id, clean_addr)) => {
                    self.kademlia.add_address(&peer_id, clean_addr);
                    added += 1;
                    tracing::info!(%peer_id, %addr, "added bootstrap node to Kademlia routing table");
                }
                None => {
                    tracing::warn!(%addr, "skipping bootstrap node: missing /p2p/ component");
                }
            }
        }

        if !nodes.is_empty() && added == 0 {
            return Err(BitevachatError::NetworkError {
                reason: "no valid bootstrap nodes found (all missing /p2p/ component)".into(),
            });
        }

        Ok(())
    }

    /// Initiates a Kademlia bootstrap operation.
    ///
    /// Performs a lookup for the local peer ID to populate the
    /// routing table with nearby peers. Should be called after
    /// bootstrap nodes have been added.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if the bootstrap cannot
    /// be started (e.g. no known peers).
    pub fn bootstrap(&mut self) -> BResult<kad::QueryId> {
        self.kademlia
            .bootstrap()
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to start Kademlia bootstrap: {e}"),
            })
    }

    /// Sets the Kademlia mode (Client or Server).
    ///
    /// - `Server` — actively participates in DHT queries and stores records.
    /// - `Client` — only initiates queries, does not serve records.
    pub fn set_mode(&mut self, mode: kad::Mode) {
        self.kademlia.set_mode(Some(mode));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extracts the `PeerId` and the address-without-p2p from a multiaddr.
///
/// Given `/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...`, returns
/// `Some((PeerId, /ip4/1.2.3.4/tcp/4001))`.
///
/// Returns `None` if the multiaddr does not contain a `/p2p/` component.
fn extract_peer_id(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let components = addr.iter();
    let mut clean_addr = Multiaddr::empty();
    let mut peer_id = None;

    for proto in components {
        match proto {
            libp2p::multiaddr::Protocol::P2p(id) => {
                peer_id = Some(id);
            }
            other => {
                clean_addr.push(other);
            }
        }
    }

    peer_id.map(|pid| (pid, clean_addr))
}

/// Parses a `PeerId` from a Kademlia record value.
///
/// Use this to extract the result of a [`DiscoveryBehaviour::find_peer`]
/// query from a `kad::GetRecordOk` event.
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if the value is not a valid
/// `PeerId` encoding.
pub fn parse_peer_id_from_record(value: &[u8]) -> BResult<PeerId> {
    PeerId::from_bytes(value).map_err(|e| BitevachatError::NetworkError {
        reason: format!("failed to parse PeerId from DHT record: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_peer_id_with_p2p_component() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer_id}")
            .parse()
            .unwrap();

        let result = extract_peer_id(&addr);
        assert!(result.is_some());
        let (pid, clean) = result.unwrap();
        assert_eq!(pid, peer_id);
        assert_eq!(clean.to_string(), "/ip4/127.0.0.1/tcp/4001");
    }

    #[test]
    fn extract_peer_id_without_p2p_returns_none() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(extract_peer_id(&addr).is_none());
    }

    #[test]
    fn parse_peer_id_from_valid_bytes() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let bytes = peer_id.to_bytes();
        let parsed = parse_peer_id_from_record(&bytes);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap(), peer_id);
    }

    #[test]
    fn parse_peer_id_from_invalid_bytes() {
        let bad_bytes = [0xFFu8; 5];
        let result = parse_peer_id_from_record(&bad_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn build_discovery_behaviour_default_config() {
        let keypair = identity::Keypair::generate_ed25519();
        let config = NetworkConfig::default();
        let result = build_discovery_behaviour(&keypair, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_discovery_behaviour_zero_replication_fails() {
        let keypair = identity::Keypair::generate_ed25519();
        let config = NetworkConfig {
            kad_replication_factor: 0,
            ..NetworkConfig::default()
        };
        let result = build_discovery_behaviour(&keypair, &config);
        assert!(result.is_err());
    }
}