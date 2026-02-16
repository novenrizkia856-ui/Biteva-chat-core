//! Relay protocol support for NAT traversal.
//!
//! Integrates libp2p's Circuit Relay v2 protocol:
//!
//! - **Relay client** — allows this node to connect through a relay
//!   when behind a NAT. Built into the transport layer via
//!   `SwarmBuilder::with_relay_client`.
//! - **Relay server** (optional) — allows this node to serve as a
//!   relay for other peers. Enabled via config.
//!
//! # Relay-only mode
//!
//! When `relay_only` is set in [`NetworkConfig`], direct dials are
//! disabled and all outbound connections go through relay nodes.
//! This is useful for nodes on highly restricted networks.

use libp2p::relay;
use libp2p::{Multiaddr, PeerId};

use bitevachat_types::BitevachatError;

/// Local alias to avoid shadowing `std::result::Result`.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Relay server configuration
// ---------------------------------------------------------------------------

/// Builds a relay server [`relay::Behaviour`] if enabled.
///
/// Returns `Some(behaviour)` when `enable_relay_server` is true,
/// `None` otherwise. The caller wraps this in a `Toggle`.
///
/// # Parameters
///
/// - `local_peer_id` — this node's PeerId.
/// - `enable` — whether relay server mode is active.
pub fn build_relay_server_behaviour(
    local_peer_id: PeerId,
    enable: bool,
) -> Option<relay::Behaviour> {
    if enable {
        let config = relay::Config::default();
        tracing::info!("relay server mode enabled");
        Some(relay::Behaviour::new(local_peer_id, config))
    } else {
        tracing::debug!("relay server mode disabled");
        None
    }
}

// ---------------------------------------------------------------------------
// Relay address helpers
// ---------------------------------------------------------------------------

/// Constructs a relay circuit multiaddr for reaching a target peer
/// through a relay node.
///
/// Produces: `{relay_addr}/p2p/{relay_peer_id}/p2p-circuit/p2p/{target_peer_id}`
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if the multiaddr cannot
/// be constructed (e.g. invalid relay address format).
pub fn build_relay_circuit_addr(
    relay_addr: &Multiaddr,
    relay_peer_id: &PeerId,
    target_peer_id: &PeerId,
) -> BResult<Multiaddr> {
    let circuit_str = format!(
        "{}/p2p/{}/p2p-circuit/p2p/{}",
        relay_addr, relay_peer_id, target_peer_id
    );

    circuit_str
        .parse()
        .map_err(|e| BitevachatError::NetworkError {
            reason: format!("failed to build relay circuit address: {e}"),
        })
}

/// Constructs a relay reservation address for listening through
/// a relay node.
///
/// Produces: `{relay_addr}/p2p/{relay_peer_id}/p2p-circuit`
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if the multiaddr cannot
/// be constructed.
pub fn build_relay_listen_addr(
    relay_addr: &Multiaddr,
    relay_peer_id: &PeerId,
) -> BResult<Multiaddr> {
    let listen_str = format!("{}/p2p/{}/p2p-circuit", relay_addr, relay_peer_id);

    listen_str
        .parse()
        .map_err(|e| BitevachatError::NetworkError {
            reason: format!("failed to build relay listen address: {e}"),
        })
}

/// Extracts the relay PeerId from a relay multiaddr.
///
/// Looks for the first `/p2p/` component in the address.
pub fn extract_relay_peer_id(relay_addr: &Multiaddr) -> Option<PeerId> {
    relay_addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            Some(peer_id)
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Relay event logging
// ---------------------------------------------------------------------------

/// Logs relay client events at appropriate levels.
pub fn log_relay_client_event(event: &relay::client::Event) {
    match event {
        relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            renewal,
            ..
        } => {
            tracing::info!(
                %relay_peer_id,
                renewal,
                "relay reservation accepted"
            );
        }
        relay::client::Event::OutboundCircuitEstablished {
            relay_peer_id,
            ..
        } => {
            tracing::info!(
                %relay_peer_id,
                "outbound relay circuit established"
            );
        }
        relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
            tracing::info!(
                %src_peer_id,
                "inbound relay circuit established"
            );
        }
        other => {
            tracing::debug!(?other, "relay client: other event");
        }
    }
}

/// Logs relay server events at appropriate levels.
pub fn log_relay_server_event(event: &relay::Event) {
    match event {
        relay::Event::ReservationReqAccepted {
            src_peer_id,
            renewed,
        } => {
            tracing::info!(
                %src_peer_id,
                renewed,
                "relay server: reservation accepted"
            );
        }
        relay::Event::ReservationReqDenied { src_peer_id } => {
            tracing::warn!(
                %src_peer_id,
                "relay server: reservation denied"
            );
        }
        relay::Event::ReservationTimedOut { src_peer_id } => {
            tracing::debug!(
                %src_peer_id,
                "relay server: reservation timed out"
            );
        }
        #[allow(deprecated)]
        relay::Event::CircuitReqAcceptFailed {
            src_peer_id,
            error,
            ..
        } => {
            tracing::warn!(
                %src_peer_id,
                ?error,
                "relay server: circuit request accept failed"
            );
        }
        relay::Event::CircuitReqDenied {
            src_peer_id,
            dst_peer_id,
        } => {
            tracing::warn!(
                %src_peer_id,
                %dst_peer_id,
                "relay server: circuit request denied"
            );
        }
        relay::Event::CircuitReqAccepted {
            src_peer_id,
            dst_peer_id,
        } => {
            tracing::info!(
                %src_peer_id,
                %dst_peer_id,
                "relay server: circuit request accepted"
            );
        }
        relay::Event::CircuitClosed {
            src_peer_id,
            dst_peer_id,
            error,
        } => {
            tracing::debug!(
                %src_peer_id,
                %dst_peer_id,
                ?error,
                "relay server: circuit closed"
            );
        }
        _ => {
            tracing::trace!(?event, "relay server: other event");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_relay_circuit_addr_valid() {
        let relay_addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        let relay_peer = PeerId::random();
        let target_peer = PeerId::random();

        let result = build_relay_circuit_addr(&relay_addr, &relay_peer, &target_peer);
        assert!(result.is_ok());

        let addr = result.unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.contains("p2p-circuit"));
        assert!(addr_str.contains(&relay_peer.to_string()));
        assert!(addr_str.contains(&target_peer.to_string()));
    }

    #[test]
    fn build_relay_listen_addr_valid() {
        let relay_addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        let relay_peer = PeerId::random();

        let result = build_relay_listen_addr(&relay_addr, &relay_peer);
        assert!(result.is_ok());

        let addr = result.unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.contains("p2p-circuit"));
        assert!(addr_str.contains(&relay_peer.to_string()));
    }

    #[test]
    fn extract_relay_peer_id_found() {
        let peer = PeerId::random();
        let addr: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();

        let extracted = extract_relay_peer_id(&addr);
        assert_eq!(extracted, Some(peer));
    }

    #[test]
    fn extract_relay_peer_id_not_found() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        assert!(extract_relay_peer_id(&addr).is_none());
    }

    #[test]
    fn build_relay_server_enabled() {
        let peer = PeerId::random();
        let result = build_relay_server_behaviour(peer, true);
        assert!(result.is_some());
    }

    #[test]
    fn build_relay_server_disabled() {
        let peer = PeerId::random();
        let result = build_relay_server_behaviour(peer, false);
        assert!(result.is_none());
    }
}