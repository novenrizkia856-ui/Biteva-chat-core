//! Integration tests for NAT traversal components.
//!
//! Tests NAT status detection, relay fallback, relay-only mode,
//! fallback chain ordering, and config toggle behaviour.

use bitevachat_network::config::NetworkConfig;
use bitevachat_network::hole_punch::{ConnectionStrategy, FallbackChain};
use bitevachat_network::nat::{from_libp2p_status, NatManager, NatStatus};
use bitevachat_network::relay::{
    build_relay_circuit_addr, build_relay_listen_addr, extract_relay_peer_id,
};
use bitevachat_network::turn::TurnClient;
use libp2p::{autonat, Multiaddr, PeerId};

// ---------------------------------------------------------------------------
// NAT detection tests
// ---------------------------------------------------------------------------

#[test]
fn nat_manager_initial_state() {
    let manager = NatManager::new();
    assert_eq!(manager.current_status(), &NatStatus::Unknown);
    assert!(manager.external_address().is_none());
}

#[test]
fn nat_status_transition_to_public() {
    let mut manager = NatManager::new();
    let addr: Multiaddr = "/ip4/203.0.113.1/tcp/4001".parse().unwrap();

    let event = autonat::Event::StatusChanged {
        old: autonat::NatStatus::Unknown,
        new: autonat::NatStatus::Public(addr.clone()),
    };

    let result = manager.on_autonat_event(event);
    assert_eq!(result, Some(NatStatus::Public));
    assert_eq!(manager.external_address(), Some(&addr));
}

#[test]
fn nat_status_transition_to_private() {
    let mut manager = NatManager::new();

    // First become public.
    let addr: Multiaddr = "/ip4/203.0.113.1/tcp/4001".parse().unwrap();
    manager.on_autonat_event(autonat::Event::StatusChanged {
        old: autonat::NatStatus::Unknown,
        new: autonat::NatStatus::Public(addr.clone()),
    });

    // Then become private.
    let result = manager.on_autonat_event(autonat::Event::StatusChanged {
        old: autonat::NatStatus::Public(addr),
        new: autonat::NatStatus::Private,
    });

    assert_eq!(result, Some(NatStatus::BehindNat));
    assert!(manager.external_address().is_none());
}

#[test]
fn from_libp2p_status_mapping() {
    let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();

    assert_eq!(
        from_libp2p_status(&autonat::NatStatus::Public(addr)),
        NatStatus::Public
    );
    assert_eq!(
        from_libp2p_status(&autonat::NatStatus::Private),
        NatStatus::BehindNat
    );
    assert_eq!(
        from_libp2p_status(&autonat::NatStatus::Unknown),
        NatStatus::Unknown
    );
}

// ---------------------------------------------------------------------------
// Relay fallback tests
// ---------------------------------------------------------------------------

#[test]
fn relay_circuit_addr_construction() {
    let relay_addr: Multiaddr = "/ip4/203.0.113.1/tcp/4001".parse().unwrap();
    let relay_peer = PeerId::random();
    let target_peer = PeerId::random();

    let result = build_relay_circuit_addr(&relay_addr, &relay_peer, &target_peer);
    assert!(result.is_ok());

    let circuit = result.unwrap();
    let s = circuit.to_string();
    assert!(s.contains("p2p-circuit"), "missing p2p-circuit: {s}");
    assert!(s.contains(&relay_peer.to_string()));
    assert!(s.contains(&target_peer.to_string()));
}

#[test]
fn relay_listen_addr_construction() {
    let relay_addr: Multiaddr = "/ip4/203.0.113.1/tcp/4001".parse().unwrap();
    let relay_peer = PeerId::random();

    let result = build_relay_listen_addr(&relay_addr, &relay_peer);
    assert!(result.is_ok());

    let listen = result.unwrap();
    let s = listen.to_string();
    assert!(s.contains("p2p-circuit"), "missing p2p-circuit: {s}");
}

#[test]
fn extract_relay_peer_from_addr() {
    let peer = PeerId::random();
    let addr: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{peer}")
        .parse()
        .unwrap();

    assert_eq!(extract_relay_peer_id(&addr), Some(peer));
}

#[test]
fn extract_relay_peer_from_addr_without_p2p() {
    let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
    assert!(extract_relay_peer_id(&addr).is_none());
}

// ---------------------------------------------------------------------------
// Relay-only mode tests
// ---------------------------------------------------------------------------

#[test]
fn relay_only_config_requires_relay_client() {
    let config = NetworkConfig {
        relay_only: true,
        enable_relay_client: false,
        relay_servers: vec!["/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap()],
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn relay_only_config_requires_servers() {
    let config = NetworkConfig {
        relay_only: true,
        enable_relay_client: true,
        relay_servers: Vec::new(),
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn relay_only_fallback_chain_skips_direct() {
    let mut chain = FallbackChain::new(true, false);
    assert_eq!(
        chain.next_strategy(),
        Some(&ConnectionStrategy::RelayCircuit)
    );
    assert!(chain.next_strategy().is_none());
}

// ---------------------------------------------------------------------------
// Fallback chain ordering tests
// ---------------------------------------------------------------------------

#[test]
fn fallback_chain_default_order() {
    let mut chain = FallbackChain::new(false, false);
    assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Direct));
    assert_eq!(
        chain.next_strategy(),
        Some(&ConnectionStrategy::RelayCircuit)
    );
    assert!(chain.next_strategy().is_none());
}

#[test]
fn fallback_chain_full_order() {
    let mut chain = FallbackChain::new(false, true);
    assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Direct));
    assert_eq!(
        chain.next_strategy(),
        Some(&ConnectionStrategy::RelayCircuit)
    );
    assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Turn));
    assert!(chain.next_strategy().is_none());
    assert!(chain.exhausted());
}

#[test]
fn fallback_chain_relay_only_with_turn() {
    let mut chain = FallbackChain::new(true, true);
    assert_eq!(
        chain.next_strategy(),
        Some(&ConnectionStrategy::RelayCircuit)
    );
    assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Turn));
    assert!(chain.exhausted());
}

#[test]
fn fallback_chain_reset_restarts() {
    let mut chain = FallbackChain::new(false, false);
    chain.next_strategy();
    chain.next_strategy();
    assert!(chain.exhausted());

    chain.reset();
    assert!(!chain.exhausted());
    assert_eq!(chain.peek(), Some(&ConnectionStrategy::Direct));
}

// ---------------------------------------------------------------------------
// Config toggle behaviour tests
// ---------------------------------------------------------------------------

#[test]
fn default_config_has_autonat_enabled() {
    let config = NetworkConfig::default();
    assert!(config.enable_autonat);
    assert!(config.enable_relay_client);
    assert!(!config.enable_relay_server);
    assert!(!config.relay_only);
    assert!(!config.enable_turn);
}

#[test]
fn relay_server_config_valid() {
    let config = NetworkConfig {
        enable_relay_server: true,
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn turn_config_requires_servers() {
    let config = NetworkConfig {
        enable_turn: true,
        turn_servers: Vec::new(),
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn turn_config_with_servers_valid() {
    let config = NetworkConfig {
        enable_turn: true,
        turn_servers: vec!["turn:example.com:3478".into()],
        ..NetworkConfig::default()
    };
    assert!(config.validate().is_ok());
}

// ---------------------------------------------------------------------------
// TURN stub tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn turn_allocate_returns_error() {
    let client = TurnClient::new(vec!["turn:example.com:3478".into()]);
    let result = client.allocate().await;
    assert!(result.is_err());
}

#[test]
fn turn_client_has_servers() {
    let empty = TurnClient::new(Vec::new());
    assert!(!empty.has_servers());

    let with = TurnClient::new(vec!["turn:example.com:3478".into()]);
    assert!(with.has_servers());
}