//! Integration tests for P2P message delivery.
//!
//! Tests the full message lifecycle: send → validate → ACK.
//! Requires `tokio` multi-thread runtime.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitevachat_crypto::signing::{pubkey_to_address, Keypair, PublicKey, Signature};
use bitevachat_network::config::NetworkConfig;
use bitevachat_network::events::NetworkEvent;
use bitevachat_network::handler::MessageHandler;
use bitevachat_network::protocol::Ack;
use bitevachat_network::swarm::BitevachatSwarm;
use bitevachat_protocol::message::{Message, MessageEnvelope};
use bitevachat_protocol::nonce::NonceCache;
use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType, Signable, Timestamp};
use libp2p::kad;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constructs a signed `MessageEnvelope` from the given keypair.
fn make_envelope(
    sender_kp: &Keypair,
    recipient_addr: Address,
    nonce_byte: u8,
) -> MessageEnvelope {
    let sender_pk = sender_kp.public_key();
    let sender_addr = pubkey_to_address(&sender_pk);

    let msg = Message {
        sender: sender_addr,
        recipient: recipient_addr,
        payload_type: PayloadType::Text,
        payload_ciphertext: b"test-encrypted-payload".to_vec(),
        node_id: NodeId::new([0x01; 32]),
        nonce: Nonce::new([nonce_byte; 12]),
        timestamp: Timestamp::now(),
        message_id: MessageId::new([nonce_byte; 32]),
    };

    let signable = msg.signable_bytes();
    let signature = sender_kp.sign(&signable);

    MessageEnvelope { message: msg, signature }
}

/// Creates a handler + event receiver for unit-level tests.
fn setup_handler() -> (
    MessageHandler,
    mpsc::UnboundedReceiver<NetworkEvent>,
    Arc<Mutex<NonceCache>>,
) {
    let cache = Arc::new(Mutex::new(NonceCache::new(1000)));
    let (tx, rx) = mpsc::unbounded_channel();
    let handler =
        MessageHandler::new(cache.clone(), tx);
    (handler, rx, cache)
}

// ---------------------------------------------------------------------------
// Unit-level handler tests (no swarm needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_message_accepted_and_ack_ok() {
    let (handler, mut rx, _cache) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let sender_pk = *sender_kp.public_key().as_bytes();

    let envelope = make_envelope(&sender_kp, Address::new([0xBB; 32]), 0xAA);
    let peer_id = libp2p::PeerId::random();

    let result = handler
        .on_message_received(peer_id, envelope, &sender_pk)
        .await;

    assert_eq!(result.ack, Ack::Ok, "valid message should produce Ack::Ok");

    // Event should have been emitted.
    let event = rx.try_recv();
    assert!(
        event.is_ok(),
        "NetworkEvent::MessageReceived should be emitted"
    );
    match event.as_ref().ok() {
        Some(NetworkEvent::MessageReceived(_)) => {}
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_signature_rejected() {
    let (handler, mut rx, _cache) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let sender_pk = *sender_kp.public_key().as_bytes();

    let mut envelope = make_envelope(&sender_kp, Address::new([0xBB; 32]), 0xAA);

    // Tamper with the signature.
    let mut sig_bytes = *envelope.signature.as_bytes();
    sig_bytes[0] ^= 0xFF;
    envelope.signature = Signature::from_bytes(sig_bytes);

    let peer_id = libp2p::PeerId::random();
    let result = handler
        .on_message_received(peer_id, envelope, &sender_pk)
        .await;

    assert_eq!(
        result.ack,
        Ack::InvalidSignature,
        "tampered signature should be rejected"
    );

    // No event should be emitted.
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn replay_attempt_rejected() {
    let (handler, _rx, _cache) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let sender_pk = *sender_kp.public_key().as_bytes();

    let envelope = make_envelope(&sender_kp, Address::new([0xBB; 32]), 0xAA);
    let peer_id = libp2p::PeerId::random();

    // First delivery succeeds.
    let r1 = handler
        .on_message_received(peer_id, envelope.clone(), &sender_pk)
        .await;
    assert_eq!(r1.ack, Ack::Ok);

    // Replay attempt with same nonce + sender.
    let r2 = handler
        .on_message_received(peer_id, envelope, &sender_pk)
        .await;
    assert_eq!(
        r2.ack,
        Ack::InvalidNonce,
        "replayed nonce should be rejected"
    );
}

#[tokio::test]
async fn wrong_sender_pubkey_rejected() {
    let (handler, _rx, _cache) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);

    let envelope = make_envelope(&sender_kp, Address::new([0xBB; 32]), 0xAA);
    let peer_id = libp2p::PeerId::random();

    // Use a completely different public key.
    let wrong_pk = [0xFF; 32];
    let result = handler
        .on_message_received(peer_id, envelope, &wrong_pk)
        .await;

    assert_eq!(
        result.ack,
        Ack::InvalidSignature,
        "wrong pubkey should produce InvalidSignature"
    );
}

#[tokio::test]
async fn expired_timestamp_rejected() {
    let (handler, _rx, _cache) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let sender_pk = *sender_kp.public_key().as_bytes();
    let sender_addr = pubkey_to_address(&PublicKey::from_bytes(sender_pk));

    // Create a message with a timestamp 10 minutes in the past.
    let old_dt = chrono::Utc::now() - chrono::Duration::minutes(10);
    let msg = Message {
        sender: sender_addr,
        recipient: Address::new([0xBB; 32]),
        payload_type: PayloadType::Text,
        payload_ciphertext: b"old-message".to_vec(),
        node_id: NodeId::new([0x01; 32]),
        nonce: Nonce::new([0xDD; 12]),
        timestamp: Timestamp::from_datetime(old_dt),
        message_id: MessageId::new([0xDD; 32]),
    };

    let signable = msg.signable_bytes();
    let signature = sender_kp.sign(&signable);
    let envelope = MessageEnvelope { message: msg, signature };

    let peer_id = libp2p::PeerId::random();
    let result = handler
        .on_message_received(peer_id, envelope, &sender_pk)
        .await;

    assert_eq!(
        result.ack,
        Ack::InvalidTimestamp,
        "expired timestamp should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Swarm-level tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_create_and_connect() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("bitevachat_network=debug")
        .try_init();

    // --- Node A ---
    let seed_a = [0x01u8; 32];
    let keypair_a = Keypair::from_seed(&seed_a);
    let nonce_cache_a = Arc::new(Mutex::new(NonceCache::new(1000)));

    let config_a = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0"
            .parse()
            .expect("valid multiaddr"),
        ..NetworkConfig::default()
    };

    let (mut swarm_a, mut rx_a) =
        BitevachatSwarm::new(config_a.clone(), &keypair_a, nonce_cache_a)
            .await
            .expect("failed to create swarm A");

    let peer_id_a = *swarm_a.local_peer_id();
    swarm_a
        .start_listening(config_a.listen_addr)
        .expect("listen A");
    swarm_a.set_kademlia_mode(kad::Mode::Server);

    // --- Node B ---
    let seed_b = [0x02u8; 32];
    let keypair_b = Keypair::from_seed(&seed_b);
    let nonce_cache_b = Arc::new(Mutex::new(NonceCache::new(1000)));

    let config_b = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0"
            .parse()
            .expect("valid multiaddr"),
        ..NetworkConfig::default()
    };

    let (mut swarm_b, mut rx_b) =
        BitevachatSwarm::new(config_b.clone(), &keypair_b, nonce_cache_b)
            .await
            .expect("failed to create swarm B");

    let peer_id_b = *swarm_b.local_peer_id();
    swarm_b
        .start_listening(config_b.listen_addr)
        .expect("listen B");
    swarm_b.set_kademlia_mode(kad::Mode::Server);

    assert_ne!(peer_id_a, peer_id_b, "PeerIds must differ");

    // Wait for listeners to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addr_a = swarm_a
        .listeners()
        .into_iter()
        .next()
        .expect("node A must have a listen address");

    let dial_addr: libp2p::Multiaddr = format!("{addr_a}/p2p/{peer_id_a}")
        .parse()
        .expect("valid dial multiaddr");

    swarm_b.dial_peer(dial_addr).expect("dial A from B");

    // Run both swarms in background tasks.
    let handle_a = tokio::spawn(async move { swarm_a.run().await });
    let handle_b = tokio::spawn(async move { swarm_b.run().await });

    // Wait for PeerConnected events from both sides.
    let mut a_connected = false;
    let mut b_connected = false;

    let timeout = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(timeout);

    while !a_connected || !b_connected {
        tokio::select! {
            _ = &mut timeout => {
                panic!("timeout: nodes did not connect within 10 seconds");
            }
            Some(event) = rx_a.recv(), if !a_connected => {
                if matches!(event, NetworkEvent::PeerConnected(_)) {
                    a_connected = true;
                }
            }
            Some(event) = rx_b.recv(), if !b_connected => {
                if matches!(event, NetworkEvent::PeerConnected(_)) {
                    b_connected = true;
                }
            }
        }
    }

    tracing::info!("both nodes connected successfully");

    // Clean up.
    handle_a.abort();
    handle_b.abort();
}

// ---------------------------------------------------------------------------
// Protocol codec tests
// ---------------------------------------------------------------------------

#[test]
fn ack_serialization_deterministic() {
    use bitevachat_network::protocol::Ack;

    let variants = [
        Ack::Ok,
        Ack::InvalidSignature,
        Ack::InvalidNonce,
        Ack::InvalidTimestamp,
        Ack::DecryptionFailed,
    ];

    for ack in &variants {
        let mut buf1 = Vec::new();
        ciborium::into_writer(ack, &mut buf1).unwrap();
        let mut buf2 = Vec::new();
        ciborium::into_writer(ack, &mut buf2).unwrap();
        assert_eq!(buf1, buf2, "Ack serialization must be deterministic");
    }
}

#[test]
fn ack_cbor_roundtrip_all_variants() {
    use bitevachat_network::protocol::Ack;

    let variants = [
        Ack::Ok,
        Ack::InvalidSignature,
        Ack::InvalidNonce,
        Ack::InvalidTimestamp,
        Ack::DecryptionFailed,
    ];

    for ack in &variants {
        let mut buf = Vec::new();
        ciborium::into_writer(ack, &mut buf).unwrap();
        let decoded: Ack = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(&decoded, ack);
    }
}