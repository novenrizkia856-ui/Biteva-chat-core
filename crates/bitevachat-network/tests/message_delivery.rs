//! Integration tests for message delivery validation.
//!
//! Tests the inbound message handler pipeline: pubkey→address binding,
//! Ed25519 signature verification, timestamp skew, nonce replay detection,
//! and ACK generation.

use std::sync::{Arc, Mutex};

use bitevachat_crypto::signing::{pubkey_to_address, Keypair};
use bitevachat_network::events::NetworkEvent;
use bitevachat_network::handler::{MessageHandler, DEFAULT_MAX_TIMESTAMP_SKEW_SECS};
use bitevachat_network::protocol::Ack;
use bitevachat_protocol::canonical::to_canonical_cbor;
use bitevachat_protocol::message::{Message, MessageEnvelope};
use bitevachat_protocol::nonce::NonceCache;
use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType, Timestamp};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_test_envelope(sender_kp: &Keypair) -> (MessageEnvelope, [u8; 32]) {
    let sender_pk = sender_kp.public_key();
    let sender_addr = pubkey_to_address(&sender_pk);

    let msg = Message {
        sender: sender_addr,
        recipient: Address::new([0xBB; 32]),
        payload_type: PayloadType::Text,
        payload_ciphertext: b"encrypted-data".to_vec(),
        node_id: NodeId::new([0x01; 32]),
        nonce: Nonce::new([0xAA; 12]),
        timestamp: Timestamp::now(),
        message_id: MessageId::new([0xCC; 32]),
    };

    // Sign the canonical CBOR encoding — same as handler verifies.
    let canonical = to_canonical_cbor(&msg).expect("canonical CBOR");
    let signature = sender_kp.sign(&canonical);

    let envelope = MessageEnvelope {
        message: msg,
        signature,
    };
    let pubkey_bytes = *sender_pk.as_bytes();
    (envelope, pubkey_bytes)
}

fn setup_handler() -> (MessageHandler, mpsc::UnboundedReceiver<NetworkEvent>) {
    let cache = Arc::new(Mutex::new(NonceCache::new(1000)));
    let (tx, rx) = mpsc::unbounded_channel();
    let handler = MessageHandler::new(cache, DEFAULT_MAX_TIMESTAMP_SKEW_SECS, tx);
    (handler, rx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_message_accepted_and_ack_ok() {
    let (handler, mut rx) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let (envelope, pubkey) = make_test_envelope(&sender_kp);

    let peer_id = libp2p::PeerId::random();
    let result = handler
        .on_message_received(peer_id, envelope, &pubkey)
        .await;

    assert_eq!(result.ack, Ack::Ok);

    // Handler should have emitted a MessageReceived event.
    let event = rx.try_recv().expect("should receive event");
    assert!(matches!(event, NetworkEvent::MessageReceived(_)));
}

#[tokio::test]
async fn invalid_signature_rejected() {
    let (handler, _rx) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let (mut envelope, pubkey) = make_test_envelope(&sender_kp);

    // Tamper with the payload to invalidate the signature.
    envelope.message.payload_ciphertext = b"tampered".to_vec();

    let peer_id = libp2p::PeerId::random();
    let result = handler
        .on_message_received(peer_id, envelope, &pubkey)
        .await;

    assert_eq!(result.ack, Ack::InvalidSignature);
}

#[tokio::test]
async fn wrong_sender_pubkey_rejected() {
    let (handler, _rx) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let (_envelope, _pubkey) = make_test_envelope(&sender_kp);

    // Use a different keypair's envelope but wrong pubkey.
    let (envelope, _) = make_test_envelope(&sender_kp);
    let wrong_pubkey = [0xFF; 32];

    let peer_id = libp2p::PeerId::random();
    let result = handler
        .on_message_received(peer_id, envelope, &wrong_pubkey)
        .await;

    assert_eq!(result.ack, Ack::InvalidSignature);
}

#[tokio::test]
async fn replay_attempt_rejected() {
    let (handler, _rx) = setup_handler();
    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let (envelope, pubkey) = make_test_envelope(&sender_kp);

    let peer_id = libp2p::PeerId::random();

    // First send should succeed.
    let r1 = handler
        .on_message_received(peer_id, envelope.clone(), &pubkey)
        .await;
    assert_eq!(r1.ack, Ack::Ok);

    // Replay with same nonce should fail.
    let r2 = handler
        .on_message_received(peer_id, envelope, &pubkey)
        .await;
    assert_eq!(r2.ack, Ack::InvalidNonce);
}

#[tokio::test]
async fn expired_timestamp_rejected() {
    let (handler_custom, _rx) = {
        let cache = Arc::new(Mutex::new(NonceCache::new(1000)));
        let (tx, rx) = mpsc::unbounded_channel();
        // Use a very tight timestamp skew (1 second).
        let handler = MessageHandler::new(cache, 1, tx);
        (handler, rx)
    };

    let sender_kp = Keypair::from_seed(&[0x01; 32]);
    let sender_pk = sender_kp.public_key();
    let sender_addr = pubkey_to_address(&sender_pk);

    // Create a message with a timestamp 10 minutes in the past.
    let old_ts = {
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::seconds(600);
        Timestamp::from_datetime(old)
    };

    let msg = Message {
        sender: sender_addr,
        recipient: Address::new([0xBB; 32]),
        payload_type: PayloadType::Text,
        payload_ciphertext: b"encrypted-data".to_vec(),
        node_id: NodeId::new([0x01; 32]),
        nonce: Nonce::new([0xBB; 12]),
        timestamp: old_ts,
        message_id: MessageId::new([0xDD; 32]),
    };

    let canonical = to_canonical_cbor(&msg).expect("canonical CBOR");
    let signature = sender_kp.sign(&canonical);
    let envelope = MessageEnvelope {
        message: msg,
        signature,
    };
    let pubkey_bytes = *sender_pk.as_bytes();

    let peer_id = libp2p::PeerId::random();
    let result = handler_custom
        .on_message_received(peer_id, envelope, &pubkey_bytes)
        .await;

    assert_eq!(result.ack, Ack::InvalidTimestamp);
}

#[tokio::test]
async fn ack_serialization_deterministic() {
    let variants = [
        Ack::Ok,
        Ack::InvalidSignature,
        Ack::InvalidNonce,
        Ack::InvalidTimestamp,
        Ack::DecryptionFailed,
    ];

    for ack in &variants {
        let mut bytes1 = Vec::new();
        ciborium::into_writer(ack, &mut bytes1).expect("serialize");
        let mut bytes2 = Vec::new();
        ciborium::into_writer(ack, &mut bytes2).expect("serialize");
        assert_eq!(bytes1, bytes2, "CBOR serialization not deterministic for {ack:?}");

        // Roundtrip check.
        let decoded: Ack = ciborium::from_reader(bytes1.as_slice()).expect("deserialize");
        assert_eq!(&decoded, ack);
    }
}

#[tokio::test]
async fn two_nodes_create_and_connect() {
    use std::time::Duration;
    use tokio::time::timeout;

    let _ = tracing_subscriber::fmt()
        .with_env_filter("bitevachat_network=debug")
        .try_init();

    let config = bitevachat_network::config::NetworkConfig::default();

    // --- Node A ---
    let kp_a = Keypair::from_seed(&[0xAA; 32]);
    let (mut swarm_a, mut rx_a) =
        bitevachat_network::swarm::BitevachatSwarm::new(config.clone(), &kp_a)
            .await
            .expect("swarm A");

    swarm_a
        .start_listening("/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
        .expect("listen A");

    // --- Node B ---
    let kp_b = Keypair::from_seed(&[0xBB; 32]);
    let (mut swarm_b, mut rx_b) =
        bitevachat_network::swarm::BitevachatSwarm::new(config, &kp_b)
            .await
            .expect("swarm B");

    swarm_b
        .start_listening("/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
        .expect("listen B");

    // Poll both swarms briefly so they bind their listeners.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Get node A's actual listen address.
    let addr_a = swarm_a.listeners().into_iter().next().expect("listener A");

    // Dial from B → A.
    let peer_a = *swarm_a.local_peer_id();
    let dial_addr: libp2p::Multiaddr =
        format!("{addr_a}/p2p/{peer_a}").parse().expect("dial addr");
    swarm_b.dial_peer(dial_addr).expect("dial");

    // Run both event loops concurrently, wait for PeerConnected events.
    let run_a = tokio::spawn(async move { swarm_a.run().await });
    let run_b = tokio::spawn(async move { swarm_b.run().await });

    // Wait for both sides to report PeerConnected.
    let got_a = timeout(Duration::from_secs(10), async {
        while let Some(ev) = rx_a.recv().await {
            if matches!(ev, NetworkEvent::PeerConnected(_)) {
                return true;
            }
        }
        false
    })
    .await;

    let got_b = timeout(Duration::from_secs(10), async {
        while let Some(ev) = rx_b.recv().await {
            if matches!(ev, NetworkEvent::PeerConnected(_)) {
                return true;
            }
        }
        false
    })
    .await;

    assert!(got_a.unwrap_or(false), "node A should see PeerConnected");
    assert!(got_b.unwrap_or(false), "node B should see PeerConnected");

    // Abort the event loops.
    run_a.abort();
    run_b.abort();
}