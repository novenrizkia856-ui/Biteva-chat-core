//! High-level swarm wrapper for the Bitevachat network.
//!
//! [`BitevachatSwarm`] encapsulates the libp2p `Swarm` with the
//! combined [`BitevachatBehaviour`] and provides an async event loop
//! for message routing, gossip, and DHT discovery.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub;
use libp2p::mdns;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, yamux, Multiaddr, PeerId, Swarm};

use bitevachat_crypto::signing::{pubkey_to_address, Keypair, PublicKey};
use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_protocol::nonce::NonceCache;
use bitevachat_types::{Address, BitevachatError, MessageId};
use tokio::sync::mpsc;

use crate::config::NetworkConfig;
use crate::discovery::{
    build_discovery_behaviour, parse_peer_id_from_record, DiscoveryBehaviour,
    DiscoveryBehaviourEvent,
};
use crate::events::NetworkEvent;
use crate::gossip::{self, subscribe_default_topics};
use crate::handler::{MessageHandler, DEFAULT_MAX_TIMESTAMP_SKEW_SECS};
use crate::identity::wallet_keypair_to_libp2p;
use crate::protocol::{Ack, WireMessage, MSG_PROTOCOL};
use crate::routing::{build_wire_message, DeliveryStatus, Router};
use crate::transport;

/// Convenience alias to avoid shadowing `std::result::Result`
/// which the `#[derive(NetworkBehaviour)]` macro requires.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Combined behaviour
// ---------------------------------------------------------------------------

/// Combined libp2p behaviour for Bitevachat.
///
/// Composes:
/// - [`DiscoveryBehaviour`] — Kademlia DHT + Identify.
/// - `cbor::Behaviour<WireMessage, Ack>` — direct messaging via CBOR.
/// - `gossipsub::Behaviour` — pub/sub for metadata.
///
/// The `#[derive(NetworkBehaviour)]` macro auto-generates
/// `BitevachatBehaviourEvent` with one variant per field.
#[derive(NetworkBehaviour)]
pub struct BitevachatBehaviour {
    /// Kademlia + Identify.
    pub discovery: DiscoveryBehaviour,
    /// Direct message send/receive with ACK (CBOR codec).
    pub messaging: libp2p_request_response::cbor::Behaviour<WireMessage, Ack>,
    /// Pub/sub for presence and profile updates.
    pub gossip: gossipsub::Behaviour,
    /// mDNS for automatic LAN peer discovery.
    pub mdns: mdns::tokio::Behaviour,
}

// ---------------------------------------------------------------------------
// BitevachatSwarm
// ---------------------------------------------------------------------------

/// High-level wrapper around `Swarm<BitevachatBehaviour>`.
///
/// Provides a safe async API for the full Bitevachat network layer:
/// message routing with ACK, gossip pub/sub, and DHT discovery.
///
/// # Usage
///
/// ```ignore
/// let (mut swarm, event_rx) = BitevachatSwarm::new(config, &wallet_kp).await?;
/// swarm.start_listening("/ip4/0.0.0.0/tcp/0".parse()?)?;
/// swarm.run().await;
/// ```
pub struct BitevachatSwarm {
    /// The underlying libp2p swarm.
    swarm: Swarm<BitevachatBehaviour>,
    /// Inbound message handler (validation pipeline).
    handler: MessageHandler,
    /// Outbound delivery tracker (pending → ACK).
    router: Router,
    /// Sender-side event channel (receiver given to caller).
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    /// Mapping from Bitevachat Address bytes → libp2p PeerId.
    ///
    /// Populated from:
    /// 1. Identify protocol (extract Ed25519 pubkey → compute address).
    /// 2. Received messages (envelope sender → source peer).
    /// 3. mDNS discovery + DHT lookups.
    address_book: HashMap<[u8; 32], PeerId>,
    /// Our own Ed25519 public key (32 bytes) for WireMessage construction.
    local_sender_pubkey: [u8; 32],
}

impl BitevachatSwarm {
    /// Creates a new swarm with messaging, gossip, and discovery.
    ///
    /// Returns `(swarm, event_receiver)` where `event_receiver` is
    /// the async channel that delivers all [`NetworkEvent`]s to the
    /// caller.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if transport, behaviour,
    /// or identity construction fails.
    pub async fn new(
        config: NetworkConfig,
        wallet_keypair: &Keypair,
    ) -> BResult<(Self, mpsc::UnboundedReceiver<NetworkEvent>)> {
        config.validate()?;

        // Convert wallet identity → libp2p identity.
        let libp2p_keypair = wallet_keypair_to_libp2p(wallet_keypair)?;

        // Channels for network events.
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Shared nonce cache for replay detection.
        let nonce_cache = Arc::new(Mutex::new(NonceCache::new(10_000)));

        // Build handler.
        let handler = MessageHandler::new(
            Arc::clone(&nonce_cache),
            DEFAULT_MAX_TIMESTAMP_SKEW_SECS,
            event_tx.clone(),
        );

        // Build router.
        let router = Router::new();

        // Build swarm via SwarmBuilder.
        let config_clone = config.clone();
        let signing_keypair = libp2p_keypair.clone();

        let swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair)
            .with_tokio()
            .with_tcp(
                transport::tcp_config(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to configure TCP transport: {e}"),
            })?
            .with_quic()
            .with_behaviour(|key| {
                build_combined_behaviour(key, &config_clone, &signing_keypair)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            })
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to build network behaviour: {e}"),
            })?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(
                    config.idle_timeout_secs,
                ))
            })
            .build();

        let me = Self {
            swarm,
            handler,
            router,
            event_sender: event_tx,
            address_book: HashMap::new(),
            local_sender_pubkey: *wallet_keypair.public_key().as_bytes(),
        };

        Ok((me, event_rx))
    }

    /// Returns the local `PeerId` of this swarm.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    // -----------------------------------------------------------------------
    // Listening
    // -----------------------------------------------------------------------

    /// Starts listening on the given multiaddr.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if the address cannot
    /// be bound (e.g. port already in use).
    pub fn start_listening(&mut self, addr: Multiaddr) -> BResult<()> {
        self.swarm
            .listen_on(addr)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to start listening: {e}"),
            })?;
        Ok(())
    }

    /// Returns the list of addresses this swarm is currently listening on.
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    /// Returns the set of currently connected peer IDs.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    // -----------------------------------------------------------------------
    // Address book
    // -----------------------------------------------------------------------

    /// Records a Bitevachat Address → PeerId mapping.
    ///
    /// Called when we learn a peer's identity from the Identify
    /// protocol, from an incoming message, or from a DHT lookup.
    pub fn register_peer_address(&mut self, address: &Address, peer_id: PeerId) {
        self.address_book.insert(*address.as_bytes(), peer_id);
    }

    /// Resolves a Bitevachat Address to a libp2p PeerId, if known.
    pub fn resolve_address(&self, address: &Address) -> Option<PeerId> {
        self.address_book.get(address.as_bytes()).copied()
    }

    /// Returns our own Ed25519 public key (32 bytes).
    pub fn sender_pubkey(&self) -> &[u8; 32] {
        &self.local_sender_pubkey
    }

    /// Attempts to deliver a message to a recipient by Bitevachat Address.
    ///
    /// Looks up the PeerId in the local address book, checks that we
    /// are connected, and dispatches via `request_response`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — message queued for delivery (ACK comes later).
    /// - `Err(...)` — recipient unknown or not connected; retry later.
    pub fn try_deliver_to_address(
        &mut self,
        recipient: &Address,
        envelope: MessageEnvelope,
        message_id: MessageId,
    ) -> BResult<()> {
        let peer_id = self.resolve_address(recipient).ok_or_else(|| {
            BitevachatError::NetworkError {
                reason: format!(
                    "no PeerId known for address {}; DHT lookup needed",
                    recipient,
                ),
            }
        })?;

        // Check if we're actually connected to this peer.
        if !self.swarm.is_connected(&peer_id) {
            return Err(BitevachatError::NetworkError {
                reason: format!(
                    "peer {} is known but not connected",
                    peer_id,
                ),
            });
        }

        let sender_pubkey = self.local_sender_pubkey;
        self.send_message_to_peer(peer_id, envelope, sender_pubkey, message_id)?;

        tracing::info!(
            %message_id,
            %recipient,
            %peer_id,
            "message dispatched to connected peer"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Dialing
    // -----------------------------------------------------------------------

    /// Dials a remote peer at the given multiaddr.
    pub fn dial_peer(&mut self, addr: Multiaddr) -> BResult<()> {
        self.swarm
            .dial(addr)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to dial peer: {e}"),
            })
    }

    // -----------------------------------------------------------------------
    // Discovery (DHT)
    // -----------------------------------------------------------------------

    /// Publishes this node's address → PeerId mapping in the DHT.
    pub fn publish_address(
        &mut self,
        address: &Address,
        peer_id: &PeerId,
    ) -> BResult<kad::QueryId> {
        self.swarm
            .behaviour_mut()
            .discovery
            .publish_address(address, peer_id)
    }

    /// Starts a DHT lookup for the PeerId associated with an address.
    pub fn find_peer(&mut self, address: &Address) -> kad::QueryId {
        self.swarm.behaviour_mut().discovery.find_peer(address)
    }

    /// Adds bootstrap nodes and initiates Kademlia bootstrap.
    pub fn bootstrap(&mut self, nodes: &[Multiaddr]) -> BResult<()> {
        self.swarm
            .behaviour_mut()
            .discovery
            .add_bootstrap_nodes(nodes)?;

        if !nodes.is_empty() {
            self.swarm
                .behaviour_mut()
                .discovery
                .bootstrap()?;
        }

        Ok(())
    }

    /// Sets the Kademlia mode (Client or Server).
    pub fn set_kademlia_mode(&mut self, mode: kad::Mode) {
        self.swarm.behaviour_mut().discovery.set_mode(mode);
    }

    // -----------------------------------------------------------------------
    // Direct messaging
    // -----------------------------------------------------------------------

    /// Sends a message to a connected peer via `request_response`.
    ///
    /// The message is wrapped in a [`WireMessage`] with the sender's
    /// public key and tracked by the [`Router`]. The result (ACK or
    /// failure) is delivered asynchronously as a [`NetworkEvent`].
    ///
    /// # Parameters
    ///
    /// - `peer_id` — target peer's libp2p PeerId.
    /// - `envelope` — signed message envelope.
    /// - `sender_pubkey` — sender's Ed25519 public key (32 bytes).
    /// - `message_id` — message identifier for tracking.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful queueing. The actual delivery result
    /// arrives later as a `NetworkEvent::DeliveryAck` or
    /// `NetworkEvent::DeliveryFailed`.
    pub fn send_message_to_peer(
        &mut self,
        peer_id: PeerId,
        envelope: MessageEnvelope,
        sender_pubkey: [u8; 32],
        message_id: MessageId,
    ) -> BResult<()> {
        let recipient = envelope.message.recipient.clone();
        let wire = build_wire_message(envelope.clone(), sender_pubkey);

        let request_id = self
            .swarm
            .behaviour_mut()
            .messaging
            .send_request(&peer_id, wire);

        self.router.track_send(request_id, message_id, recipient, envelope);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Gossip
    // -----------------------------------------------------------------------

    /// Publishes metadata to a gossipsub topic.
    pub fn publish_gossip(
        &mut self,
        topic_name: &str,
        data: Vec<u8>,
    ) -> BResult<()> {
        gossip::publish_metadata(&mut self.swarm.behaviour_mut().gossip, topic_name, data)
    }

    // -----------------------------------------------------------------------
    // Event loop
    // -----------------------------------------------------------------------

    /// Processes a single swarm event.
    ///
    /// Designed for use inside `tokio::select!` where the caller needs
    /// to multiplex swarm events with other async sources (commands,
    /// timers, shutdown signals). Each call drives the libp2p swarm
    /// forward by one event.
    pub async fn poll_next(&mut self) {
        match self.swarm.select_next_some().await {
            // --- Connection events ------------------------------------
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                tracing::info!(%address, ?listener_id, "new listen address");
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                tracing::info!(
                    %peer_id,
                    ?endpoint,
                    num_established,
                    "connection established"
                );
                let _ = self
                    .event_sender
                    .send(NetworkEvent::PeerConnected(peer_id));
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                cause,
                num_established,
                ..
            } => {
                tracing::info!(%peer_id, ?cause, num_established, "connection closed");
                if num_established == 0 {
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::PeerDisconnected(peer_id));
                }
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(?peer_id, %error, "outgoing connection error");
            }

            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                tracing::warn!(
                    %local_addr,
                    %send_back_addr,
                    %error,
                    "incoming connection error"
                );
            }

            // --- Behaviour events -------------------------------------
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }

            // --- Catch-all --------------------------------------------
            other => {
                tracing::trace!(?other, "unhandled swarm event");
            }
        }
    }

    /// Runs the swarm event loop, processing all network events.
    ///
    /// This method runs indefinitely. Use `tokio::select!` or task
    /// cancellation to stop it.
    pub async fn run(&mut self) {
        loop {
            match self.swarm.select_next_some().await {
                // --- Connection events ------------------------------------
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } => {
                    tracing::info!(%address, ?listener_id, "new listen address");
                }

                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint,
                    num_established,
                    ..
                } => {
                    tracing::info!(
                        %peer_id,
                        ?endpoint,
                        num_established,
                        "connection established"
                    );
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::PeerConnected(peer_id));
                }

                SwarmEvent::ConnectionClosed {
                    peer_id,
                    cause,
                    num_established,
                    ..
                } => {
                    tracing::info!(%peer_id, ?cause, num_established, "connection closed");
                    if num_established == 0 {
                        let _ = self
                            .event_sender
                            .send(NetworkEvent::PeerDisconnected(peer_id));
                    }
                }

                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    tracing::warn!(?peer_id, %error, "outgoing connection error");
                }

                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                    ..
                } => {
                    tracing::warn!(
                        %local_addr,
                        %send_back_addr,
                        %error,
                        "incoming connection error"
                    );
                }

                // --- Behaviour events -------------------------------------
                SwarmEvent::Behaviour(event) => {
                    self.handle_behaviour_event(event).await;
                }

                // --- Catch-all --------------------------------------------
                other => {
                    tracing::trace!(?other, "unhandled swarm event");
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal event dispatch
    // -----------------------------------------------------------------------

    async fn handle_behaviour_event(&mut self, event: BitevachatBehaviourEvent) {
        match event {
            BitevachatBehaviourEvent::Discovery(disc) => {
                handle_discovery_event(disc, &mut self.address_book, &self.event_sender);
            }
            BitevachatBehaviourEvent::Messaging(msg_event) => {
                self.handle_messaging_event(msg_event).await;
            }
            BitevachatBehaviourEvent::Gossip(gossip_event) => {
                self.handle_gossip_event(gossip_event);
            }
            BitevachatBehaviourEvent::Mdns(mdns_event) => {
                self.handle_mdns_event(mdns_event);
            }
        }
    }

    /// Handles mDNS events for automatic LAN peer discovery.
    ///
    /// When a new peer is discovered via mDNS, we add its addresses
    /// to the Kademlia routing table so DHT lookups can find it.
    fn handle_mdns_event(&mut self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    tracing::info!(%peer_id, %addr, "mDNS: discovered peer");
                    // Add to Kademlia so DHT queries can resolve this peer.
                    self.swarm
                        .behaviour_mut()
                        .discovery
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    // Also dial directly to establish a connection.
                    if let Err(e) = self.swarm.dial(addr) {
                        tracing::debug!(%peer_id, %e, "mDNS: dial failed (may already be connected)");
                    }
                }
            }
            mdns::Event::Expired(peers) => {
                for (peer_id, addr) in peers {
                    tracing::debug!(%peer_id, %addr, "mDNS: peer expired");
                }
            }
        }
    }

    /// Handles request_response events for direct messaging.
    async fn handle_messaging_event(
        &mut self,
        event: request_response::Event<WireMessage, Ack>,
    ) {
        match event {
            // --- Inbound request: validate and respond with ACK ---
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
            } => {
                let wire: WireMessage = request;

                // Learn sender's Address → PeerId mapping.
                let sender_bytes = *wire.envelope.message.sender.as_bytes();
                self.address_book.insert(sender_bytes, peer);

                let result = self
                    .handler
                    .on_message_received(peer, wire.envelope, &wire.sender_pubkey)
                    .await;

                // Send the ACK back through the response channel.
                if self
                    .swarm
                    .behaviour_mut()
                    .messaging
                    .send_response(channel, result.ack.clone())
                    .is_err()
                {
                    tracing::warn!(%peer, "failed to send ACK (channel closed)");
                }
            }

            // --- Outbound response: ACK received from remote ---
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => {
                if let Some((msg_id, status)) =
                    self.router.on_ack_received(&request_id, &response)
                {
                    match status {
                        DeliveryStatus::Delivered => {
                            tracing::info!(?msg_id, %peer, "message delivered (ACK Ok)");
                            let _ = self
                                .event_sender
                                .send(NetworkEvent::DeliveryAck(msg_id));
                        }
                        DeliveryStatus::Failed => {
                            tracing::warn!(?msg_id, %peer, ?response, "message rejected by peer");
                            let _ = self
                                .event_sender
                                .send(NetworkEvent::DeliveryFailed(msg_id));
                        }
                        DeliveryStatus::Queued => {
                            // Should not occur for an ACK, but handle gracefully.
                            tracing::debug!(?msg_id, "unexpected Queued status on ACK");
                        }
                    }
                }
            }

            // --- Outbound failure: send failed ---
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                tracing::warn!(%peer, ?error, "outbound message delivery failed");
                if let Some(pending) = self.router.on_send_failed(&request_id) {
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::DeliveryFailed(pending.message_id));
                }
            }

            // --- Inbound failure: handler error ---
            request_response::Event::InboundFailure {
                peer,
                error,
                ..
            } => {
                tracing::warn!(%peer, ?error, "inbound message handling failed");
            }

            // --- Response sent confirmation ---
            request_response::Event::ResponseSent { peer, .. } => {
                tracing::trace!(%peer, "ACK response sent");
            }
        }
    }

    /// Handles gossipsub events.
    fn handle_gossip_event(&self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            } => {
                let _ = self.event_sender.send(NetworkEvent::GossipMessage {
                    source: propagation_source,
                    topic: message.topic.to_string(),
                    data: message.data,
                });
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                tracing::debug!(%peer_id, %topic, "peer subscribed to topic");
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                tracing::debug!(%peer_id, %topic, "peer unsubscribed from topic");
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                tracing::trace!(%peer_id, "gossipsub not supported by peer");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery event handlers (logging)
// ---------------------------------------------------------------------------

fn handle_discovery_event(
    event: DiscoveryBehaviourEvent,
    address_book: &mut HashMap<[u8; 32], PeerId>,
    event_sender: &mpsc::UnboundedSender<NetworkEvent>,
) {
    match event {
        DiscoveryBehaviourEvent::Kademlia(kad_event) => {
            handle_kademlia_event(kad_event);
        }
        DiscoveryBehaviourEvent::Identify(id_event) => {
            handle_identify_event(id_event, address_book, event_sender);
        }
    }
}

fn handle_kademlia_event(event: kad::Event) {
    match event {
        kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        } => match result {
            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(
                kad::PeerRecord { record, .. },
            ))) => match parse_peer_id_from_record(&record.value) {
                Ok(peer_id) => {
                    tracing::info!(?id, %peer_id, "DHT get_record succeeded");
                }
                Err(e) => {
                    tracing::warn!(?id, %e, "DHT get_record returned unparseable value");
                }
            },
            kad::QueryResult::GetRecord(Ok(
                kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
            )) => {
                tracing::debug!(?id, "DHT get_record finished (no more records)");
            }
            kad::QueryResult::GetRecord(Err(e)) => {
                tracing::warn!(?id, ?e, "DHT get_record failed");
            }
            kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                tracing::info!(?id, ?key, "DHT put_record succeeded");
            }
            kad::QueryResult::PutRecord(Err(e)) => {
                tracing::warn!(?id, ?e, "DHT put_record failed");
            }
            kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk {
                peer,
                num_remaining,
            })) => {
                tracing::info!(?id, %peer, num_remaining, "Kademlia bootstrap progress");
            }
            kad::QueryResult::Bootstrap(Err(e)) => {
                tracing::warn!(?id, ?e, "Kademlia bootstrap failed");
            }
            kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                tracing::debug!(?id, peers = ?ok.peers, "get_closest_peers result");
            }
            kad::QueryResult::GetClosestPeers(Err(e)) => {
                tracing::warn!(?id, ?e, "get_closest_peers failed");
            }
            other => {
                tracing::trace!(?id, ?step, ?other, "other Kademlia query result");
            }
        },
        kad::Event::RoutingUpdated {
            peer, addresses, ..
        } => {
            tracing::debug!(%peer, ?addresses, "Kademlia routing table updated");
        }
        kad::Event::InboundRequest { request } => {
            tracing::trace!(?request, "Kademlia inbound request");
        }
        other => {
            tracing::trace!(?other, "other Kademlia event");
        }
    }
}

fn handle_identify_event(
    event: identify::Event,
    address_book: &mut HashMap<[u8; 32], PeerId>,
    event_sender: &mpsc::UnboundedSender<NetworkEvent>,
) {
    match event {
        identify::Event::Received { peer_id, info, .. } => {
            tracing::info!(
                %peer_id,
                protocol_version = %info.protocol_version,
                agent_version = %info.agent_version,
                listen_addrs = ?info.listen_addrs,
                "identify: received peer info"
            );

            // If the peer's public key is Ed25519, compute their
            // Bitevachat address and add to the address book.
            if let Ok(ed_pk) = info.public_key.try_into_ed25519() {
                let raw_bytes = ed_pk.to_bytes();
                let bpk = PublicKey::from_bytes(raw_bytes);
                let address = pubkey_to_address(&bpk);
                address_book.insert(*address.as_bytes(), peer_id);
                tracing::info!(
                    %peer_id,
                    %address,
                    "identify: mapped peer address in address book"
                );

                // Notify higher layers so they can flush pending
                // messages for this newly-reachable address.
                let _ = event_sender.send(NetworkEvent::PeerAddressResolved {
                    address,
                    peer_id,
                });
            }
        }
        identify::Event::Sent { peer_id, .. } => {
            tracing::debug!(%peer_id, "identify: sent our info to peer");
        }
        identify::Event::Pushed { peer_id, info, .. } => {
            tracing::debug!(
                %peer_id,
                agent_version = %info.agent_version,
                "identify: pushed info update to peer"
            );
        }
        identify::Event::Error { peer_id, error, .. } => {
            tracing::warn!(%peer_id, %error, "identify: error");
        }
    }
}

// ---------------------------------------------------------------------------
// Behaviour construction
// ---------------------------------------------------------------------------

/// Builds the combined [`BitevachatBehaviour`].
fn build_combined_behaviour(
    key: &libp2p::identity::Keypair,
    config: &NetworkConfig,
    signing_keypair: &libp2p::identity::Keypair,
) -> BResult<BitevachatBehaviour> {
    let discovery = build_discovery_behaviour(key, config)?;

    // Use the built-in CBOR codec from libp2p-request-response.
    // Behaviour::new creates a default cbor::Codec internally;
    // WireMessage/Ack implement Serialize + Deserialize via serde.
    let messaging = libp2p_request_response::cbor::Behaviour::<WireMessage, Ack>::new(
        [(MSG_PROTOCOL, ProtocolSupport::Full)],
        request_response::Config::default(),
    );

    let mut gossip_beh = gossip::build_gossip_behaviour(signing_keypair)?;
    subscribe_default_topics(&mut gossip_beh)?;

    // mDNS for automatic LAN peer discovery.
    let local_peer_id = PeerId::from(key.public());
    let mdns_config = mdns::Config {
        ttl: Duration::from_secs(300),
        query_interval: Duration::from_secs(30),
        enable_ipv6: false,
    };
    let mdns_beh = mdns::tokio::Behaviour::new(mdns_config, local_peer_id)
        .map_err(|e| BitevachatError::NetworkError {
            reason: format!("failed to create mDNS behaviour: {e}"),
        })?;

    Ok(BitevachatBehaviour {
        discovery,
        messaging,
        gossip: gossip_beh,
        mdns: mdns_beh,
    })
}