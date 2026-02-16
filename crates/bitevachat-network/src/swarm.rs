//! High-level swarm wrapper for the Bitevachat network.
//!
//! [`BitevachatSwarm`] encapsulates the libp2p `Swarm` with the
//! combined [`BitevachatBehaviour`] and provides an async event loop
//! for message routing, gossip, DHT discovery, and NAT traversal.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::autonat;
use libp2p::dcutr;
use libp2p::gossipsub;
use libp2p::relay;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, yamux, Multiaddr, PeerId, Swarm};

use bitevachat_crypto::signing::Keypair;
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
use crate::hole_punch;
use crate::identity::wallet_keypair_to_libp2p;
use crate::nat::{self, NatManager};
use crate::protocol::{Ack, WireMessage, MSG_PROTOCOL};
use crate::relay as relay_mod;
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
/// - `autonat::Behaviour` — NAT status detection.
/// - `relay::client::Behaviour` — relay client for NAT traversal.
/// - `dcutr::Behaviour` — Direct Connection Upgrade through Relay.
/// - `Toggle<relay::Behaviour>` — optional relay server.
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
    /// NAT status detection via AutoNAT probes.
    pub autonat: autonat::Behaviour,
    /// Relay client for connecting through relay nodes.
    pub relay_client: relay::client::Behaviour,
    /// DCUtR hole punching (automatic relay → direct upgrade).
    pub dcutr: dcutr::Behaviour,
    /// Optional relay server (serves as relay for other peers).
    pub relay_server: Toggle<relay::Behaviour>,
}

// ---------------------------------------------------------------------------
// BitevachatSwarm
// ---------------------------------------------------------------------------

/// High-level wrapper around `Swarm<BitevachatBehaviour>`.
///
/// Provides a safe async API for the full Bitevachat network layer:
/// message routing with ACK, gossip pub/sub, DHT discovery, and
/// NAT traversal with automatic fallback.
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
    /// NAT status manager.
    nat_manager: NatManager,
    /// Whether relay-only mode is active.
    relay_only: bool,
}

impl BitevachatSwarm {
    /// Creates a new swarm with messaging, gossip, discovery, and
    /// NAT traversal.
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

        // Capture config for the behaviour closure.
        let config_clone = config.clone();
        let signing_keypair = libp2p_keypair.clone();
        let relay_only = config.relay_only;

        // Build swarm via SwarmBuilder with relay client transport.
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
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to configure relay client transport: {e}"),
            })?
            .with_behaviour(|key, relay_client| {
                build_combined_behaviour(
                    key,
                    &config_clone,
                    &signing_keypair,
                    relay_client,
                )
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
            nat_manager: NatManager::new(),
            relay_only,
        };

        Ok((me, event_rx))
    }

    /// Returns the local `PeerId` of this swarm.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Returns the current NAT status.
    pub fn nat_status(&self) -> &nat::NatStatus {
        self.nat_manager.current_status()
    }

    /// Returns the discovered external address, if any.
    pub fn external_address(&self) -> Option<&Multiaddr> {
        self.nat_manager.external_address()
    }

    /// Returns whether relay-only mode is active.
    pub fn is_relay_only(&self) -> bool {
        self.relay_only
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

    /// Starts listening on a relay circuit address.
    ///
    /// This makes the node reachable through the relay for peers
    /// that cannot connect directly. The relay must be connected
    /// first.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if the relay listen
    /// address cannot be constructed or bound.
    pub fn listen_on_relay(
        &mut self,
        relay_addr: &Multiaddr,
        relay_peer_id: &PeerId,
    ) -> BResult<()> {
        let listen_addr =
            relay_mod::build_relay_listen_addr(relay_addr, relay_peer_id)?;

        self.swarm
            .listen_on(listen_addr)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to listen on relay: {e}"),
            })?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Dialing
    // -----------------------------------------------------------------------

    /// Dials a remote peer at the given multiaddr.
    ///
    /// In relay-only mode, this method rejects direct addresses and
    /// only accepts relay circuit addresses.
    pub fn dial_peer(&mut self, addr: Multiaddr) -> BResult<()> {
        if self.relay_only {
            let addr_str = addr.to_string();
            if !addr_str.contains("p2p-circuit") {
                return Err(BitevachatError::NetworkError {
                    reason: "relay-only mode: direct dial disabled; \
                             use a relay circuit address"
                        .into(),
                });
            }
        }

        self.swarm
            .dial(addr)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to dial peer: {e}"),
            })
    }

    /// Dials a peer through a relay circuit.
    ///
    /// Constructs a circuit address and dials it. DCUtR will
    /// automatically attempt to upgrade to a direct connection.
    pub fn dial_via_relay(
        &mut self,
        relay_addr: &Multiaddr,
        relay_peer_id: &PeerId,
        target_peer_id: &PeerId,
    ) -> BResult<()> {
        let circuit_addr = relay_mod::build_relay_circuit_addr(
            relay_addr,
            relay_peer_id,
            target_peer_id,
        )?;

        tracing::info!(
            %target_peer_id,
            %relay_peer_id,
            "dialing peer via relay circuit"
        );

        self.swarm
            .dial(circuit_addr)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to dial via relay: {e}"),
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

        self.router
            .track_send(request_id, message_id, recipient, envelope);

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
        gossip::publish_metadata(
            &mut self.swarm.behaviour_mut().gossip,
            topic_name,
            data,
        )
    }

    // -----------------------------------------------------------------------
    // Event loop
    // -----------------------------------------------------------------------

    /// Processes exactly one swarm event.
    ///
    /// Designed for integration with `tokio::select!` in the node
    /// event loop. Each call awaits the next event from the libp2p
    /// swarm and dispatches it through the appropriate handler.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped before
    /// completion, no events are lost — they remain in the swarm's
    /// internal queue for the next poll.
    pub async fn poll_next(&mut self) {
        let event = self.swarm.select_next_some().await;
        self.dispatch_swarm_event(event).await;
    }

    /// Runs the swarm event loop, processing all network events.
    ///
    /// This method runs indefinitely. Use `tokio::select!` or task
    /// cancellation to stop it. Prefer [`poll_next`](Self::poll_next)
    /// when integrating with external event loops.
    pub async fn run(&mut self) {
        loop {
            self.poll_next().await;
        }
    }

    /// Dispatches a single swarm event to the appropriate handler.
    async fn dispatch_swarm_event(
        &mut self,
        event: SwarmEvent<BitevachatBehaviourEvent>,
    ) {
        match event {
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
                tracing::info!(
                    %peer_id, ?cause, num_established,
                    "connection closed"
                );
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

    // -----------------------------------------------------------------------
    // Internal event dispatch
    // -----------------------------------------------------------------------

    async fn handle_behaviour_event(&mut self, event: BitevachatBehaviourEvent) {
        match event {
            BitevachatBehaviourEvent::Discovery(disc) => {
                handle_discovery_event(disc);
            }
            BitevachatBehaviourEvent::Messaging(msg_event) => {
                self.handle_messaging_event(msg_event).await;
            }
            BitevachatBehaviourEvent::Gossip(gossip_event) => {
                self.handle_gossip_event(gossip_event);
            }
            BitevachatBehaviourEvent::Autonat(autonat_event) => {
                if let Some(new_status) =
                    self.nat_manager.on_autonat_event(autonat_event)
                {
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::NatStatusChanged(new_status));
                }
            }
            BitevachatBehaviourEvent::RelayClient(relay_event) => {
                relay_mod::log_relay_client_event(&relay_event);
            }
            BitevachatBehaviourEvent::Dcutr(dcutr_event) => {
                if let Some(peer_id) =
                    hole_punch::handle_dcutr_event(dcutr_event)
                {
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::HolePunchSucceeded(peer_id));
                }
            }
            BitevachatBehaviourEvent::RelayServer(relay_event) => {
                relay_mod::log_relay_server_event(&relay_event);
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
                            tracing::warn!(
                                ?msg_id, %peer, ?response,
                                "message rejected by peer"
                            );
                            let _ = self
                                .event_sender
                                .send(NetworkEvent::DeliveryFailed(msg_id));
                        }
                        DeliveryStatus::Queued => {
                            tracing::debug!(
                                ?msg_id,
                                "unexpected Queued status on ACK"
                            );
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
                tracing::warn!(
                    %peer, ?error,
                    "outbound message delivery failed"
                );
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

fn handle_discovery_event(event: DiscoveryBehaviourEvent) {
    match event {
        DiscoveryBehaviourEvent::Kademlia(kad_event) => {
            handle_kademlia_event(kad_event);
        }
        DiscoveryBehaviourEvent::Identify(id_event) => {
            handle_identify_event(id_event);
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
                    tracing::warn!(
                        ?id, %e,
                        "DHT get_record returned unparseable value"
                    );
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
                tracing::info!(
                    ?id, %peer, num_remaining,
                    "Kademlia bootstrap progress"
                );
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

fn handle_identify_event(event: identify::Event) {
    match event {
        identify::Event::Received { peer_id, info, .. } => {
            tracing::info!(
                %peer_id,
                protocol_version = %info.protocol_version,
                agent_version = %info.agent_version,
                listen_addrs = ?info.listen_addrs,
                "identify: received peer info"
            );
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
    relay_client: relay::client::Behaviour,
) -> BResult<BitevachatBehaviour> {
    let local_peer_id = key.public().to_peer_id();

    let discovery = build_discovery_behaviour(key, config)?;

    // Use the built-in CBOR codec from libp2p-request-response.
    let messaging = libp2p_request_response::cbor::Behaviour::<WireMessage, Ack>::new(
        [(MSG_PROTOCOL, ProtocolSupport::Full)],
        request_response::Config::default(),
    );

    let mut gossip_beh = gossip::build_gossip_behaviour(signing_keypair)?;
    subscribe_default_topics(&mut gossip_beh)?;

    // AutoNAT for NAT status detection.
    let autonat_config = nat::build_autonat_config(config.autonat_confidence_max);
    let autonat = autonat::Behaviour::new(local_peer_id, autonat_config);

    // DCUtR for hole punching.
    let dcutr = dcutr::Behaviour::new(local_peer_id);

    // Optional relay server.
    let relay_server = Toggle::from(
        relay_mod::build_relay_server_behaviour(
            local_peer_id,
            config.enable_relay_server,
        ),
    );

    Ok(BitevachatBehaviour {
        discovery,
        messaging,
        gossip: gossip_beh,
        autonat,
        relay_client,
        dcutr,
        relay_server,
    })
}