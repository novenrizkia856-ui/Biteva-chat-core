//! High-level swarm wrapper for the Bitevachat network.
//!
//! [`BitevachatSwarm`] encapsulates the libp2p `Swarm` with the
//! combined [`BitevachatBehaviour`] and provides an async event loop
//! for message routing, gossip, DHT discovery, **relay-based NAT
//! traversal**, and **application-level message forwarding**.
//!
//! # Relay architecture
//!
//! ```text
//! Client A (NAT)            VPS (relay server)         Client B (NAT)
//!   relay_client  ---------> relay::Behaviour <--------- relay_client
//!   listen /p2p-circuit      accept circuits             listen /p2p-circuit
//!   autonat                  autonat                     autonat
//!   dcutr (hole punch)       dcutr                       dcutr (hole punch)
//! ```
//!
//! # Application-level forwarding
//!
//! Public/VPS nodes act as store-and-forward relays. When a message
//! arrives whose `recipient` does not match this node's own address,
//! the VPS validates the signature (anti-spam) and forwards the
//! original [`WireMessage`] to the actual recipient, preserving the
//! sender's public key so the final recipient can verify authenticity.
//!
//! # Store-and-forward mailbox
//!
//! When the recipient is not currently connected, the message is
//! stored in an in-memory [`Mailbox`]. When the recipient later
//! connects and completes the Identify handshake, all pending
//! messages are flushed automatically.
//!
//! Private/NAT-ed nodes that cannot reach the recipient directly
//! will send the message to a connected relay/public node, which
//! then either forwards immediately or stores in the mailbox.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::autonat;
use libp2p::dcutr;
use libp2p::gossipsub;
use libp2p::mdns;
use libp2p::relay;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
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
use crate::handler::MessageHandler;
use crate::identity::wallet_keypair_to_libp2p;
use crate::mailbox::{Mailbox, MailboxStats};
use crate::nat::NatManager;
use crate::protocol::{Ack, WireMessage, MSG_PROTOCOL};
use crate::relay as relay_helpers;
use crate::routing::{build_wire_message, DeliveryStatus, Router};
use crate::transport;

/// Convenience alias to avoid shadowing `std::result::Result`
/// which the `#[derive(NetworkBehaviour)]` macro requires.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Combined behaviour
// ---------------------------------------------------------------------------

/// Combined libp2p behaviour for Bitevachat.
#[derive(NetworkBehaviour)]
pub struct BitevachatBehaviour {
    pub discovery: DiscoveryBehaviour,
    pub messaging: libp2p_request_response::cbor::Behaviour<WireMessage, Ack>,
    pub gossip: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: Toggle<relay::Behaviour>,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

// ---------------------------------------------------------------------------
// BitevachatSwarm
// ---------------------------------------------------------------------------

pub struct BitevachatSwarm {
    swarm: Swarm<BitevachatBehaviour>,
    handler: MessageHandler,
    router: Router,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    address_book: HashMap<[u8; 32], PeerId>,
    local_sender_pubkey: [u8; 32],
    local_address: Address,
    relay_nodes: Vec<(PeerId, Multiaddr)>,
    nat_manager: NatManager,
    relay_reservations_active: bool,
    /// Store-and-forward mailbox for messages to offline recipients.
    mailbox: Mailbox,
}

impl BitevachatSwarm {
    pub async fn new(
        config: NetworkConfig,
        wallet_keypair: &Keypair,
    ) -> BResult<(Self, mpsc::UnboundedReceiver<NetworkEvent>)> {
        config.validate()?;

        let libp2p_keypair = wallet_keypair_to_libp2p(wallet_keypair)?;
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let nonce_cache = Arc::new(Mutex::new(NonceCache::new(10_000)));

        // Build handler with default asymmetric timestamp tolerances.
        let handler = MessageHandler::new(
            Arc::clone(&nonce_cache),
            event_tx.clone(),
        );
        let router = Router::new();

        // CRITICAL: `.with_relay_client()` MUST be called so the
        // transport layer can create relay circuits.
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
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to configure relay client transport: {e}"),
            })?
            .with_behaviour(|key, relay_client| {
                build_combined_behaviour(key, &config_clone, &signing_keypair, relay_client)
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

        let local_pubkey_bytes = *wallet_keypair.public_key().as_bytes();
        let local_pk = PublicKey::from_bytes(local_pubkey_bytes);
        let local_address = pubkey_to_address(&local_pk);

        // Build mailbox with config limits.
        let mailbox = Mailbox::with_limits(
            config.mailbox_max_per_recipient,
            config.mailbox_max_total,
            config.mailbox_ttl_secs,
        );

        tracing::info!(%local_address, "swarm initialized with local address");

        let me = Self {
            swarm,
            handler,
            router,
            event_sender: event_tx,
            address_book: HashMap::new(),
            local_sender_pubkey: local_pubkey_bytes,
            local_address,
            relay_nodes: Vec::new(),
            nat_manager: NatManager::new(),
            relay_reservations_active: false,
            mailbox,
        };

        Ok((me, event_rx))
    }

    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    pub fn local_address(&self) -> &Address {
        &self.local_address
    }

    // -----------------------------------------------------------------------
    // Listening
    // -----------------------------------------------------------------------

    pub fn start_listening(&mut self, addr: Multiaddr) -> BResult<()> {
        self.swarm
            .listen_on(addr)
            .map_err(|e| BitevachatError::NetworkError {
                reason: format!("failed to start listening: {e}"),
            })?;
        Ok(())
    }

    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    // -----------------------------------------------------------------------
    // Relay operations
    // -----------------------------------------------------------------------

    pub fn register_relay_nodes(&mut self, nodes: &[Multiaddr]) {
        let local = *self.swarm.local_peer_id();

        for addr in nodes {
            if let Some((peer_id, clean_addr)) = extract_peer_id_and_addr(addr) {
                // Never register ourselves as a relay node.
                if peer_id == local {
                    tracing::debug!(
                        %peer_id,
                        "skipping self-registration as relay node"
                    );
                    continue;
                }

                if !self.relay_nodes.iter().any(|(p, _)| p == &peer_id) {
                    self.relay_nodes.push((peer_id, clean_addr.clone()));
                    tracing::info!(
                        %peer_id,
                        addr = %clean_addr,
                        "registered relay node"
                    );
                }
            }
        }
    }

    pub fn listen_on_relays(&mut self) -> BResult<()> {
        if self.relay_nodes.is_empty() {
            tracing::debug!("no relay nodes registered, skipping relay listen");
            return Ok(());
        }

        let local = *self.swarm.local_peer_id();
        let nodes = self.relay_nodes.clone();
        for (peer_id, addr) in &nodes {
            // Never listen on our own relay circuit.
            if *peer_id == local {
                continue;
            }
            let circuit_listen =
                relay_helpers::build_relay_listen_addr(addr, peer_id)?;

            match self.swarm.listen_on(circuit_listen.clone()) {
                Ok(listener_id) => {
                    tracing::info!(
                        %peer_id,
                        addr = %circuit_listen,
                        ?listener_id,
                        "listening on relay circuit"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        %peer_id,
                        %e,
                        "failed to listen on relay circuit (will retry)"
                    );
                }
            }
        }

        self.relay_reservations_active = true;
        Ok(())
    }

    pub fn relay_active(&self) -> bool {
        self.relay_reservations_active
    }

    pub fn relay_nodes(&self) -> &[(PeerId, Multiaddr)] {
        &self.relay_nodes
    }

    pub fn dial_via_relay(&mut self, target_peer_id: &PeerId) -> BResult<bool> {
        if self.relay_nodes.is_empty() {
            return Ok(false);
        }

        let nodes = self.relay_nodes.clone();
        for (relay_pid, relay_addr) in &nodes {
            if relay_pid == target_peer_id {
                continue;
            }
            if !self.swarm.is_connected(relay_pid) {
                continue;
            }

            match relay_helpers::build_relay_circuit_addr(
                relay_addr,
                relay_pid,
                target_peer_id,
            ) {
                Ok(circuit_addr) => {
                    tracing::info!(
                        %target_peer_id,
                        relay = %relay_pid,
                        addr = %circuit_addr,
                        "dialing peer via relay circuit"
                    );
                    match self.swarm.dial(circuit_addr) {
                        Ok(()) => return Ok(true),
                        Err(e) => {
                            tracing::debug!(
                                %target_peer_id,
                                relay = %relay_pid,
                                %e,
                                "relay dial failed, trying next relay"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(%e, "failed to build relay circuit addr");
                }
            }
        }

        Ok(false)
    }

    // -----------------------------------------------------------------------
    // Address book
    // -----------------------------------------------------------------------

    pub fn register_peer_address(&mut self, address: &Address, peer_id: PeerId) {
        self.address_book.insert(*address.as_bytes(), peer_id);
    }

    pub fn resolve_address(&self, address: &Address) -> Option<PeerId> {
        self.address_book.get(address.as_bytes()).copied()
    }

    pub fn sender_pubkey(&self) -> &[u8; 32] {
        &self.local_sender_pubkey
    }

    /// Attempts to deliver a message to the given recipient address.
    ///
    /// # Delivery strategy (ordered fallback)
    ///
    /// 1. **Direct** — if the recipient is in the address book AND
    ///    currently connected, send via `request_response` directly.
    ///
    /// 2. **Relay dial** — if the recipient is known but not connected,
    ///    attempt to dial through a relay circuit (async — message
    ///    retries from pending queue).
    ///
    /// 3. **Store-and-forward** — send the message to a connected
    ///    relay/public node. That node will either forward immediately
    ///    (if the recipient is connected to it) or store the message
    ///    in its mailbox for delivery when the recipient connects.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if all strategies fail
    /// (no connected relay nodes, no known peers).
    pub fn try_deliver_to_address(
        &mut self,
        recipient: &Address,
        envelope: MessageEnvelope,
        message_id: MessageId,
    ) -> BResult<()> {
        // Strategy 1: Direct delivery to the recipient.
        if let Some(peer_id) = self.resolve_address(recipient) {
            if self.swarm.is_connected(&peer_id) {
                let sender_pubkey = self.local_sender_pubkey;
                self.send_message_to_peer(peer_id, envelope, sender_pubkey, message_id)?;
                tracing::info!(
                    %message_id, %recipient, %peer_id,
                    "message dispatched to connected peer"
                );
                return Ok(());
            }

            // Strategy 2: Relay dial (async — retried from pending queue).
            match self.dial_via_relay(&peer_id) {
                Ok(true) => {
                    tracing::info!(
                        %message_id, %recipient, %peer_id,
                        "initiated relay dial -- message will retry from pending queue"
                    );
                }
                Ok(false) => {
                    tracing::debug!(
                        %message_id, %peer_id,
                        "no relay nodes available for relay dial"
                    );
                }
                Err(e) => {
                    tracing::warn!(%message_id, %e, "relay dial attempt failed");
                }
            }
        }

        // Strategy 3: Store-and-forward via a connected relay/public node.
        //
        // Send the message to a relay node we are connected to. The
        // relay will see that the message recipient differs from its
        // own address, validate the signature, and either:
        //   (a) forward immediately if the recipient is connected, or
        //   (b) store in its mailbox for later delivery.
        self.send_via_relay_forward(recipient, envelope, message_id)
    }

    /// Sends a message to a connected relay node for store-and-forward
    /// delivery to the actual recipient.
    ///
    /// The relay node receives a `WireMessage` whose `recipient` field
    /// differs from the relay's own address. The relay validates the
    /// signature and either forwards or stores in its mailbox.
    fn send_via_relay_forward(
        &mut self,
        recipient: &Address,
        envelope: MessageEnvelope,
        message_id: MessageId,
    ) -> BResult<()> {
        // Clone relay_nodes to avoid borrow conflict with send_message_to_peer.
        let relay_nodes = self.relay_nodes.clone();

        for (relay_pid, _) in &relay_nodes {
            // Don't forward to the recipient itself.
            if self.resolve_address(recipient) == Some(*relay_pid) {
                continue;
            }

            if !self.swarm.is_connected(relay_pid) {
                continue;
            }

            let sender_pubkey = self.local_sender_pubkey;
            match self.send_message_to_peer(
                *relay_pid,
                envelope,
                sender_pubkey,
                message_id,
            ) {
                Ok(()) => {
                    tracing::info!(
                        %message_id,
                        %recipient,
                        relay = %relay_pid,
                        "message sent to relay node for store-and-forward"
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!(
                        %message_id,
                        relay = %relay_pid,
                        %e,
                        "failed to send to relay, trying next"
                    );
                    // envelope was moved into send_message_to_peer which failed.
                    // We cannot try the next relay because envelope is consumed.
                    // Return the error.
                    return Err(e);
                }
            }
        }

        Err(BitevachatError::NetworkError {
            reason: format!(
                "no connected relay/public node available for store-and-forward to {}",
                recipient,
            ),
        })
    }

    // -----------------------------------------------------------------------
    // Dialing
    // -----------------------------------------------------------------------

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

    pub fn find_peer(&mut self, address: &Address) -> kad::QueryId {
        self.swarm.behaviour_mut().discovery.find_peer(address)
    }

    pub fn bootstrap(&mut self, nodes: &[Multiaddr]) -> BResult<()> {
        // Filter out our own address to prevent self-dial.
        let local = *self.swarm.local_peer_id();
        let filtered: Vec<Multiaddr> = nodes
            .iter()
            .filter(|addr| {
                extract_peer_id_and_addr(addr)
                    .map_or(true, |(pid, _)| pid != local)
            })
            .cloned()
            .collect();

        if filtered.is_empty() && !nodes.is_empty() {
            tracing::debug!(
                "all bootstrap nodes filtered out (self-references only)"
            );
            return Ok(());
        }

        self.swarm
            .behaviour_mut()
            .discovery
            .add_bootstrap_nodes(&filtered)?;

        if !filtered.is_empty() {
            self.swarm
                .behaviour_mut()
                .discovery
                .bootstrap()?;
        }

        Ok(())
    }

    pub fn set_kademlia_mode(&mut self, mode: kad::Mode) {
        self.swarm.behaviour_mut().discovery.set_mode(mode);
    }

    // -----------------------------------------------------------------------
    // Direct messaging
    // -----------------------------------------------------------------------

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
    // Application-level forwarding (with mailbox fallback)
    // -----------------------------------------------------------------------

    /// Forwards a message to its intended recipient.
    ///
    /// If the recipient is currently connected, the message is sent
    /// immediately via `request_response`. If the recipient is NOT
    /// connected, the message is stored in the [`Mailbox`] for
    /// automatic delivery when the recipient connects.
    fn forward_message(&mut self, wire: WireMessage, recipient: &Address) {
        let recipient_bytes = *recipient.as_bytes();
        let msg_id = wire.envelope.message.message_id;

        // Try direct forward first.
        if let Some(peer_id) = self.resolve_address(recipient) {
            if self.swarm.is_connected(&peer_id) {
                let _request_id = self
                    .swarm
                    .behaviour_mut()
                    .messaging
                    .send_request(&peer_id, wire);

                tracing::info!(
                    %msg_id,
                    recipient = %recipient,
                    %peer_id,
                    "forwarded message to connected recipient"
                );
                return;
            }
        }

        // Recipient not connected — store in mailbox.
        let stored = self.mailbox.store(&recipient_bytes, wire);
        if stored {
            let pending = self.mailbox.pending_count_for(&recipient_bytes);
            tracing::info!(
                %msg_id,
                recipient = %recipient,
                pending_in_mailbox = pending,
                "recipient offline -- message stored in mailbox for later delivery"
            );
        } else {
            tracing::warn!(
                %msg_id,
                recipient = %recipient,
                "recipient offline -- mailbox full, message dropped \
                 (sender's pending queue will retry)"
            );
        }
    }

    /// Flushes all mailbox messages for a recipient that just connected.
    ///
    /// Called after the Identify handshake resolves the peer's
    /// Bitevachat address. Messages are sent in FIFO order.
    fn flush_mailbox_for_peer(&mut self, address: &Address, peer_id: &PeerId) {
        let address_bytes = *address.as_bytes();
        let pending = self.mailbox.pending_count_for(&address_bytes);

        if pending == 0 {
            return;
        }

        tracing::info!(
            %address,
            %peer_id,
            pending,
            "flushing mailbox for newly-connected peer"
        );

        let messages = self.mailbox.drain(&address_bytes);
        let mut delivered = 0usize;
        let mut failed = 0usize;

        for wire in messages {
            let msg_id = wire.envelope.message.message_id;

            if !self.swarm.is_connected(peer_id) {
                // Peer disconnected mid-flush. Re-store remaining
                // messages would require re-collecting into a vec,
                // which adds complexity. The sender's pending queue
                // will handle retries.
                tracing::warn!(
                    %address, %peer_id,
                    "peer disconnected during mailbox flush -- \
                     remaining messages will be retried by senders"
                );
                failed = failed.saturating_add(1);
                break;
            }

            let _request_id = self
                .swarm
                .behaviour_mut()
                .messaging
                .send_request(peer_id, wire);

            delivered = delivered.saturating_add(1);

            tracing::debug!(
                %msg_id,
                %address,
                "mailbox: delivered stored message to peer"
            );
        }

        tracing::info!(
            %address,
            delivered,
            failed,
            "mailbox flush completed"
        );
    }

    // -----------------------------------------------------------------------
    // Mailbox management (public API for maintenance)
    // -----------------------------------------------------------------------

    /// Purges expired messages from the mailbox.
    ///
    /// Call this from the maintenance tick to reclaim memory.
    /// Returns the number of purged entries.
    pub fn purge_mailbox(&mut self) -> usize {
        self.mailbox.purge_expired()
    }

    /// Returns mailbox statistics for monitoring.
    pub fn mailbox_stats(&self) -> MailboxStats {
        self.mailbox.stats()
    }

    // -----------------------------------------------------------------------
    // Gossip
    // -----------------------------------------------------------------------

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

    pub async fn poll_next(&mut self) {
        match self.swarm.select_next_some().await {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                let addr_str = address.to_string();
                if addr_str.contains("p2p-circuit") {
                    tracing::info!(
                        %address, ?listener_id,
                        "*** relay circuit listener active -- node reachable via relay ***"
                    );
                } else {
                    tracing::info!(%address, ?listener_id, "new listen address");
                }
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let addr_str = endpoint.get_remote_address().to_string();
                if addr_str.contains("p2p-circuit") {
                    tracing::info!(
                        %peer_id, remote_addr = %addr_str,
                        "*** RELAYED connection established ***"
                    );
                } else {
                    tracing::info!(
                        %peer_id, ?endpoint, num_established,
                        "connection established"
                    );
                }
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
                    %local_addr, %send_back_addr, %error,
                    "incoming connection error"
                );
            }

            SwarmEvent::ExternalAddrConfirmed { address } => {
                tracing::info!(%address, "external address confirmed");
            }

            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }

            other => {
                tracing::trace!(?other, "unhandled swarm event");
            }
        }
    }

    pub async fn run(&mut self) {
        loop {
            self.poll_next().await;
        }
    }

    // -----------------------------------------------------------------------
    // Internal event dispatch
    // -----------------------------------------------------------------------

    async fn handle_behaviour_event(&mut self, event: BitevachatBehaviourEvent) {
        match event {
            BitevachatBehaviourEvent::Discovery(disc) => {
                let resolved = handle_discovery_event(
                    disc,
                    &mut self.address_book,
                    &self.event_sender,
                );

                // When a peer's address is resolved via Identify,
                // flush any mailbox messages waiting for that peer.
                if let Some((address, peer_id)) = resolved {
                    self.flush_mailbox_for_peer(&address, &peer_id);
                }
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
            BitevachatBehaviourEvent::RelayClient(event) => {
                self.handle_relay_client_event(event);
            }
            BitevachatBehaviourEvent::RelayServer(event) => {
                relay_helpers::log_relay_server_event(&event);
            }
            BitevachatBehaviourEvent::Autonat(event) => {
                if let Some(new_status) = self.nat_manager.on_autonat_event(event) {
                    let _ = self.event_sender.send(
                        NetworkEvent::NatStatusChanged(new_status),
                    );
                }
            }
            BitevachatBehaviourEvent::Dcutr(event) => {
                self.handle_dcutr_event(event);
            }
        }
    }

    fn handle_relay_client_event(&mut self, event: relay::client::Event) {
        relay_helpers::log_relay_client_event(&event);

        match event {
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id, renewal, ..
            } => {
                self.relay_reservations_active = true;
                tracing::info!(
                    %relay_peer_id, renewal,
                    "relay reservation ACTIVE -- node reachable via this relay"
                );
            }
            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                tracing::info!(
                    %src_peer_id,
                    "inbound relay circuit from peer"
                );
            }
            _ => {}
        }
    }

    fn handle_dcutr_event(&mut self, event: dcutr::Event) {
        // dcutr::Event variant names differ across libp2p versions.
        // Use Debug formatting for safe, version-agnostic logging.
        tracing::info!(?event, "DCUtR event received");
    }

    fn handle_mdns_event(&mut self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    tracing::info!(%peer_id, %addr, "mDNS: discovered peer");
                    self.swarm
                        .behaviour_mut()
                        .discovery
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    if let Err(e) = self.swarm.dial(addr) {
                        tracing::debug!(%peer_id, %e, "mDNS: dial failed");
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

    async fn handle_messaging_event(
        &mut self,
        event: request_response::Event<WireMessage, Ack>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
            } => {
                let wire: WireMessage = request;
                let sender_bytes = *wire.envelope.message.sender.as_bytes();
                self.address_book.insert(sender_bytes, peer);

                let msg_recipient = &wire.envelope.message.recipient;
                let is_for_us = msg_recipient.as_bytes() == self.local_address.as_bytes();

                if is_for_us {
                    let result = self
                        .handler
                        .on_message_received(peer, wire.envelope, &wire.sender_pubkey)
                        .await;

                    if self
                        .swarm
                        .behaviour_mut()
                        .messaging
                        .send_response(channel, result.ack.clone())
                        .is_err()
                    {
                        tracing::warn!(%peer, "failed to send ACK (channel closed)");
                    }
                } else {
                    let recipient = msg_recipient.clone();

                    tracing::info!(
                        sender = %wire.envelope.message.sender,
                        %recipient,
                        "inbound message not for us -- attempting forward/mailbox"
                    );

                    match self.handler.validate_signature_only(&wire.envelope, &wire.sender_pubkey) {
                        Ok(()) => {
                            if self
                                .swarm
                                .behaviour_mut()
                                .messaging
                                .send_response(channel, Ack::Ok)
                                .is_err()
                            {
                                tracing::warn!(%peer, "failed to send relay ACK");
                            }

                            // forward_message now stores to mailbox if
                            // the recipient is not connected.
                            self.forward_message(wire, &recipient);
                        }
                        Err(ack) => {
                            tracing::warn!(
                                %peer,
                                "relay: rejecting message with invalid signature"
                            );
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .messaging
                                .send_response(channel, ack);
                        }
                    }
                }
            }

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
                            tracing::warn!(?msg_id, %peer, ?response, "message rejected");
                            let _ = self
                                .event_sender
                                .send(NetworkEvent::DeliveryFailed(msg_id));
                        }
                        DeliveryStatus::Queued => {
                            tracing::debug!(?msg_id, "unexpected Queued status on ACK");
                        }
                    }
                }
            }

            request_response::Event::OutboundFailure {
                peer, request_id, error,
            } => {
                tracing::warn!(%peer, ?error, "outbound message delivery failed");
                if let Some(pending) = self.router.on_send_failed(&request_id) {
                    let _ = self
                        .event_sender
                        .send(NetworkEvent::DeliveryFailed(pending.message_id));
                }
            }

            request_response::Event::InboundFailure {
                peer, error, ..
            } => {
                tracing::warn!(%peer, ?error, "inbound message handling failed");
            }

            request_response::Event::ResponseSent { peer, .. } => {
                tracing::trace!(%peer, "ACK response sent");
            }
        }
    }

    fn handle_gossip_event(&self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source, message, ..
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
// Discovery event handlers
// ---------------------------------------------------------------------------

/// Handles a discovery event and returns the resolved address+peer
/// if an Identify handshake completed.
fn handle_discovery_event(
    event: DiscoveryBehaviourEvent,
    address_book: &mut HashMap<[u8; 32], PeerId>,
    event_sender: &mpsc::UnboundedSender<NetworkEvent>,
) -> Option<(Address, PeerId)> {
    match event {
        DiscoveryBehaviourEvent::Kademlia(kad_event) => {
            handle_kademlia_event(kad_event);
            None
        }
        DiscoveryBehaviourEvent::Identify(id_event) => {
            handle_identify_event(id_event, address_book, event_sender)
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
                peer, num_remaining,
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

/// Handles an Identify event.
///
/// Returns `Some((address, peer_id))` when a peer's Bitevachat
/// address was resolved, `None` otherwise. The caller uses this
/// to flush the mailbox for the newly-resolved address.
fn handle_identify_event(
    event: identify::Event,
    address_book: &mut HashMap<[u8; 32], PeerId>,
    event_sender: &mpsc::UnboundedSender<NetworkEvent>,
) -> Option<(Address, PeerId)> {
    match event {
        identify::Event::Received { peer_id, info, .. } => {
            tracing::info!(
                %peer_id,
                protocol_version = %info.protocol_version,
                agent_version = %info.agent_version,
                listen_addrs = ?info.listen_addrs,
                "identify: received peer info"
            );

            if let Ok(ed_pk) = info.public_key.try_into_ed25519() {
                let raw_bytes = ed_pk.to_bytes();
                let bpk = PublicKey::from_bytes(raw_bytes);
                let address = pubkey_to_address(&bpk);
                address_book.insert(*address.as_bytes(), peer_id);
                tracing::info!(
                    %peer_id, %address,
                    "identify: mapped peer address in address book"
                );

                let _ = event_sender.send(NetworkEvent::PeerAddressResolved {
                    address,
                    peer_id,
                });

                return Some((address, peer_id));
            }

            None
        }
        identify::Event::Sent { peer_id, .. } => {
            tracing::debug!(%peer_id, "identify: sent our info to peer");
            None
        }
        identify::Event::Pushed { peer_id, info, .. } => {
            tracing::debug!(
                %peer_id,
                agent_version = %info.agent_version,
                "identify: pushed info update to peer"
            );
            None
        }
        identify::Event::Error { peer_id, error, .. } => {
            tracing::warn!(%peer_id, %error, "identify: error");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn extract_peer_id_and_addr(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut clean_addr = Multiaddr::empty();
    let mut peer_id = None;

    for proto in addr.iter() {
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

// ---------------------------------------------------------------------------
// Behaviour construction
// ---------------------------------------------------------------------------

fn build_combined_behaviour(
    key: &libp2p::identity::Keypair,
    config: &NetworkConfig,
    signing_keypair: &libp2p::identity::Keypair,
    relay_client: relay::client::Behaviour,
) -> BResult<BitevachatBehaviour> {
    let discovery = build_discovery_behaviour(key, config)?;

    let messaging = libp2p_request_response::cbor::Behaviour::<WireMessage, Ack>::new(
        [(MSG_PROTOCOL, ProtocolSupport::Full)],
        request_response::Config::default(),
    );

    let mut gossip_beh = gossip::build_gossip_behaviour(signing_keypair)?;
    subscribe_default_topics(&mut gossip_beh)?;

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

    let relay_server = if config.enable_relay_server {
        tracing::info!("relay SERVER enabled -- this node will relay for others");
        Toggle::from(Some(relay::Behaviour::new(
            local_peer_id,
            relay::Config::default(),
        )))
    } else {
        tracing::debug!("relay server disabled (client only)");
        Toggle::from(None)
    };

    let autonat_config = crate::nat::build_autonat_config(3);
    let autonat_beh = autonat::Behaviour::new(local_peer_id, autonat_config);
    let dcutr_beh = dcutr::Behaviour::new(local_peer_id);

    Ok(BitevachatBehaviour {
        discovery,
        messaging,
        gossip: gossip_beh,
        mdns: mdns_beh,
        relay_client,
        relay_server,
        autonat: autonat_beh,
        dcutr: dcutr_beh,
    })
}