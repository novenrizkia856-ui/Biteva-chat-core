//! High-level swarm wrapper for the Bitevachat network.
//!
//! [`BitevachatSwarm`] encapsulates the libp2p `Swarm` with the
//! Bitevachat-specific [`DiscoveryBehaviour`] and provides an async
//! event loop for connection management and DHT operations.

use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, kad, noise, tcp, yamux, Multiaddr, PeerId, Swarm};

use bitevachat_crypto::signing::Keypair;
use bitevachat_types::{Address, BitevachatError, Result};

use crate::config::NetworkConfig;
use crate::discovery::{
    build_discovery_behaviour, parse_peer_id_from_record, DiscoveryBehaviour,
    DiscoveryBehaviourEvent,
};
use crate::identity::wallet_keypair_to_libp2p;
use crate::transport;

// ---------------------------------------------------------------------------
// BitevachatSwarm
// ---------------------------------------------------------------------------

/// High-level wrapper around the libp2p `Swarm<DiscoveryBehaviour>`.
///
/// Provides a safe async API for starting, connecting, and running
/// the Bitevachat peer-to-peer network layer.
pub struct BitevachatSwarm {
    /// The underlying libp2p swarm.
    swarm: Swarm<DiscoveryBehaviour>,
}

impl BitevachatSwarm {
    /// Creates a new swarm from a wallet keypair and network config.
    ///
    /// # Flow
    ///
    /// 1. Convert the wallet keypair to a libp2p identity.
    /// 2. Build TCP + QUIC transport via `SwarmBuilder`.
    /// 3. Construct the `DiscoveryBehaviour` (Kademlia + Identify).
    /// 4. Apply connection limits and idle timeout.
    /// 5. Return the ready-to-use swarm.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if:
    /// - The wallet keypair cannot be converted to libp2p identity.
    /// - The transport or behaviour construction fails.
    /// - The config validation fails.
    pub async fn new(
        config: NetworkConfig,
        wallet_keypair: &Keypair,
    ) -> Result<Self> {
        config.validate()?;

        // 1. Convert wallet identity → libp2p identity
        let libp2p_keypair = wallet_keypair_to_libp2p(wallet_keypair)?;

        // 2–3. Build transport + behaviour via SwarmBuilder
        let config_clone = config.clone();
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
                build_discovery_behaviour(key, &config_clone).map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                })
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

        Ok(Self { swarm })
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
    pub fn start_listening(&mut self, addr: Multiaddr) -> Result<()> {
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

    // -----------------------------------------------------------------------
    // Dialing
    // -----------------------------------------------------------------------

    /// Dials a remote peer at the given multiaddr.
    ///
    /// The multiaddr should include a `/p2p/<peer_id>` component for
    /// identity verification.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if the dial cannot be
    /// initiated.
    pub fn dial_peer(&mut self, addr: Multiaddr) -> Result<()> {
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
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if the DHT put cannot
    /// be initiated.
    pub fn publish_address(
        &mut self,
        address: &Address,
        peer_id: &PeerId,
    ) -> Result<kad::QueryId> {
        self.swarm
            .behaviour_mut()
            .publish_address(address, peer_id)
    }

    /// Starts a DHT lookup for the PeerId associated with an address.
    ///
    /// Results are delivered asynchronously through the event loop.
    pub fn find_peer(&mut self, address: &Address) -> kad::QueryId {
        self.swarm.behaviour_mut().find_peer(address)
    }

    /// Adds bootstrap nodes and initiates a Kademlia bootstrap.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::NetworkError` if no valid bootstrap
    /// nodes were provided or bootstrap cannot start.
    pub fn bootstrap(&mut self, nodes: &[Multiaddr]) -> Result<()> {
        self.swarm
            .behaviour_mut()
            .add_bootstrap_nodes(nodes)?;

        if !nodes.is_empty() {
            self.swarm
                .behaviour_mut()
                .bootstrap()?;
        }

        Ok(())
    }

    /// Sets the Kademlia mode (Client or Server).
    pub fn set_kademlia_mode(&mut self, mode: kad::Mode) {
        self.swarm.behaviour_mut().set_mode(mode);
    }

    // -----------------------------------------------------------------------
    // Event loop
    // -----------------------------------------------------------------------

    /// Runs the swarm event loop, processing all network events.
    ///
    /// This is a skeleton implementation that logs events via `tracing`.
    /// Full protocol handling (message routing, acknowledgements) will
    /// be added in later stages.
    ///
    /// # Cancellation
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
                    tracing::info!(
                        %address,
                        ?listener_id,
                        "new listen address"
                    );
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
                }

                SwarmEvent::ConnectionClosed {
                    peer_id,
                    cause,
                    num_established,
                    ..
                } => {
                    tracing::info!(
                        %peer_id,
                        ?cause,
                        num_established,
                        "connection closed"
                    );
                }

                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    tracing::warn!(
                        ?peer_id,
                        %error,
                        "outgoing connection error"
                    );
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
                    handle_behaviour_event(event);
                }

                // --- Catch-all for other swarm events ---------------------
                other => {
                    tracing::trace!(?other, "unhandled swarm event");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Event handlers (skeleton — logging only)
// ---------------------------------------------------------------------------

fn handle_behaviour_event(event: DiscoveryBehaviourEvent) {
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
            ))) => {
                match parse_peer_id_from_record(&record.value) {
                    Ok(peer_id) => {
                        tracing::info!(
                            ?id,
                            %peer_id,
                            "DHT get_record succeeded: found peer"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            ?id,
                            %e,
                            "DHT get_record returned unparseable value"
                        );
                    }
                }
            }
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
                    ?id,
                    %peer,
                    num_remaining,
                    "Kademlia bootstrap progress"
                );
            }
            kad::QueryResult::Bootstrap(Err(e)) => {
                tracing::warn!(?id, ?e, "Kademlia bootstrap failed");
            }
            kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                tracing::debug!(
                    ?id,
                    peers = ?ok.peers,
                    "get_closest_peers result"
                );
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