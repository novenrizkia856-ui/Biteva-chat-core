//! Main event loop driving all node subsystems.
//!
//! [`run_event_loop`] is spawned as a tokio task by [`Node::start`].
//! It uses `tokio::select!` to multiplex:
//!
//! 1. **Network swarm** — `poll_next()` drives libp2p event processing.
//! 2. **Network events** — `MessageReceived`, `DeliveryAck`, etc.
//! 3. **Commands** — `SendMessage`, `GetStatus`, `Shutdown` from RPC.
//! 4. **Pending tick** — periodic retry of undelivered messages.
//! 5. **Maintenance tick** — storage flush, DHT refresh.
//! 6. **Shutdown signal** — graceful exit via `watch` channel.
//!
//! All branches are non-blocking. No busy loops. No uncontrolled
//! task spawning.

use std::time::Duration;

use bitevachat_network::events::NetworkEvent;
use bitevachat_network::gossip::TOPIC_PROFILE_UPDATES;
use bitevachat_types::{BitevachatError, MessageId, NodeEvent, NodeId, Timestamp};

use crate::command::{ContactInfo, MessageInfo, NodeCommand, NodeStatus, PeerInfo};
use crate::incoming;
use crate::maintenance;
use crate::node::{NodeRuntime, NodeState};
use crate::outgoing;

// ---------------------------------------------------------------------------
// Helper: PeerId -> NodeId
// ---------------------------------------------------------------------------

/// Converts a libp2p `PeerId` to a Bitevachat `NodeId`.
///
/// `PeerId` is a variable-length multihash; `NodeId` is fixed 32 bytes.
/// We hash the PeerId bytes with SHA3-256 to produce a consistent
/// 32-byte identifier.
fn peer_id_to_node_id(peer_id: &libp2p::PeerId) -> NodeId {
    let bytes = peer_id.to_bytes();
    let hash = bitevachat_crypto::hash::sha3_256(&bytes);
    NodeId::new(hash)
}

// ---------------------------------------------------------------------------
// Event loop entry point
// ---------------------------------------------------------------------------

/// Runs the node event loop until shutdown is signalled.
///
/// This function takes ownership of the [`NodeRuntime`] and runs
/// until the shutdown watch channel fires. It is designed to be
/// spawned as a tokio task via `Node::start`.
pub(crate) async fn run_event_loop(mut rt: NodeRuntime) {
    tracing::info!("node event loop started");

    let mut pending_tick = tokio::time::interval(
        Duration::from_secs(rt.pending_tick_secs),
    );
    let mut maintenance_tick = tokio::time::interval(
        Duration::from_secs(rt.maintenance_tick_secs),
    );

    // Start listening on the configured address.
    if let Err(e) = rt.network.start_listening(rt.listen_addr.clone()) {
        tracing::error!(%e, "failed to start listening -- continuing without listener");
    }

    // Bootstrap: connect to known peers so we can join the DHT.
    //
    // Without bootstrap nodes, the only discovery method is mDNS
    // (LAN only).  With bootstrap nodes, the node can discover
    // peers across the internet via the Kademlia DHT.
    if !rt.bootstrap_nodes.is_empty() {
        tracing::info!(
            count = rt.bootstrap_nodes.len(),
            "bootstrapping with known peers"
        );
        match rt.network.bootstrap(&rt.bootstrap_nodes) {
            Ok(()) => tracing::info!("Kademlia bootstrap initiated"),
            Err(e) => tracing::warn!(%e, "bootstrap failed (will retry in maintenance tick)"),
        }
    } else {
        tracing::info!("no bootstrap nodes configured — using mDNS only (LAN discovery)");
    }

    // Publish our Address→PeerId mapping to the DHT so other
    // nodes can find us.  This may fail if no peers are known yet
    // (the mDNS or bootstrap process will add them later and we
    // re-publish in the maintenance tick).
    {
        let my_address = bitevachat_crypto::signing::pubkey_to_address(
            &bitevachat_crypto::signing::PublicKey::from_bytes(*rt.wallet.public_key()),
        );
        let my_peer_id = *rt.network.local_peer_id();
        match rt.network.publish_address(&my_address, &my_peer_id) {
            Ok(_qid) => tracing::info!(%my_address, "published address to DHT"),
            Err(e) => tracing::debug!(%e, "DHT publish deferred (no peers yet)"),
        }
    }

    loop {
        tokio::select! {
            // ---------------------------------------------------------------
            // 1. Drive the network swarm (process one libp2p event).
            // ---------------------------------------------------------------
            _ = rt.network.poll_next() => {
                // Events are dispatched internally by the swarm and
                // emitted to network_rx. Nothing else to do here.
            }

            // ---------------------------------------------------------------
            // 2. Process network events emitted by the swarm.
            // ---------------------------------------------------------------
            Some(net_event) = rt.network_rx.recv() => {
                let flush_pending = matches!(
                    &net_event,
                    NetworkEvent::PeerAddressResolved { .. }
                );

                handle_network_event(
                    net_event,
                    &rt.spam_filter,
                    &rt.profile_manager,
                    &rt.storage,
                    &rt.pending_queue,
                    &rt.event_tx,
                ).await;

                if flush_pending {
                    handle_pending_tick(&mut rt);
                }
            }

            // ---------------------------------------------------------------
            // 3. Process commands from RPC / CLI.
            // ---------------------------------------------------------------
            Some(cmd) = rt.command_rx.recv() => {
                let should_shutdown = handle_command(cmd, &mut rt);
                if should_shutdown {
                    tracing::info!("shutdown command received -- exiting event loop");
                    break;
                }
            }

            // ---------------------------------------------------------------
            // 4. Pending message retry tick.
            // ---------------------------------------------------------------
            _ = pending_tick.tick() => {
                handle_pending_tick(&mut rt);
            }

            // ---------------------------------------------------------------
            // 5. Maintenance tick (flush, prune, DHT refresh).
            // ---------------------------------------------------------------
            _ = maintenance_tick.tick() => {
                handle_maintenance_tick(&rt.storage, &rt.config);

                // Re-publish our Address→PeerId in the DHT periodically.
                let my_address = bitevachat_crypto::signing::pubkey_to_address(
                    &bitevachat_crypto::signing::PublicKey::from_bytes(*rt.wallet.public_key()),
                );
                let my_peer_id = *rt.network.local_peer_id();
                let _ = rt.network.publish_address(&my_address, &my_peer_id);

                // Periodic Kademlia re-bootstrap to refresh the routing
                // table and discover new peers.
                if !rt.bootstrap_nodes.is_empty() {
                    let _ = rt.network.bootstrap(&rt.bootstrap_nodes);
                }

                // Log network health.
                let peers = rt.network.connected_peers();
                tracing::info!(
                    connected_peers = peers.len(),
                    "maintenance: network health check"
                );
            }

            // ---------------------------------------------------------------
            // 6. Shutdown signal via watch channel.
            // ---------------------------------------------------------------
            _ = rt.shutdown_rx.changed() => {
                if *rt.shutdown_rx.borrow() {
                    tracing::info!("shutdown signal received -- exiting event loop");
                    break;
                }
            }
        }
    }

    // Graceful shutdown sequence.
    shutdown_sequence(&rt.storage, &rt.pending_queue);

    tracing::info!("node event loop exited");
}

// ---------------------------------------------------------------------------
// Network event handler
// ---------------------------------------------------------------------------

/// Dispatches a network event to the appropriate handler.
async fn handle_network_event(
    event: NetworkEvent,
    spam_filter: &crate::spam_filter::SpamFilter,
    profile_manager: &crate::profile_manager::ProfileManager,
    storage: &bitevachat_storage::engine::StorageEngine,
    pending_queue: &std::sync::Arc<bitevachat_storage::pending::PendingQueue>,
    event_tx: &tokio::sync::mpsc::Sender<NodeEvent>,
) {
    match event {
        NetworkEvent::MessageReceived(envelope) => {
            let result = incoming::handle_incoming_message(
                &envelope,
                None, // PoW: transport metadata, not yet wired
                spam_filter,
                storage,
                event_tx,
            ).await;

            if let Err(e) = result {
                tracing::warn!(%e, "failed to process incoming message");
            }
        }

        NetworkEvent::DeliveryAck(msg_id) => {
            // Mark delivered in pending queue (ignore if not present).
            let _ = pending_queue.mark_delivered(&msg_id);

            let _ = event_tx
                .send(NodeEvent::DeliveryAcknowledged {
                    message_id: msg_id,
                })
                .await;
        }

        NetworkEvent::DeliveryFailed(msg_id) => {
            // Increment retry count in pending queue.
            let now = Timestamp::now();
            let _ = pending_queue.mark_failed(&msg_id, &now);

            tracing::debug!(%msg_id, "message delivery failed, pending queue updated");
        }

        NetworkEvent::PeerConnected(peer_id) => {
            tracing::info!(%peer_id, "peer connected");
            let node_id = peer_id_to_node_id(&peer_id);
            let _ = event_tx
                .send(NodeEvent::PeerConnected { node_id })
                .await;
        }

        NetworkEvent::PeerAddressResolved { address, peer_id } => {
            tracing::info!(
                %address,
                %peer_id,
                "peer address resolved — will flush pending messages"
            );

            match pending_queue.reset_backoff_for_recipient(&address) {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        %address,
                        count = n,
                        "reset backoff for pending messages"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(%e, %address, "failed to reset pending backoff");
                }
            }
        }

        NetworkEvent::PeerDisconnected(peer_id) => {
            tracing::info!(%peer_id, "peer disconnected");
            let node_id = peer_id_to_node_id(&peer_id);
            let _ = event_tx
                .send(NodeEvent::PeerDisconnected { node_id })
                .await;
        }

        NetworkEvent::GossipMessage { source, topic, data } => {
            handle_gossip_message(
                &source,
                &topic,
                &data,
                profile_manager,
                storage,
                event_tx,
            ).await;
        }

        NetworkEvent::NatStatusChanged(status) => {
            tracing::info!(?status, "NAT status changed");
        }

        NetworkEvent::HolePunchSucceeded(peer_id) => {
            tracing::info!(%peer_id, "hole punch succeeded -- direct connection active");
        }
    }
}

/// Handles a gossip message by dispatching based on topic.
async fn handle_gossip_message(
    source: &libp2p::PeerId,
    topic: &str,
    data: &[u8],
    profile_manager: &crate::profile_manager::ProfileManager,
    storage: &bitevachat_storage::engine::StorageEngine,
    event_tx: &tokio::sync::mpsc::Sender<NodeEvent>,
) {
    tracing::debug!(
        %source,
        topic,
        bytes = data.len(),
        "gossip message received"
    );

    if topic == TOPIC_PROFILE_UPDATES {
        handle_gossip_profile_update(data, profile_manager, storage, event_tx).await;
    }
    // Other topics (e.g. "presence") can be added here.
}

/// Processes a profile update received via gossip.
///
/// All errors are logged and swallowed — a malformed gossip message
/// must never crash the event loop.
async fn handle_gossip_profile_update(
    data: &[u8],
    profile_manager: &crate::profile_manager::ProfileManager,
    storage: &bitevachat_storage::engine::StorageEngine,
    event_tx: &tokio::sync::mpsc::Sender<NodeEvent>,
) {
    let signed = match bitevachat_protocol::profiles::deserialize_signed_profile(data) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%e, "failed to deserialize gossip profile");
            return;
        }
    };

    tracing::debug!(
        address = %signed.profile.address,
        version = signed.profile.version,
        "received profile update via gossip (pubkey lookup pending)"
    );

    // Emit event to notify consumers that a profile arrived.
    // Full verification will be added when PeerId->PublicKey
    // mapping is wired from the identify protocol.
    let _ = event_tx
        .send(NodeEvent::ProfileUpdated {
            address: signed.profile.address,
        })
        .await;
}

// ---------------------------------------------------------------------------
// Command handler
// ---------------------------------------------------------------------------

/// Processes a single node command.
///
/// Returns `true` if the event loop should exit (shutdown command).
///
/// This function is intentionally **not** async. All operations
/// are synchronous (build envelope, enqueue pending, build status).
/// Keeping it sync avoids holding `&mut NodeRuntime` across await
/// points, which would require `NodeRuntime: Sync` (violated by
/// libp2p's `Swarm` internals).
fn handle_command(
    cmd: NodeCommand,
    rt: &mut NodeRuntime,
) -> bool {
    match cmd {
        NodeCommand::SendMessage {
            recipient,
            plaintext,
            payload_type,
            shared_key,
            reply,
        } => {
            let result = handle_send_message(
                rt,
                recipient,
                &plaintext,
                payload_type,
                &shared_key,
            );
            let _ = reply.send(result);
            false
        }

        NodeCommand::ListMessages { convo_id, limit, offset, reply } => {
            let result = handle_list_messages(rt, convo_id, limit, offset);
            let _ = reply.send(result);
            false
        }

        NodeCommand::GetMessage { message_id, reply } => {
            let result = handle_get_message(&rt.storage, message_id);
            let _ = reply.send(result);
            false
        }

        NodeCommand::AddContact { address, alias, reply } => {
            let result = handle_add_contact(&rt.storage, address, &alias);
            let _ = reply.send(result);
            false
        }

        NodeCommand::BlockContact { address, reply } => {
            let result = handle_block_contact(&rt.storage, address, true);
            let _ = reply.send(result);
            false
        }

        NodeCommand::UnblockContact { address, reply } => {
            let result = handle_block_contact(&rt.storage, address, false);
            let _ = reply.send(result);
            false
        }

        NodeCommand::ListContacts { reply } => {
            let result = handle_list_contacts(&rt.storage);
            let _ = reply.send(result);
            false
        }

        NodeCommand::GetStatus { reply } => {
            let status = build_status(rt);
            let _ = reply.send(status);
            false
        }

        NodeCommand::ListPeers { reply } => {
            let result = handle_list_peers(rt);
            let _ = reply.send(result);
            false
        }

        NodeCommand::InjectMessage { envelope, reply } => {
            let result = handle_inject_message(&rt.storage, &envelope);
            let _ = reply.send(result);
            false
        }

        NodeCommand::UpdateProfile { name, bio, avatar_bytes, reply } => {
            let kp = match rt.wallet.get_keypair() {
                Ok(k) => k,
                Err(e) => {
                    let _ = reply.send(Err(e));
                    return false;
                }
            };
            let result = rt.profile_manager.update_profile(
                kp,
                name,
                bio,
                avatar_bytes.as_deref(),
                &rt.storage,
            );
            // Map Result<Vec<u8>> to Result<(String, u64)>:
            // On success we return (avatar_cid_hex, new_version).
            let mapped = result.map(|_cbor_bytes| {
                // Re-read the just-updated profile to get cid + version.
                let address = bitevachat_crypto::signing::pubkey_to_address(
                    &bitevachat_crypto::signing::PublicKey::from_bytes(
                        *rt.wallet.public_key(),
                    ),
                );
                let (cid_str, version) = rt.profile_manager
                    .get_profile(&address)
                    .map(|signed| {
                        let cid = signed.profile.avatar_cid
                            .map(|c| c.to_string())
                            .unwrap_or_default();
                        (cid, signed.profile.version)
                    })
                    .unwrap_or_else(|| (String::new(), 1));
                (cid_str, version)
            });
            let _ = reply.send(mapped);
            false
        }

        NodeCommand::GetProfile { address, reply } => {
            let result = rt.profile_manager.get_profile_with_fallback(
                &address,
                &rt.storage,
            );
            let _ = reply.send(result);
            false
        }

        NodeCommand::DialPeer { addr, reply } => {
            tracing::info!(%addr, "manual peer dial requested");
            let result = rt.network.dial_peer(addr);
            let _ = reply.send(result);
            false
        }

        NodeCommand::AddBootstrapNode { addr, reply } => {
            tracing::info!(%addr, "adding bootstrap node");
            let result = rt.network.bootstrap(&[addr]);
            let _ = reply.send(result);
            false
        }

        NodeCommand::Shutdown => true,
    }
}

/// Handles the SendMessage command: build envelope → store locally → enqueue pending.
fn handle_send_message(
    rt: &mut NodeRuntime,
    recipient: bitevachat_types::Address,
    plaintext: &[u8],
    payload_type: bitevachat_types::PayloadType,
    shared_key: &[u8; 32],
) -> std::result::Result<MessageId, BitevachatError> {
    let (envelope, message_id) = outgoing::build_outgoing_envelope(
        &rt.wallet,
        recipient,
        plaintext,
        payload_type,
        shared_key,
        rt.node_id,
    )?;

    // --- 1. Store outgoing message in the local message database --------
    let sender_addr = bitevachat_crypto::signing::pubkey_to_address(
        &bitevachat_crypto::signing::PublicKey::from_bytes(*rt.wallet.public_key()),
    );
    let convo_id = incoming::compute_convo_id(&sender_addr, &recipient);

    let type_byte = match payload_type {
        bitevachat_types::PayloadType::Text => 0u8,
        bitevachat_types::PayloadType::File => 1u8,
        bitevachat_types::PayloadType::System => 2u8,
    };

    let stored = bitevachat_storage::messages::StoredMessage {
        sender: *sender_addr.as_bytes(),
        recipient: *recipient.as_bytes(),
        message_id: *message_id.as_bytes(),
        convo_id: *convo_id.as_bytes(),
        timestamp_millis: envelope.message.timestamp.as_datetime().timestamp_millis(),
        payload_type: type_byte,
        // Store PLAINTEXT for local display; encryption is for the wire only.
        payload_ciphertext: plaintext.to_vec(),
        nonce: *envelope.message.nonce.as_bytes(),
        signature: envelope.signature.as_bytes().to_vec(),
    };

    if let Err(e) = rt.storage.messages().and_then(|ms| ms.store_message(&stored)) {
        tracing::warn!(%e, %message_id, "failed to store outgoing message locally");
        // Continue — delivery is more important than local persistence.
    } else {
        tracing::debug!(%message_id, "outgoing message stored locally");
    }

    // --- 2. Enqueue for pending delivery --------------------------------
    let pending_entry = bitevachat_storage::pending::PendingEntry {
        envelope: envelope.clone(),
        retry_count: 0,
        last_attempt: None,
        created_at: Timestamp::now(),
        recipient,
    };

    rt.pending_queue.enqueue(pending_entry).map_err(|e| {
        tracing::warn!(%e, "failed to enqueue message for pending delivery");
        e
    })?;

    tracing::info!(
        %message_id,
        "message stored and enqueued for delivery"
    );

    // --- 3. Attempt direct delivery if peer is known + connected -------
    match rt.network.try_deliver_to_address(
        &recipient,
        envelope,
        message_id,
    ) {
        Ok(()) => {
            tracing::info!(%message_id, %recipient, "direct delivery dispatched");
        }
        Err(e) => {
            // Not fatal: message is in the pending queue and will be
            // retried on the next tick once the peer is discovered.
            tracing::debug!(
                %message_id,
                %recipient,
                %e,
                "direct delivery not possible, will retry from pending queue"
            );
        }
    }

    Ok(message_id)
}

/// Builds a status snapshot of the node.
fn build_status(rt: &NodeRuntime) -> NodeStatus {
    let pending_count = rt
        .pending_queue
        .total_count()
        .unwrap_or(0);

    let listeners: Vec<String> = rt
        .network
        .listeners()
        .iter()
        .map(|a| a.to_string())
        .collect();

    let address = bitevachat_crypto::signing::pubkey_to_address(
        &bitevachat_crypto::signing::PublicKey::from_bytes(*rt.wallet.public_key()),
    );

    NodeStatus {
        state: NodeState::Running,
        address,
        peer_id: rt.network.local_peer_id().to_string(),
        node_id: rt.node_id,
        listeners,
        pending_count,
    }
}

// ---------------------------------------------------------------------------
// Message query handlers
// ---------------------------------------------------------------------------

/// Lists messages for a conversation.
///
/// The `convo_id` from the GUI is the **peer address** (not the
/// hashed conversation ID). We recompute the real ConvoId using
/// `compute_convo_id(my_address, peer_address)` to match what
/// both `handle_send_message` and `incoming::store_envelope` use.
fn handle_list_messages(
    rt: &NodeRuntime,
    convo_id: bitevachat_types::ConvoId,
    limit: u64,
    offset: u64,
) -> std::result::Result<Vec<MessageInfo>, BitevachatError> {
    let my_address = bitevachat_crypto::signing::pubkey_to_address(
        &bitevachat_crypto::signing::PublicKey::from_bytes(*rt.wallet.public_key()),
    );

    // The GUI sends the peer address bytes wrapped as ConvoId.
    // Recompute the real SHA3 convo ID from (my_address, peer_address).
    let peer_address = bitevachat_types::Address::new(*convo_id.as_bytes());
    let real_convo_id = incoming::compute_convo_id(&my_address, &peer_address);

    let msg_store = rt.storage.messages()?;
    let stored_messages = msg_store.get_messages(
        &real_convo_id,
        limit as usize,
        offset as usize,
    )?;

    tracing::debug!(
        count = stored_messages.len(),
        limit,
        offset,
        "ListMessages: returning {} messages",
        stored_messages.len(),
    );

    let results: Vec<MessageInfo> = stored_messages
        .into_iter()
        .map(|sm| {
            let pt = match sm.payload_type {
                0 => bitevachat_types::PayloadType::Text,
                1 => bitevachat_types::PayloadType::File,
                _ => bitevachat_types::PayloadType::System,
            };

            let dt = chrono::DateTime::from_timestamp_millis(sm.timestamp_millis)
                .unwrap_or_else(|| chrono::Utc::now());
            let ts = Timestamp::from_datetime(dt);

            MessageInfo {
                message_id: MessageId::new(sm.message_id),
                sender: bitevachat_types::Address::new(sm.sender),
                recipient: bitevachat_types::Address::new(sm.recipient),
                timestamp: ts,
                payload_type: pt,
                payload_ciphertext: sm.payload_ciphertext,
            }
        })
        .collect();

    Ok(results)
}

fn handle_get_message(
    _storage: &bitevachat_storage::engine::StorageEngine,
    message_id: MessageId,
) -> std::result::Result<Option<MessageInfo>, BitevachatError> {
    // Single-message lookup is not yet supported by the current
    // MessageStore API (it uses prefix scans). Log and return None.
    tracing::debug!(%message_id, "GetMessage: single-key lookup not yet implemented");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Contact handlers
// ---------------------------------------------------------------------------

fn handle_add_contact(
    storage: &bitevachat_storage::engine::StorageEngine,
    address: bitevachat_types::Address,
    alias: &str,
) -> std::result::Result<(), BitevachatError> {
    let contact_store = storage.contacts()?;
    let alias_opt = if alias.is_empty() {
        None
    } else {
        Some(alias.to_string())
    };
    contact_store.set_alias(&address, alias_opt)?;
    tracing::info!(%address, alias, "contact added/updated");
    Ok(())
}

fn handle_block_contact(
    storage: &bitevachat_storage::engine::StorageEngine,
    address: bitevachat_types::Address,
    blocked: bool,
) -> std::result::Result<(), BitevachatError> {
    let contact_store = storage.contacts()?;
    if blocked {
        contact_store.block(&address)?;
        tracing::info!(%address, "contact blocked");
    } else {
        contact_store.unblock(&address)?;
        tracing::info!(%address, "contact unblocked");
    }
    Ok(())
}

fn handle_list_contacts(
    storage: &bitevachat_storage::engine::StorageEngine,
) -> std::result::Result<Vec<ContactInfo>, BitevachatError> {
    let contact_store = storage.contacts()?;
    let entries = contact_store.list_contacts()?;

    let results: Vec<ContactInfo> = entries
        .into_iter()
        .map(|(address, record)| ContactInfo {
            address,
            alias: record.alias.unwrap_or_default(),
            blocked: record.blocked,
        })
        .collect();

    tracing::debug!(count = results.len(), "ListContacts: returning contacts");
    Ok(results)
}

// ---------------------------------------------------------------------------
// Peer query handler
// ---------------------------------------------------------------------------

fn handle_list_peers(
    rt: &NodeRuntime,
) -> std::result::Result<Vec<PeerInfo>, BitevachatError> {
    let peers: Vec<PeerInfo> = rt
        .network
        .connected_peers()
        .into_iter()
        .map(|peer_id| {
            let node_id = peer_id_to_node_id(&peer_id);
            PeerInfo {
                peer_id: peer_id.to_string(),
                node_id,
            }
        })
        .collect();

    tracing::debug!(count = peers.len(), "ListPeers: returning connected peers");
    Ok(peers)
}

// ---------------------------------------------------------------------------
// Inject message handler
// ---------------------------------------------------------------------------

fn handle_inject_message(
    storage: &bitevachat_storage::engine::StorageEngine,
    envelope: &bitevachat_protocol::message::MessageEnvelope,
) -> std::result::Result<MessageId, BitevachatError> {
    let message_id = envelope.message.message_id;
    let sender = &envelope.message.sender;
    let recipient = &envelope.message.recipient;

    let convo_id = incoming::compute_convo_id(sender, recipient);

    let type_byte = match envelope.message.payload_type {
        bitevachat_types::PayloadType::Text => 0u8,
        bitevachat_types::PayloadType::File => 1u8,
        bitevachat_types::PayloadType::System => 2u8,
    };

    let stored = bitevachat_storage::messages::StoredMessage {
        sender: *sender.as_bytes(),
        recipient: *recipient.as_bytes(),
        message_id: *message_id.as_bytes(),
        convo_id: *convo_id.as_bytes(),
        timestamp_millis: envelope.message.timestamp.as_datetime().timestamp_millis(),
        payload_type: type_byte,
        payload_ciphertext: envelope.message.payload_ciphertext.clone(),
        nonce: *envelope.message.nonce.as_bytes(),
        signature: envelope.signature.as_bytes().to_vec(),
    };

    let msg_store = storage.messages()?;
    msg_store.store_message(&stored)?;

    tracing::info!(
        %message_id,
        %sender,
        "injected message stored"
    );

    Ok(message_id)
}

// ---------------------------------------------------------------------------
// Pending tick handler
// ---------------------------------------------------------------------------

fn handle_pending_tick(
    rt: &mut NodeRuntime,
) {
    let now = Timestamp::now();

    // 1. Purge expired entries (7 day TTL).
    if let Err(e) = rt.pending_queue.purge_expired(7, &now) {
        tracing::warn!(%e, "failed to purge expired pending entries");
    }

    // 2. Dequeue entries whose backoff has elapsed.
    let ready = match rt.pending_queue.dequeue_ready(&now) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(%e, "pending dequeue_ready failed");
            return;
        }
    };

    if ready.is_empty() {
        return;
    }

    tracing::debug!(count = ready.len(), "pending tick: retrying messages");

    // 3. Attempt delivery for each ready entry.
    for entry in &ready {
        let msg_id = *entry.message_id();

        match rt.network.try_deliver_to_address(
            &entry.recipient,
            entry.envelope.clone(),
            msg_id,
        ) {
            Ok(()) => {
                // Delivery dispatched — the ACK handler
                // (NetworkEvent::DeliveryAck) will call
                // pending_queue.mark_delivered() when the
                // recipient acknowledges receipt.
                tracing::debug!(
                    %msg_id,
                    recipient = %entry.recipient,
                    "pending retry: dispatched to connected peer"
                );
            }
            Err(e) => {
                // Peer not known or not connected — bump retry count
                // so exponential backoff kicks in.
                let fail_now = Timestamp::now();
                let _ = rt.pending_queue.mark_failed(&msg_id, &fail_now);
                tracing::debug!(
                    %msg_id,
                    %e,
                    retry = entry.retry_count + 1,
                    "pending retry: delivery failed, will backoff"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Maintenance tick handler
// ---------------------------------------------------------------------------

fn handle_maintenance_tick(
    storage: &bitevachat_storage::engine::StorageEngine,
    config: &bitevachat_types::config::AppConfig,
) {
    let report = maintenance::run_storage_maintenance(storage, config);

    match report {
        Ok(r) => {
            tracing::debug!(
                flushed = r.flushed,
                dht_refresh = r.dht_refresh_needed,
                "maintenance tick completed"
            );
        }
        Err(e) => {
            tracing::warn!(%e, "maintenance tick failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Shutdown sequence
// ---------------------------------------------------------------------------

/// Performs graceful shutdown: flush storage, log final state.
fn shutdown_sequence(
    storage: &bitevachat_storage::engine::StorageEngine,
    pending_queue: &std::sync::Arc<bitevachat_storage::pending::PendingQueue>,
) {
    tracing::info!("running shutdown sequence");

    // Flush storage.
    if let Err(e) = storage.flush() {
        tracing::error!(%e, "failed to flush storage during shutdown");
    }

    let pending = pending_queue.total_count().unwrap_or(0);
    tracing::info!(
        pending_messages = pending,
        "shutdown complete"
    );
}