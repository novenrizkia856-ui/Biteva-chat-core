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
use bitevachat_types::{BitevachatError, MessageId, NodeEvent, NodeId, Timestamp};

use crate::command::{NodeCommand, NodeStatus};
use crate::incoming;
use crate::maintenance;
use crate::node::{NodeRuntime, NodeState};
use crate::outgoing;
use crate::pending_scheduler::PendingScheduler;

// ---------------------------------------------------------------------------
// Helper: PeerId → NodeId
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
/// spawned as a single tokio task — all mutable state lives here,
/// eliminating the need for locks on hot paths.
pub(crate) async fn run_event_loop(mut rt: NodeRuntime) {
    tracing::info!("node event loop starting");

    let scheduler = PendingScheduler::new(
        rt.pending_queue.clone(),
        rt.config.pending_ttl_days,
    );

    let mut pending_tick = tokio::time::interval(
        Duration::from_secs(rt.pending_tick_secs),
    );
    let mut maintenance_tick = tokio::time::interval(
        Duration::from_secs(rt.maintenance_tick_secs),
    );

    // Start listening on the configured address.
    if let Err(e) = rt.network.start_listening(rt.listen_addr.clone()) {
        tracing::error!(%e, "failed to start listening — continuing without listener");
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
                handle_network_event(
                    net_event,
                    &rt.storage,
                    &rt.pending_queue,
                    &rt.event_tx,
                ).await;
            }

            // ---------------------------------------------------------------
            // 3. Process commands from RPC / CLI.
            // ---------------------------------------------------------------
            Some(cmd) = rt.command_rx.recv() => {
                let should_shutdown = handle_command(cmd, &mut rt);
                if should_shutdown {
                    tracing::info!("shutdown command received — exiting event loop");
                    break;
                }
            }

            // ---------------------------------------------------------------
            // 4. Pending message retry tick.
            // ---------------------------------------------------------------
            _ = pending_tick.tick() => {
                handle_pending_tick(&scheduler, &rt.pending_queue);
            }

            // ---------------------------------------------------------------
            // 5. Maintenance tick (flush, prune, DHT refresh).
            // ---------------------------------------------------------------
            _ = maintenance_tick.tick() => {
                handle_maintenance_tick(&rt.storage, &rt.config);
            }

            // ---------------------------------------------------------------
            // 6. Shutdown signal via watch channel.
            // ---------------------------------------------------------------
            _ = rt.shutdown_rx.changed() => {
                if *rt.shutdown_rx.borrow() {
                    tracing::info!("shutdown signal received — exiting event loop");
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
    storage: &bitevachat_storage::engine::StorageEngine,
    pending_queue: &std::sync::Arc<bitevachat_storage::pending::PendingQueue>,
    event_tx: &tokio::sync::mpsc::Sender<NodeEvent>,
) {
    match event {
        NetworkEvent::MessageReceived(envelope) => {
            let result = incoming::handle_incoming_message(
                &envelope,
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

        NetworkEvent::PeerDisconnected(peer_id) => {
            tracing::info!(%peer_id, "peer disconnected");
            let node_id = peer_id_to_node_id(&peer_id);
            let _ = event_tx
                .send(NodeEvent::PeerDisconnected { node_id })
                .await;
        }

        NetworkEvent::GossipMessage { source, topic, data } => {
            tracing::debug!(
                %source,
                %topic,
                bytes = data.len(),
                "gossip message received"
            );
        }

        NetworkEvent::NatStatusChanged(status) => {
            tracing::info!(?status, "NAT status changed");
        }

        NetworkEvent::HolePunchSucceeded(peer_id) => {
            tracing::info!(%peer_id, "hole punch succeeded — direct connection active");
        }
    }
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
            // Send reply; ignore if receiver dropped.
            let _ = reply.send(result);
            false
        }

        NodeCommand::GetStatus { reply } => {
            let status = build_status(rt);
            let _ = reply.send(status);
            false
        }

        NodeCommand::Shutdown => true,
    }
}

/// Handles the SendMessage command: build envelope → enqueue pending.
///
/// Synchronous — no network I/O here. Actual delivery is handled
/// by the pending scheduler on the next tick.
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

    // Resolve recipient PeerId via DHT lookup.
    // The DHT query is asynchronous — results arrive via Kademlia
    // events. For the initial implementation, we enqueue the message
    // as pending and let the scheduler handle delivery when the
    // peer is discovered.
    //
    // TODO: Implement synchronous peer cache lookup. If the peer
    // is already known/connected, send immediately via
    // `network.send_message_to_peer()`.

    // Enqueue for pending delivery.
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
        "message enqueued for delivery"
    );

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
// Pending tick handler
// ---------------------------------------------------------------------------

/// Processes one pending scheduler tick.
///
/// Dequeues ready entries and attempts re-delivery. Failures are
/// handled by the pending queue's backoff mechanism.
///
/// Synchronous — `PendingQueue` methods are all blocking. No await
/// points means no `&NodeRuntime` held across thread boundaries.
fn handle_pending_tick(
    scheduler: &PendingScheduler,
    pending_queue: &std::sync::Arc<bitevachat_storage::pending::PendingQueue>,
) {
    let ready = match scheduler.tick() {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(%e, "pending scheduler tick failed");
            return;
        }
    };

    if ready.is_empty() {
        return;
    }

    tracing::debug!(count = ready.len(), "pending scheduler: retrying messages");

    for entry in &ready {
        let msg_id = entry.message_id().clone();

        // For retry, we need the recipient's PeerId. If we don't have
        // it cached, start a DHT lookup and skip this entry (the next
        // tick will retry after the lookup completes).
        //
        // TODO: Implement peer cache lookup. When the peer is known
        // and connected, send directly via the network swarm.
        // For now, mark as failed so backoff increments.
        let now = Timestamp::now();
        let _ = pending_queue.mark_failed(&msg_id, &now);
    }
}

// ---------------------------------------------------------------------------
// Maintenance tick handler
// ---------------------------------------------------------------------------

/// Runs periodic maintenance tasks.
///
/// Synchronous — `run_storage_maintenance` is blocking I/O.
/// Taking specific fields (`&StorageEngine`, `&AppConfig`) instead
/// of `&NodeRuntime` avoids the `Sync` bound problem.
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
///
/// Synchronous — storage flush is blocking. Takes specific fields
/// to avoid `&NodeRuntime` shared reference across await points.
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