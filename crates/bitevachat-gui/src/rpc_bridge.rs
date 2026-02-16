//! Async RPC bridge between the eframe UI thread and the gRPC node.
//!
//! Runs entirely on a dedicated tokio runtime thread. The UI
//! communicates via bounded channels using `try_send` / `try_recv`
//! to avoid ever blocking the render loop.
//!
//! The bridge now also handles embedded node bootstrap: creating the
//! wallet, starting the node, starting the RPC server, and then
//! connecting as a gRPC client.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tonic::transport::Channel;

use crate::embedded::{self, BootstrapInfo};
use crate::proto;

// ---------------------------------------------------------------------------
// Channel buffer sizes
// ---------------------------------------------------------------------------

/// UI → bridge command channel capacity.
pub const CMD_CHANNEL_SIZE: usize = 256;

/// Bridge → UI event channel capacity.
pub const EVT_CHANNEL_SIZE: usize = 1024;

/// Polling interval for status / messages when streaming unavailable.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Connection timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// UiCommand — UI sends these to the bridge
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum UiCommand {
    /// Bootstrap the full embedded node stack, then auto-connect.
    BootstrapNode {
        data_dir: PathBuf,
        /// `Some(words)` for new wallet, `None` for existing wallet.
        mnemonic: Option<String>,
        passphrase: String,
    },
    Connect {
        endpoint: String,
    },
    Disconnect,
    GetStatus,
    SendMessage {
        recipient: String,
        text: String,
    },
    ListMessages {
        convo_id: String,
        limit: u64,
        offset: u64,
    },
    ListContacts,
    AddContact {
        address: String,
        alias: String,
    },
    BlockContact {
        address: String,
    },
    UnblockContact {
        address: String,
    },
    ListPeers,
    GetProfile {
        address: String,
    },
    UpdateProfile {
        name: String,
        bio: String,
        avatar: Vec<u8>,
        remove_avatar: bool,
    },
    GetAvatar {
        cid: String,
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// UiEvent — bridge sends these back to the UI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Embedded node started successfully.
    NodeStarted {
        address: String,
        rpc_endpoint: String,
    },
    Connected,
    Disconnected(String),
    Status(NodeStatus),
    MessageSent {
        message_id: String,
    },
    Messages(Vec<MessageItem>),
    ContactList(Vec<ContactItem>),
    PeerList(Vec<PeerItem>),
    Profile(ProfileData),
    ProfileUpdated {
        avatar_cid: String,
        version: u64,
    },
    AvatarLoaded {
        cid: String,
        data: Vec<u8>,
    },
    Notification {
        event_type: String,
        message_id: String,
        sender: String,
        convo_id: String,
    },
    Error(String),
}

// ---------------------------------------------------------------------------
// Data structs shared between bridge and UI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct NodeStatus {
    pub state: String,
    pub address: String,
    pub peer_id: String,
    pub node_id: String,
    pub listeners: Vec<String>,
    pub pending_count: u64,
}

#[derive(Debug, Clone)]
pub struct MessageItem {
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub timestamp: String,
    pub payload_type: String,
    pub payload_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ContactItem {
    pub address: String,
    pub alias: String,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct PeerItem {
    pub peer_id: String,
    pub node_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProfileData {
    pub found: bool,
    pub address: String,
    pub name: String,
    pub bio: String,
    pub avatar_cid: String,
    pub timestamp: String,
    pub version: u64,
}

// ---------------------------------------------------------------------------
// Channel pair constructor
// ---------------------------------------------------------------------------

/// Creates the bounded channel pair for UI ↔ bridge communication.
pub fn create_channels() -> (
    mpsc::Sender<UiCommand>,
    mpsc::Receiver<UiCommand>,
    mpsc::Sender<UiEvent>,
    mpsc::Receiver<UiEvent>,
) {
    let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_SIZE);
    let (evt_tx, evt_rx) = mpsc::channel(EVT_CHANNEL_SIZE);
    (cmd_tx, cmd_rx, evt_tx, evt_rx)
}

// ---------------------------------------------------------------------------
// Bridge main loop
// ---------------------------------------------------------------------------

/// Runs the RPC bridge. Call this from a dedicated tokio runtime thread.
///
/// Never panics. All errors are forwarded to the UI as `UiEvent::Error`.
pub async fn run_bridge(
    mut cmd_rx: mpsc::Receiver<UiCommand>,
    evt_tx: mpsc::Sender<UiEvent>,
) {
    let mut connection: Option<RpcClients> = None;
    let mut _bootstrap: Option<BootstrapInfo> = None;
    let mut poll_ticker = tokio::time::interval(POLL_INTERVAL);
    poll_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(command) => {
                        handle_command(
                            command,
                            &mut connection,
                            &mut _bootstrap,
                            &evt_tx,
                        ).await;
                    }
                    None => {
                        // UI dropped the sender — exit.
                        break;
                    }
                }
            }
            _ = poll_ticker.tick() => {
                if let Some(ref mut clients) = connection {
                    poll_status(clients, &evt_tx).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RPC client wrapper
// ---------------------------------------------------------------------------

struct RpcClients {
    message: proto::message_service_client::MessageServiceClient<Channel>,
    contact: proto::contact_service_client::ContactServiceClient<Channel>,
    node: proto::node_service_client::NodeServiceClient<Channel>,
    profile: proto::profile_service_client::ProfileServiceClient<Channel>,
}

async fn connect_to_node(endpoint: &str) -> Result<RpcClients, String> {
    let channel = Channel::from_shared(endpoint.to_string())
        .map_err(|e| format!("invalid endpoint: {e}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CONNECT_TIMEOUT * 2)
        .connect()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    Ok(RpcClients {
        message: proto::message_service_client::MessageServiceClient::new(
            channel.clone(),
        ),
        contact: proto::contact_service_client::ContactServiceClient::new(
            channel.clone(),
        ),
        node: proto::node_service_client::NodeServiceClient::new(
            channel.clone(),
        ),
        profile: proto::profile_service_client::ProfileServiceClient::new(
            channel,
        ),
    })
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

async fn handle_command(
    cmd: UiCommand,
    connection: &mut Option<RpcClients>,
    bootstrap: &mut Option<BootstrapInfo>,
    evt_tx: &mpsc::Sender<UiEvent>,
) {
    match cmd {
        // ---------------------------------------------------------------
        // Embedded node bootstrap
        // ---------------------------------------------------------------
        UiCommand::BootstrapNode {
            data_dir,
            mnemonic,
            passphrase,
        } => {
            let _ = evt_tx.send(UiEvent::Status(NodeStatus {
                state: "starting...".into(),
                ..Default::default()
            })).await;

            let result = embedded::bootstrap_node(
                &data_dir,
                mnemonic.as_deref(),
                &passphrase,
            )
            .await;

            match result {
                Ok(info) => {
                    let address = info.address.clone();
                    let endpoint = info.rpc_endpoint.clone();
                    *bootstrap = Some(info);

                    let _ = evt_tx.send(UiEvent::NodeStarted {
                        address: address.clone(),
                        rpc_endpoint: endpoint.clone(),
                    }).await;

                    // Small delay for the RPC server to be ready.
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    // Auto-connect to the embedded RPC server.
                    match connect_to_node(&endpoint).await {
                        Ok(clients) => {
                            *connection = Some(clients);
                            let _ = evt_tx.send(UiEvent::Connected).await;
                        }
                        Err(e) => {
                            // Retry once after a short delay.
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            match connect_to_node(&endpoint).await {
                                Ok(clients) => {
                                    *connection = Some(clients);
                                    let _ = evt_tx.send(UiEvent::Connected).await;
                                }
                                Err(e2) => {
                                    let _ = evt_tx.send(UiEvent::Error(
                                        format!("node started but RPC connect failed: {e}, retry: {e2}"),
                                    )).await;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = evt_tx.send(UiEvent::Error(e)).await;
                }
            }
        }

        // ---------------------------------------------------------------
        // Manual connect (for external node)
        // ---------------------------------------------------------------
        UiCommand::Connect { endpoint } => {
            match connect_to_node(&endpoint).await {
                Ok(clients) => {
                    *connection = Some(clients);
                    let _ = evt_tx.send(UiEvent::Connected).await;
                }
                Err(e) => {
                    let _ = evt_tx.send(UiEvent::Disconnected(e)).await;
                }
            }
        }

        UiCommand::Disconnect => {
            *connection = None;
            let _ = evt_tx
                .send(UiEvent::Disconnected("disconnected by user".into()))
                .await;
        }

        UiCommand::GetStatus => {
            if let Some(ref mut clients) = connection {
                poll_status(clients, evt_tx).await;
            }
        }

        UiCommand::SendMessage { recipient, text } => {
            let Some(ref mut clients) = connection else {
                let _ = evt_tx
                    .send(UiEvent::Error("not connected".into()))
                    .await;
                return;
            };
            let req = proto::SendMessageRequest {
                recipient,
                plaintext: text.into_bytes(),
                payload_type: "text".into(),
                shared_key: vec![0u8; 32],
            };
            match clients.message.send_message(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let _ = evt_tx
                        .send(UiEvent::MessageSent {
                            message_id: inner.message_id,
                        })
                        .await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!("send failed: {}", e.message())))
                        .await;
                }
            }
        }

        UiCommand::ListMessages {
            convo_id,
            limit,
            offset,
        } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::ListMessagesRequest {
                convo_id,
                limit,
                offset,
            };
            match clients.message.list_messages(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let items: Vec<MessageItem> = inner
                        .messages
                        .into_iter()
                        .map(|m| MessageItem {
                            message_id: m.message_id,
                            sender: m.sender,
                            recipient: m.recipient,
                            timestamp: m.timestamp,
                            payload_type: m.payload_type,
                            payload_ciphertext: m.payload_ciphertext,
                        })
                        .collect();
                    let _ = evt_tx.send(UiEvent::Messages(items)).await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!(
                            "list messages: {}",
                            e.message()
                        )))
                        .await;
                }
            }
        }

        UiCommand::ListContacts => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::ListContactsRequest {};
            match clients.contact.list_contacts(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let items: Vec<ContactItem> = inner
                        .contacts
                        .into_iter()
                        .map(|c| ContactItem {
                            address: c.address,
                            alias: c.alias,
                            blocked: c.blocked,
                        })
                        .collect();
                    let _ = evt_tx.send(UiEvent::ContactList(items)).await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!(
                            "list contacts: {}",
                            e.message()
                        )))
                        .await;
                }
            }
        }

        UiCommand::AddContact { address, alias } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::AddContactRequest { address, alias };
            match clients.contact.add_contact(req).await {
                Ok(_) => {
                    let req2 = proto::ListContactsRequest {};
                    if let Ok(resp) = clients.contact.list_contacts(req2).await {
                        let items: Vec<ContactItem> = resp
                            .into_inner()
                            .contacts
                            .into_iter()
                            .map(|c| ContactItem {
                                address: c.address,
                                alias: c.alias,
                                blocked: c.blocked,
                            })
                            .collect();
                        let _ = evt_tx.send(UiEvent::ContactList(items)).await;
                    }
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!(
                            "add contact: {}",
                            e.message()
                        )))
                        .await;
                }
            }
        }

        UiCommand::BlockContact { address } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::BlockContactRequest { address };
            if let Err(e) = clients.contact.block_contact(req).await {
                let _ = evt_tx
                    .send(UiEvent::Error(format!("block: {}", e.message())))
                    .await;
            }
        }

        UiCommand::UnblockContact { address } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::UnblockContactRequest { address };
            if let Err(e) = clients.contact.unblock_contact(req).await {
                let _ = evt_tx
                    .send(UiEvent::Error(format!("unblock: {}", e.message())))
                    .await;
            }
        }

        UiCommand::ListPeers => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::ListPeersRequest {};
            match clients.node.list_peers(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let items: Vec<PeerItem> = inner
                        .peers
                        .into_iter()
                        .map(|p| PeerItem {
                            peer_id: p.peer_id,
                            node_id: p.node_id,
                        })
                        .collect();
                    let _ = evt_tx.send(UiEvent::PeerList(items)).await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!(
                            "list peers: {}",
                            e.message()
                        )))
                        .await;
                }
            }
        }

        UiCommand::GetProfile { address } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::GetProfileRequest { address };
            match clients.profile.get_profile(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let data = match inner.profile {
                        Some(p) => ProfileData {
                            found: inner.found,
                            address: p.address,
                            name: p.name,
                            bio: p.bio,
                            avatar_cid: p.avatar_cid,
                            timestamp: p.timestamp,
                            version: p.version,
                        },
                        None => ProfileData {
                            found: false,
                            ..Default::default()
                        },
                    };
                    let _ = evt_tx.send(UiEvent::Profile(data)).await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!(
                            "get profile: {}",
                            e.message()
                        )))
                        .await;
                }
            }
        }

        UiCommand::UpdateProfile {
            name,
            bio,
            avatar,
            remove_avatar,
        } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::UpdateProfileRequest {
                name,
                bio,
                avatar,
                remove_avatar,
            };
            match clients.profile.update_profile(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    let _ = evt_tx
                        .send(UiEvent::ProfileUpdated {
                            avatar_cid: inner.avatar_cid,
                            version: inner.version,
                        })
                        .await;
                }
                Err(e) => {
                    let _ = evt_tx
                        .send(UiEvent::Error(format!(
                            "update profile: {}",
                            e.message()
                        )))
                        .await;
                }
            }
        }

        UiCommand::GetAvatar { cid } => {
            let Some(ref mut clients) = connection else {
                return;
            };
            let req = proto::GetAvatarRequest { cid: cid.clone() };
            match clients.profile.get_avatar(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    if inner.found {
                        let _ = evt_tx
                            .send(UiEvent::AvatarLoaded {
                                cid,
                                data: inner.data,
                            })
                            .await;
                    }
                }
                Err(_) => {
                    // Avatar fetch failure is non-critical.
                }
            }
        }

        UiCommand::Shutdown => {
            if let Some(ref mut clients) = connection {
                let req = proto::ShutdownRequest {};
                let _ = clients.node.shutdown(req).await;
            }
            *connection = None;
            *bootstrap = None; // drops BootstrapInfo → signals RPC shutdown
            let _ = evt_tx
                .send(UiEvent::Disconnected("node shut down".into()))
                .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Polling helper
// ---------------------------------------------------------------------------

async fn poll_status(clients: &mut RpcClients, evt_tx: &mpsc::Sender<UiEvent>) {
    let req = proto::GetStatusRequest {};
    match clients.node.get_status(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            let status = NodeStatus {
                state: inner.state,
                address: inner.address,
                peer_id: inner.peer_id,
                node_id: inner.node_id,
                listeners: inner.listeners,
                pending_count: inner.pending_count,
            };
            let _ = evt_tx.send(UiEvent::Status(status)).await;
        }
        Err(_) => {
            // Polling failure is silent.
        }
    }
}