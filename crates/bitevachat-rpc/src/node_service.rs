//! `NodeService` gRPC implementation.
//!
//! Provides node status queries, peer listing, graceful shutdown, and
//! external message injection. The `InjectMessage` handler performs
//! full cryptographic re-verification via [`crate::inject`] before
//! forwarding to the node core.

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use bitevachat_node::NodeCommand;

use crate::inject;
use crate::proto;

// ---------------------------------------------------------------------------
// Service state
// ---------------------------------------------------------------------------

/// gRPC implementation of `NodeService`.
pub struct NodeServiceImpl {
    command_tx: mpsc::Sender<NodeCommand>,
}

impl NodeServiceImpl {
    /// Creates a new `NodeServiceImpl`.
    pub fn new(command_tx: mpsc::Sender<NodeCommand>) -> Self {
        Self { command_tx }
    }
}

// ---------------------------------------------------------------------------
// tonic trait implementation
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl proto::node_service_server::NodeService for NodeServiceImpl {
    /// Returns the current node status.
    async fn get_status(
        &self,
        _request: Request<proto::GetStatusRequest>,
    ) -> std::result::Result<Response<proto::NodeStatusResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::GetStatus {
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        let status = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        Ok(Response::new(proto::NodeStatusResponse {
            state: status.state.to_string(),
            address: status.address.to_string(),
            peer_id: status.peer_id,
            node_id: status.node_id.to_string(),
            listeners: status.listeners,
            pending_count: status.pending_count as u64,
        }))
    }

    /// Lists currently connected peers.
    async fn list_peers(
        &self,
        _request: Request<proto::ListPeersRequest>,
    ) -> std::result::Result<Response<proto::ListPeersResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::ListPeers {
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        let result = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        let peers = result.map_err(node_err_to_status)?;

        let proto_peers: Vec<proto::PeerEntry> = peers
            .into_iter()
            .map(|p| proto::PeerEntry {
                peer_id: p.peer_id,
                node_id: p.node_id.to_string(),
            })
            .collect();

        Ok(Response::new(proto::ListPeersResponse {
            peers: proto_peers,
        }))
    }

    /// Initiates graceful node shutdown.
    async fn shutdown(
        &self,
        _request: Request<proto::ShutdownRequest>,
    ) -> std::result::Result<Response<proto::ShutdownResponse>, Status> {
        // Fire-and-forget: the Shutdown command has no reply channel.
        self.command_tx
            .send(NodeCommand::Shutdown)
            .await
            .map_err(|_| Status::unavailable("node is already shutting down"))?;

        Ok(Response::new(proto::ShutdownResponse {}))
    }

    /// Injects an externally signed message after full re-verification.
    ///
    /// The handler:
    /// 1. Validates input lengths.
    /// 2. Verifies Ed25519 signature over canonical CBOR.
    /// 3. Verifies pubkey → sender address binding.
    /// 4. Validates timestamp skew (±5 minutes).
    /// 5. Forwards verified `MessageEnvelope` to the node.
    async fn inject_message(
        &self,
        request: Request<proto::InjectMessageRequest>,
    ) -> std::result::Result<Response<proto::InjectMessageResponse>, Status> {
        let req = request.into_inner();

        // Validate non-empty inputs.
        if req.canonical_message.is_empty() {
            return Err(Status::invalid_argument(
                "canonical_message must not be empty",
            ));
        }
        if req.signature.is_empty() {
            return Err(Status::invalid_argument(
                "signature must not be empty",
            ));
        }
        if req.sender_pubkey.is_empty() {
            return Err(Status::invalid_argument(
                "sender_pubkey must not be empty",
            ));
        }

        // Full cryptographic re-verification.
        let envelope = inject::verify_and_reconstruct(
            &req.canonical_message,
            &req.signature,
            &req.sender_pubkey,
        )
        .map_err(|e| {
            // Map specific crypto/protocol errors to appropriate status.
            use bitevachat_types::BitevachatError;
            match &e {
                BitevachatError::CryptoError { .. } => {
                    Status::unauthenticated(e.to_string())
                }
                BitevachatError::InvalidMessage { .. } => {
                    Status::invalid_argument(e.to_string())
                }
                BitevachatError::ProtocolError { .. } => {
                    Status::invalid_argument(e.to_string())
                }
                _ => Status::internal(e.to_string()),
            }
        })?;

        // Forward to node.
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::InjectMessage {
            envelope,
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        let result = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        let message_id = result.map_err(node_err_to_status)?;

        Ok(Response::new(proto::InjectMessageResponse {
            message_id: message_id.to_string(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maps a `BitevachatError` to a `tonic::Status`.
fn node_err_to_status(err: bitevachat_types::BitevachatError) -> Status {
    use bitevachat_types::BitevachatError;
    match &err {
        BitevachatError::InvalidAddress { .. }
        | BitevachatError::InvalidMessage { .. } => {
            Status::invalid_argument(err.to_string())
        }
        BitevachatError::CryptoError { .. } => {
            Status::unauthenticated(err.to_string())
        }
        BitevachatError::StorageError { .. }
        | BitevachatError::ProtocolError { .. } => {
            Status::internal(err.to_string())
        }
        BitevachatError::NetworkError { .. } => {
            Status::unavailable(err.to_string())
        }
        _ => Status::internal(err.to_string()),
    }
}