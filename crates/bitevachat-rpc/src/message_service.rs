//! `MessageService` gRPC implementation.
//!
//! Translates proto requests into [`NodeCommand`]s, sends them
//! through the bounded command channel, and awaits the oneshot reply.
//! All input is validated before sending; all errors are mapped to
//! appropriate `tonic::Status` codes.

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use bitevachat_node::NodeCommand;
use bitevachat_types::{Address, ConvoId, MessageId, PayloadType};

use crate::proto;

// ---------------------------------------------------------------------------
// Service state
// ---------------------------------------------------------------------------

/// gRPC implementation of `MessageService`.
pub struct MessageServiceImpl {
    /// Cloneable sender for the node command channel.
    command_tx: mpsc::Sender<NodeCommand>,
}

impl MessageServiceImpl {
    /// Creates a new `MessageServiceImpl`.
    pub fn new(command_tx: mpsc::Sender<NodeCommand>) -> Self {
        Self { command_tx }
    }
}

// ---------------------------------------------------------------------------
// tonic trait implementation
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl proto::message_service_server::MessageService for MessageServiceImpl {
    /// Sends an E2E encrypted message.
    async fn send_message(
        &self,
        request: Request<proto::SendMessageRequest>,
    ) -> std::result::Result<Response<proto::SendMessageResponse>, Status> {
        let req = request.into_inner();

        // Validate recipient address (64 hex chars = 32 bytes).
        let recipient: Address = req
            .recipient
            .parse()
            .map_err(|_| Status::invalid_argument("invalid recipient address hex"))?;

        // Validate payload type.
        let payload_type = parse_payload_type(&req.payload_type)?;

        // Validate shared key (exactly 32 bytes).
        if req.shared_key.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "shared_key must be 32 bytes, got {}",
                req.shared_key.len(),
            )));
        }
        let mut shared_key = [0u8; 32];
        shared_key.copy_from_slice(&req.shared_key);

        // Validate plaintext is non-empty.
        if req.plaintext.is_empty() {
            return Err(Status::invalid_argument("plaintext must not be empty"));
        }

        // Build command.
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::SendMessage {
            recipient,
            plaintext: req.plaintext,
            payload_type,
            shared_key,
            reply: reply_tx,
        };

        // Send command (backpressure if channel full).
        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        // Await reply.
        let result = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        let message_id = result.map_err(node_err_to_status)?;

        Ok(Response::new(proto::SendMessageResponse {
            message_id: message_id.to_string(),
        }))
    }

    /// Lists messages in a conversation (paginated).
    async fn list_messages(
        &self,
        request: Request<proto::ListMessagesRequest>,
    ) -> std::result::Result<Response<proto::ListMessagesResponse>, Status> {
        let req = request.into_inner();

        // Validate convo_id.
        let convo_id = parse_convo_id(&req.convo_id)?;

        let limit = if req.limit == 0 { 50 } else { req.limit };

        // Build command.
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::ListMessages {
            convo_id,
            limit,
            offset: req.offset,
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        let result = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        let messages = result.map_err(node_err_to_status)?;

        let proto_messages: Vec<proto::MessageInfo> = messages
            .into_iter()
            .map(|m| proto::MessageInfo {
                message_id: m.message_id.to_string(),
                sender: m.sender.to_string(),
                recipient: m.recipient.to_string(),
                timestamp: m.timestamp.to_string(),
                payload_type: m.payload_type.to_string(),
                payload_ciphertext: m.payload_ciphertext,
            })
            .collect();

        Ok(Response::new(proto::ListMessagesResponse {
            messages: proto_messages,
        }))
    }

    /// Retrieves a single message by ID.
    async fn get_message(
        &self,
        request: Request<proto::GetMessageRequest>,
    ) -> std::result::Result<Response<proto::GetMessageResponse>, Status> {
        let req = request.into_inner();

        let message_id: MessageId = req
            .message_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid message_id hex"))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::GetMessage {
            message_id,
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        let result = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        let maybe_msg = result.map_err(node_err_to_status)?;

        let proto_msg = maybe_msg.map(|m| proto::MessageInfo {
            message_id: m.message_id.to_string(),
            sender: m.sender.to_string(),
            recipient: m.recipient.to_string(),
            timestamp: m.timestamp.to_string(),
            payload_type: m.payload_type.to_string(),
            payload_ciphertext: m.payload_ciphertext,
        });

        Ok(Response::new(proto::GetMessageResponse {
            message: proto_msg,
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parses a payload type string into a `PayloadType`.
fn parse_payload_type(s: &str) -> std::result::Result<PayloadType, Status> {
    match s {
        "text" | "Text" => Ok(PayloadType::Text),
        "file" | "File" => Ok(PayloadType::File),
        "system" | "System" => Ok(PayloadType::System),
        _ => Err(Status::invalid_argument(format!(
            "unknown payload_type '{}'; expected 'text', 'file', or 'system'",
            s,
        ))),
    }
}

/// Parses a hex-encoded conversation ID.
fn parse_convo_id(s: &str) -> std::result::Result<ConvoId, Status> {
    let bytes = hex::decode(s).map_err(|_| {
        Status::invalid_argument("invalid convo_id hex encoding")
    })?;
    if bytes.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "convo_id must be 32 bytes, got {}",
            bytes.len(),
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ConvoId::new(arr))
}

/// Maps a `BitevachatError` to a `tonic::Status`.
fn node_err_to_status(err: bitevachat_types::BitevachatError) -> Status {
    use bitevachat_types::BitevachatError;
    match &err {
        BitevachatError::InvalidAddress { .. } => {
            Status::invalid_argument(err.to_string())
        }
        BitevachatError::InvalidMessage { .. } => {
            Status::invalid_argument(err.to_string())
        }
        BitevachatError::CryptoError { .. } => {
            Status::failed_precondition(err.to_string())
        }
        BitevachatError::StorageError { .. } => {
            Status::internal(err.to_string())
        }
        BitevachatError::NetworkError { .. } => {
            Status::unavailable(err.to_string())
        }
        BitevachatError::ProtocolError { .. } => {
            Status::internal(err.to_string())
        }
        BitevachatError::RateLimitExceeded { .. } => {
            Status::resource_exhausted(err.to_string())
        }
        BitevachatError::NonceReplay { .. } => {
            Status::already_exists(err.to_string())
        }
        BitevachatError::ConfigError { .. } => {
            Status::failed_precondition(err.to_string())
        }
    }
}