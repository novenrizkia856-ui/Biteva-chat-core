//! `ContactService` gRPC implementation.
//!
//! Handles contact alias management and block/unblock operations.
//! All address inputs are validated as 64-character hex strings
//! before being forwarded to the node.

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use bitevachat_node::NodeCommand;
use bitevachat_types::Address;

use crate::proto;

// ---------------------------------------------------------------------------
// Service state
// ---------------------------------------------------------------------------

/// gRPC implementation of `ContactService`.
pub struct ContactServiceImpl {
    command_tx: mpsc::Sender<NodeCommand>,
}

impl ContactServiceImpl {
    /// Creates a new `ContactServiceImpl`.
    pub fn new(command_tx: mpsc::Sender<NodeCommand>) -> Self {
        Self { command_tx }
    }
}

// ---------------------------------------------------------------------------
// tonic trait implementation
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl proto::contact_service_server::ContactService for ContactServiceImpl {
    /// Adds or updates a contact alias.
    async fn add_contact(
        &self,
        request: Request<proto::AddContactRequest>,
    ) -> std::result::Result<Response<proto::AddContactResponse>, Status> {
        let req = request.into_inner();

        let address = parse_address(&req.address)?;

        // Alias may be empty (clears existing alias).
        let alias = req.alias;

        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::AddContact {
            address,
            alias,
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?
            .map_err(node_err_to_status)?;

        Ok(Response::new(proto::AddContactResponse {}))
    }

    /// Blocks a contact address.
    async fn block_contact(
        &self,
        request: Request<proto::BlockContactRequest>,
    ) -> std::result::Result<Response<proto::BlockContactResponse>, Status> {
        let req = request.into_inner();
        let address = parse_address(&req.address)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::BlockContact {
            address,
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?
            .map_err(node_err_to_status)?;

        Ok(Response::new(proto::BlockContactResponse {}))
    }

    /// Unblocks a previously blocked contact.
    async fn unblock_contact(
        &self,
        request: Request<proto::UnblockContactRequest>,
    ) -> std::result::Result<Response<proto::UnblockContactResponse>, Status> {
        let req = request.into_inner();
        let address = parse_address(&req.address)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::UnblockContact {
            address,
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?
            .map_err(node_err_to_status)?;

        Ok(Response::new(proto::UnblockContactResponse {}))
    }

    /// Lists all contacts.
    async fn list_contacts(
        &self,
        _request: Request<proto::ListContactsRequest>,
    ) -> std::result::Result<Response<proto::ListContactsResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = NodeCommand::ListContacts {
            reply: reply_tx,
        };

        self.command_tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("node is shutting down"))?;

        let result = reply_rx
            .await
            .map_err(|_| Status::internal("node dropped reply channel"))?;

        let contacts = result.map_err(node_err_to_status)?;

        let proto_contacts: Vec<proto::ContactEntry> = contacts
            .into_iter()
            .map(|c| proto::ContactEntry {
                address: c.address.to_string(),
                alias: c.alias,
                blocked: c.blocked,
            })
            .collect();

        Ok(Response::new(proto::ListContactsResponse {
            contacts: proto_contacts,
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parses and validates a hex-encoded address.
fn parse_address(s: &str) -> std::result::Result<Address, Status> {
    s.parse::<Address>()
        .map_err(|_| Status::invalid_argument("invalid address: expected 64 hex characters"))
}

/// Maps a `BitevachatError` to a `tonic::Status`.
fn node_err_to_status(err: bitevachat_types::BitevachatError) -> Status {
    use bitevachat_types::BitevachatError;
    match &err {
        BitevachatError::InvalidAddress { .. } => {
            Status::invalid_argument(err.to_string())
        }
        BitevachatError::StorageError { .. } => {
            Status::internal(err.to_string())
        }
        _ => Status::internal(err.to_string()),
    }
}