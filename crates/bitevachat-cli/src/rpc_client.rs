//! RPC client wrapper over tonic-generated stubs.
//!
//! Provides a single `RpcClient` that lazily connects and maps
//! `tonic::Status` errors to human-readable strings.

use std::time::Duration;

use tonic::transport::Channel;

use crate::proto::{
    // Message service
    message_service_client::MessageServiceClient,
    SendMessageRequest, SendMessageResponse,
    ListMessagesRequest, ListMessagesResponse,
    GetMessageRequest, GetMessageResponse,
    // Contact service
    contact_service_client::ContactServiceClient,
    AddContactRequest, BlockContactRequest, UnblockContactRequest,
    ListContactsRequest, ListContactsResponse,
    // Node service
    node_service_client::NodeServiceClient,
    GetStatusRequest, NodeStatusResponse,
    ListPeersRequest, ListPeersResponse,
    ShutdownRequest,
    // Node service (extra)
    InjectMessageRequest, InjectMessageResponse,
    // Profile service
    profile_service_client::ProfileServiceClient,
    GetProfileRequest, GetProfileResponse,
    UpdateProfileRequest, UpdateProfileResponse,
    GetAvatarRequest, GetAvatarResponse,
};

/// Unified RPC client wrapping all four service clients.
pub struct RpcClient {
    message: MessageServiceClient<Channel>,
    contact: ContactServiceClient<Channel>,
    node: NodeServiceClient<Channel>,
    profile: ProfileServiceClient<Channel>,
}

impl RpcClient {
    /// Connects to the gRPC endpoint with the specified timeout.
    pub async fn connect(endpoint: &str, timeout_secs: u64) -> std::result::Result<Self, String> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| format!("invalid endpoint '{}': {}", endpoint, e))?
            .connect_timeout(Duration::from_secs(timeout_secs))
            .timeout(Duration::from_secs(timeout_secs * 2))
            .connect()
            .await
            .map_err(|e| format!("failed to connect to '{}': {}", endpoint, e))?;

        Ok(Self {
            message: MessageServiceClient::new(channel.clone()),
            contact: ContactServiceClient::new(channel.clone()),
            node: NodeServiceClient::new(channel.clone()),
            profile: ProfileServiceClient::new(channel),
        })
    }

    // -----------------------------------------------------------------------
    // Message service
    // -----------------------------------------------------------------------

    pub async fn send_message(
        &mut self,
        recipient: &str,
        plaintext: Vec<u8>,
        payload_type: &str,
        shared_key: Vec<u8>,
    ) -> std::result::Result<SendMessageResponse, String> {
        let req = SendMessageRequest {
            recipient: recipient.into(),
            plaintext,
            payload_type: payload_type.into(),
            shared_key,
        };
        self.message
            .send_message(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    pub async fn list_messages(
        &mut self,
        convo_id: &str,
        limit: u64,
        offset: u64,
    ) -> std::result::Result<ListMessagesResponse, String> {
        let req = ListMessagesRequest {
            convo_id: convo_id.into(),
            limit,
            offset,
        };
        self.message
            .list_messages(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    pub async fn get_message(
        &mut self,
        message_id: &str,
    ) -> std::result::Result<GetMessageResponse, String> {
        let req = GetMessageRequest {
            message_id: message_id.into(),
        };
        self.message
            .get_message(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    // -----------------------------------------------------------------------
    // Contact service
    // -----------------------------------------------------------------------

    pub async fn add_contact(
        &mut self,
        address: &str,
        alias: &str,
    ) -> std::result::Result<(), String> {
        let req = AddContactRequest {
            address: address.into(),
            alias: alias.into(),
        };
        self.contact
            .add_contact(req)
            .await
            .map(|_| ())
            .map_err(map_status)
    }

    pub async fn block_contact(&mut self, address: &str) -> std::result::Result<(), String> {
        let req = BlockContactRequest {
            address: address.into(),
        };
        self.contact
            .block_contact(req)
            .await
            .map(|_| ())
            .map_err(map_status)
    }

    pub async fn unblock_contact(&mut self, address: &str) -> std::result::Result<(), String> {
        let req = UnblockContactRequest {
            address: address.into(),
        };
        self.contact
            .unblock_contact(req)
            .await
            .map(|_| ())
            .map_err(map_status)
    }

    pub async fn list_contacts(
        &mut self,
    ) -> std::result::Result<ListContactsResponse, String> {
        let req = ListContactsRequest {};
        self.contact
            .list_contacts(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    // -----------------------------------------------------------------------
    // Node service
    // -----------------------------------------------------------------------

    pub async fn get_status(
        &mut self,
    ) -> std::result::Result<NodeStatusResponse, String> {
        let req = GetStatusRequest {};
        self.node
            .get_status(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    pub async fn list_peers(
        &mut self,
    ) -> std::result::Result<ListPeersResponse, String> {
        let req = ListPeersRequest {};
        self.node
            .list_peers(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    pub async fn shutdown(&mut self) -> std::result::Result<(), String> {
        let req = ShutdownRequest {};
        self.node
            .shutdown(req)
            .await
            .map(|_| ())
            .map_err(map_status)
    }

    pub async fn inject_message(
        &mut self,
        canonical_message: Vec<u8>,
        signature: Vec<u8>,
        sender_pubkey: Vec<u8>,
    ) -> std::result::Result<InjectMessageResponse, String> {
        let req = InjectMessageRequest {
            canonical_message,
            signature,
            sender_pubkey,
        };
        self.node
            .inject_message(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    // -----------------------------------------------------------------------
    // Profile service
    // -----------------------------------------------------------------------

    pub async fn get_profile(
        &mut self,
        address: &str,
    ) -> std::result::Result<GetProfileResponse, String> {
        let req = GetProfileRequest {
            address: address.into(),
        };
        self.profile
            .get_profile(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    pub async fn update_profile(
        &mut self,
        name: &str,
        bio: &str,
        avatar: Vec<u8>,
        remove_avatar: bool,
    ) -> std::result::Result<UpdateProfileResponse, String> {
        let req = UpdateProfileRequest {
            name: name.into(),
            bio: bio.into(),
            avatar,
            remove_avatar,
        };
        self.profile
            .update_profile(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }

    pub async fn get_avatar(
        &mut self,
        cid: &str,
    ) -> std::result::Result<GetAvatarResponse, String> {
        let req = GetAvatarRequest {
            cid: cid.into(),
        };
        self.profile
            .get_avatar(req)
            .await
            .map(|r| r.into_inner())
            .map_err(map_status)
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Maps a `tonic::Status` to a user-friendly error string.
fn map_status(status: tonic::Status) -> String {
    let code = status.code();
    let msg = status.message();

    match code {
        tonic::Code::Unavailable => {
            format!("node unavailable — is the Bitevachat node running? ({msg})")
        }
        tonic::Code::DeadlineExceeded => {
            format!("request timed out ({msg})")
        }
        tonic::Code::NotFound => {
            format!("not found: {msg}")
        }
        tonic::Code::InvalidArgument => {
            format!("invalid argument: {msg}")
        }
        tonic::Code::PermissionDenied => {
            format!("permission denied: {msg}")
        }
        tonic::Code::Internal => {
            format!("internal node error: {msg}")
        }
        tonic::Code::Unimplemented => {
            format!("not implemented by this node version ({msg})")
        }
        _ => {
            format!("RPC error [{code}]: {msg}")
        }
    }
}