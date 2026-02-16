//! RPC server entry point.
//!
//! [`RpcServer::start`] spawns the gRPC server as a tokio task and
//! returns a `JoinHandle` for the caller to await. The server listens
//! on the configured transport (Unix socket, localhost TCP, or remote
//! mTLS TCP) and registers all three service implementations with the
//! appropriate [`AuthInterceptor`].
//!
//! # Graceful shutdown
//!
//! The server accepts a `tokio::sync::watch::Receiver<bool>` that
//! signals shutdown. When the watch value becomes `true`, the server
//! stops accepting new connections and drains in-flight requests.
//!
//! # Design note: no `build_router` helper
//!
//! Service registration is inlined at each call site to avoid naming
//! the tonic `Router<L>` type, whose generic parameter changes with
//! each `.add_service()` call and varies across tonic versions.

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tonic::transport::Server;

use bitevachat_node::NodeCommand;
use bitevachat_types::BitevachatError;

use crate::auth::AuthInterceptor;
use crate::config::{RpcConfig, RpcMode};
use crate::contact_service::ContactServiceImpl;
use crate::message_service::MessageServiceImpl;
use crate::node_service::NodeServiceImpl;
use crate::proto;

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Shutdown helper
// ---------------------------------------------------------------------------

/// Returns a future that resolves when the shutdown watch fires.
async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    loop {
        if rx.changed().await.is_err() {
            break;
        }
        if *rx.borrow() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Service registration macro
// ---------------------------------------------------------------------------

/// Registers all three gRPC services on a server builder.
///
/// Uses a macro to avoid naming the `Router<L>` return type, which
/// has complex generics that change across tonic versions.
macro_rules! register_services {
    ($builder:expr, $interceptor:expr, $command_tx:expr) => {{
        let message_svc = MessageServiceImpl::new($command_tx.clone());
        let contact_svc = ContactServiceImpl::new($command_tx.clone());
        let node_svc = NodeServiceImpl::new($command_tx);

        let message_server =
            proto::message_service_server::MessageServiceServer::with_interceptor(
                message_svc,
                $interceptor.clone(),
            );
        let contact_server =
            proto::contact_service_server::ContactServiceServer::with_interceptor(
                contact_svc,
                $interceptor.clone(),
            );
        let node_server =
            proto::node_service_server::NodeServiceServer::with_interceptor(
                node_svc,
                $interceptor,
            );

        $builder
            .add_service(message_server)
            .add_service(contact_server)
            .add_service(node_server)
    }};
}

// ---------------------------------------------------------------------------
// RpcServer
// ---------------------------------------------------------------------------

/// Manages the lifecycle of the gRPC server.
pub struct RpcServer;

impl RpcServer {
    /// Starts the RPC server and returns a `JoinHandle`.
    ///
    /// The server registers `MessageService`, `ContactService`, and
    /// `NodeService` with an `AuthInterceptor` matching the
    /// configured mode.
    ///
    /// # Parameters
    ///
    /// - `config` — RPC configuration (bind mode, API token).
    /// - `command_tx` — node command channel sender (cloned per service).
    /// - `shutdown_rx` — watch channel that signals shutdown.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::ConfigError` if config validation
    /// fails, or `BitevachatError::NetworkError` if the server
    /// cannot bind.
    pub async fn start(
        config: RpcConfig,
        command_tx: mpsc::Sender<NodeCommand>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> BResult<JoinHandle<()>> {
        config.validate()?;

        match config.mode.clone() {
            #[cfg(unix)]
            RpcMode::UnixSocket { path } => {
                start_unix_socket(path, command_tx, shutdown_rx).await
            }

            RpcMode::LocalTcp { addr } => {
                start_tcp(addr, command_tx, shutdown_rx).await
            }

            RpcMode::Remote {
                addr,
                tls_cert_path,
                tls_key_path,
                tls_ca_cert_path,
            } => {
                let token = config.api_token.as_deref().unwrap_or("");
                start_remote_tls(
                    addr,
                    tls_cert_path,
                    tls_key_path,
                    tls_ca_cert_path,
                    token,
                    command_tx,
                    shutdown_rx,
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unix socket transport
// ---------------------------------------------------------------------------

/// Starts the server on a Unix domain socket with restrictive permissions.
#[cfg(unix)]
async fn start_unix_socket(
    path: std::path::PathBuf,
    command_tx: mpsc::Sender<NodeCommand>,
    shutdown_rx: watch::Receiver<bool>,
) -> BResult<JoinHandle<()>> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    // Remove stale socket file if it exists.
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| BitevachatError::NetworkError {
            reason: format!("failed to remove stale socket '{}': {e}", path.display()),
        })?;
    }

    // Bind the Unix listener.
    let listener = UnixListener::bind(&path).map_err(|e| {
        BitevachatError::NetworkError {
            reason: format!("failed to bind Unix socket '{}': {e}", path.display()),
        }
    })?;

    // Set restrictive permissions (owner read/write only).
    std::fs::set_permissions(
        &path,
        std::fs::Permissions::from_mode(0o600),
    )
    .map_err(|e| BitevachatError::NetworkError {
        reason: format!(
            "failed to set socket permissions on '{}': {e}",
            path.display()
        ),
    })?;

    tracing::info!(path = %path.display(), "RPC server listening on Unix socket");

    let interceptor = AuthInterceptor::local();
    let stream = UnixListenerStream::new(listener);
    let router = register_services!(Server::builder(), interceptor, command_tx);

    let socket_path = path.clone();
    let handle = tokio::spawn(async move {
        let result = router
            .serve_with_incoming_shutdown(stream, wait_for_shutdown(shutdown_rx))
            .await;

        if let Err(e) = result {
            tracing::error!(%e, "RPC server error");
        }

        // Clean up socket file.
        let _ = std::fs::remove_file(&socket_path);
        tracing::info!("RPC server (Unix socket) stopped");
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Localhost TCP transport
// ---------------------------------------------------------------------------

/// Starts the server on a loopback TCP address (no TLS).
async fn start_tcp(
    addr: std::net::SocketAddr,
    command_tx: mpsc::Sender<NodeCommand>,
    shutdown_rx: watch::Receiver<bool>,
) -> BResult<JoinHandle<()>> {
    tracing::info!(%addr, "RPC server listening on TCP");

    let interceptor = AuthInterceptor::local();
    let router = register_services!(Server::builder(), interceptor, command_tx);

    let handle = tokio::spawn(async move {
        let result = router
            .serve_with_shutdown(addr, wait_for_shutdown(shutdown_rx))
            .await;

        if let Err(e) = result {
            tracing::error!(%e, "RPC server error");
        }

        tracing::info!("RPC server (TCP) stopped");
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Remote mTLS TCP transport
// ---------------------------------------------------------------------------

/// Starts the server on a remote TCP address with mTLS.
async fn start_remote_tls(
    addr: std::net::SocketAddr,
    tls_cert_path: std::path::PathBuf,
    tls_key_path: std::path::PathBuf,
    tls_ca_cert_path: std::path::PathBuf,
    api_token: &str,
    command_tx: mpsc::Sender<NodeCommand>,
    shutdown_rx: watch::Receiver<bool>,
) -> BResult<JoinHandle<()>> {
    use tonic::transport::{Certificate, Identity, ServerTlsConfig};

    // Read TLS files.
    let cert_pem = std::fs::read(&tls_cert_path).map_err(|e| {
        BitevachatError::ConfigError {
            reason: format!(
                "failed to read TLS cert '{}': {e}",
                tls_cert_path.display()
            ),
        }
    })?;
    let key_pem = std::fs::read(&tls_key_path).map_err(|e| {
        BitevachatError::ConfigError {
            reason: format!(
                "failed to read TLS key '{}': {e}",
                tls_key_path.display()
            ),
        }
    })?;
    let ca_pem = std::fs::read(&tls_ca_cert_path).map_err(|e| {
        BitevachatError::ConfigError {
            reason: format!(
                "failed to read CA cert '{}': {e}",
                tls_ca_cert_path.display()
            ),
        }
    })?;

    let identity = Identity::from_pem(cert_pem, key_pem);
    let ca_certificate = Certificate::from_pem(ca_pem);

    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_certificate);

    tracing::info!(%addr, "RPC server listening on remote TCP with mTLS");

    // Build TLS-enabled server, then register services.
    let mut tls_builder = Server::builder()
        .tls_config(tls_config)
        .map_err(|e| BitevachatError::ConfigError {
            reason: format!("TLS configuration error: {e}"),
        })?;

    let interceptor = AuthInterceptor::remote(api_token);
    let router = register_services!(tls_builder, interceptor, command_tx);

    let handle = tokio::spawn(async move {
        let result = router
            .serve_with_shutdown(addr, wait_for_shutdown(shutdown_rx))
            .await;

        if let Err(e) = result {
            tracing::error!(%e, "RPC server (remote TLS) error");
        }

        tracing::info!("RPC server (remote TLS) stopped");
    });

    Ok(handle)
}