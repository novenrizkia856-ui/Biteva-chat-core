//! RPC server configuration.
//!
//! Defaults to Unix socket mode with restrictive permissions.
//! Remote mode is **off by default** and requires explicit mTLS
//! and API token configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use bitevachat_types::{BitevachatError, Result};

// ---------------------------------------------------------------------------
// RpcMode
// ---------------------------------------------------------------------------

/// Bind mode for the RPC server.
#[derive(Clone, Debug)]
pub enum RpcMode {
    /// Unix domain socket (Linux/macOS). Default and preferred.
    ///
    /// The socket file is created with `0600` permissions, restricting
    /// access to the owning user. No authentication is required for
    /// connections over Unix sockets (local trust boundary).
    #[cfg(unix)]
    UnixSocket {
        /// Path to the socket file (e.g. `/tmp/bitevachat.sock`).
        path: PathBuf,
    },

    /// Localhost TCP (Windows fallback or explicit choice).
    ///
    /// Binds to `127.0.0.1` only. No authentication is required
    /// for loopback connections.
    LocalTcp {
        /// Bind address (must be a loopback address).
        addr: SocketAddr,
    },

    /// Remote TCP with mandatory mTLS and API token.
    ///
    /// This mode is **disabled by default**. Enabling it requires
    /// all TLS fields and `api_token` to be set.
    Remote {
        /// Bind address (e.g. `0.0.0.0:9090`).
        addr: SocketAddr,
        /// Path to the server TLS certificate (PEM).
        tls_cert_path: PathBuf,
        /// Path to the server TLS private key (PEM).
        tls_key_path: PathBuf,
        /// Path to the CA certificate for client verification (PEM).
        tls_ca_cert_path: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// RpcConfig
// ---------------------------------------------------------------------------

/// Configuration for the RPC server.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Bind mode.
    pub mode: RpcMode,

    /// API token required for remote mode.
    ///
    /// Compared in constant time. Must be non-empty when mode is
    /// `Remote`.
    pub api_token: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            #[cfg(unix)]
            mode: RpcMode::UnixSocket {
                path: PathBuf::from("/tmp/bitevachat.sock"),
            },
            #[cfg(not(unix))]
            mode: RpcMode::LocalTcp {
                addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            },
            api_token: None,
        }
    }
}

impl RpcConfig {
    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// - Remote mode without TLS paths or API token.
    /// - Non-loopback address in `LocalTcp` mode.
    pub fn validate(&self) -> Result<()> {
        match &self.mode {
            #[cfg(unix)]
            RpcMode::UnixSocket { path } => {
                if path.as_os_str().is_empty() {
                    return Err(BitevachatError::ConfigError {
                        reason: "Unix socket path must not be empty".into(),
                    });
                }
            }

            RpcMode::LocalTcp { addr } => {
                if !addr.ip().is_loopback() {
                    return Err(BitevachatError::ConfigError {
                        reason: format!(
                            "LocalTcp mode requires a loopback address, got {}",
                            addr.ip()
                        ),
                    });
                }
            }

            RpcMode::Remote {
                tls_cert_path,
                tls_key_path,
                tls_ca_cert_path,
                ..
            } => {
                if !tls_cert_path.exists() {
                    return Err(BitevachatError::ConfigError {
                        reason: format!(
                            "TLS cert not found: {}",
                            tls_cert_path.display()
                        ),
                    });
                }
                if !tls_key_path.exists() {
                    return Err(BitevachatError::ConfigError {
                        reason: format!(
                            "TLS key not found: {}",
                            tls_key_path.display()
                        ),
                    });
                }
                if !tls_ca_cert_path.exists() {
                    return Err(BitevachatError::ConfigError {
                        reason: format!(
                            "CA cert not found: {}",
                            tls_ca_cert_path.display()
                        ),
                    });
                }
                if self.api_token.is_none() {
                    return Err(BitevachatError::ConfigError {
                        reason: "Remote mode requires an API token".into(),
                    });
                }
                if let Some(ref token) = self.api_token {
                    if token.is_empty() {
                        return Err(BitevachatError::ConfigError {
                            reason: "API token must not be empty".into(),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}