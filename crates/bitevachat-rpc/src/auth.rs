//! Authentication interceptor for the RPC server.
//!
//! # Modes
//!
//! - **Local** (Unix socket / localhost TCP): all requests allowed.
//!   The transport itself enforces access control (Unix socket
//!   permissions, loopback-only binding).
//!
//! - **Remote** (mTLS TCP): mTLS handles mutual authentication at the
//!   TLS layer. The interceptor additionally validates a bearer API
//!   token in the `authorization` metadata header using **constant-time
//!   comparison** to prevent timing side-channels.
//!
//! # Security notes
//!
//! - mTLS certificate validation is handled by tonic's `ServerTlsConfig`
//!   at the transport layer, NOT in this interceptor.
//! - The API token is stored as raw bytes to avoid string comparison
//!   optimizations that could leak timing information.

use std::sync::Arc;

use tonic::{Request, Status};

// ---------------------------------------------------------------------------
// AuthMode
// ---------------------------------------------------------------------------

/// Determines which authentication checks the interceptor performs.
#[derive(Clone, Debug)]
pub enum AuthMode {
    /// Local mode: no token required.
    Local,
    /// Remote mode: API token required in `authorization` metadata.
    Remote,
}

// ---------------------------------------------------------------------------
// AuthInterceptor
// ---------------------------------------------------------------------------

/// gRPC interceptor that validates API tokens for remote connections.
///
/// Implements `tonic::service::Interceptor` and is cloneable so it
/// can be shared across multiple service registrations.
#[derive(Clone)]
pub struct AuthInterceptor {
    /// Authentication mode.
    mode: AuthMode,
    /// API token bytes (for constant-time comparison).
    /// `None` in local mode; `Some` in remote mode.
    api_token_bytes: Option<Arc<Vec<u8>>>,
}

impl AuthInterceptor {
    /// Creates a local-mode interceptor (no token required).
    pub fn local() -> Self {
        Self {
            mode: AuthMode::Local,
            api_token_bytes: None,
        }
    }

    /// Creates a remote-mode interceptor with the given API token.
    ///
    /// The token is stored as bytes for constant-time comparison.
    pub fn remote(api_token: &str) -> Self {
        Self {
            mode: AuthMode::Remote,
            api_token_bytes: Some(Arc::new(api_token.as_bytes().to_vec())),
        }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> std::result::Result<Request<()>, Status> {
        match self.mode {
            AuthMode::Local => {
                // Local mode — transport enforces access control.
                Ok(request)
            }
            AuthMode::Remote => {
                // Remote mode — require API token.
                let expected = match &self.api_token_bytes {
                    Some(bytes) => bytes,
                    None => {
                        // Defensive: remote mode without token is a config error.
                        return Err(Status::internal(
                            "remote auth enabled but no token configured",
                        ));
                    }
                };

                let header_value = request
                    .metadata()
                    .get("authorization")
                    .ok_or_else(|| {
                        Status::unauthenticated("missing authorization header")
                    })?;

                let provided = header_value.as_bytes();

                // Strip optional "Bearer " prefix.
                let token_bytes = if provided.len() > 7
                    && provided[..7].eq_ignore_ascii_case(b"Bearer ")
                {
                    &provided[7..]
                } else {
                    provided
                };

                if !constant_time_eq(token_bytes, expected) {
                    return Err(Status::unauthenticated("invalid API token"));
                }

                Ok(request)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compares two byte slices in constant time.
///
/// Returns `true` if and only if `a` and `b` are equal in both
/// length and content. The comparison time depends only on the
/// lengths, not on the content, preventing timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::service::Interceptor;

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn local_interceptor_allows_all() {
        let mut interceptor = AuthInterceptor::local();
        let request = Request::new(());
        assert!(interceptor.call(request).is_ok());
    }

    #[test]
    fn remote_interceptor_rejects_missing_header() {
        let mut interceptor = AuthInterceptor::remote("secret-token");
        let request = Request::new(());
        let result = interceptor.call(request);
        assert!(result.is_err());
    }

    #[test]
    fn remote_interceptor_accepts_valid_token() {
        let mut interceptor = AuthInterceptor::remote("my-secret");
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "my-secret".parse().unwrap());
        assert!(interceptor.call(request).is_ok());
    }

    #[test]
    fn remote_interceptor_accepts_bearer_prefix() {
        let mut interceptor = AuthInterceptor::remote("my-secret");
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer my-secret".parse().unwrap());
        assert!(interceptor.call(request).is_ok());
    }

    #[test]
    fn remote_interceptor_rejects_wrong_token() {
        let mut interceptor = AuthInterceptor::remote("correct");
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "wrong".parse().unwrap());
        let result = interceptor.call(request);
        assert!(result.is_err());
    }
}