//! TURN client stub.
//!
//! libp2p does not provide a built-in TURN implementation. This
//! module defines the [`TurnClient`] interface and [`TurnAllocation`]
//! result type so that the routing fallback chain can reference TURN
//! as a strategy, but all operations currently return
//! `BitevachatError::NetworkError` with a "not implemented" reason.
//!
//! # Future work
//!
//! When a suitable, audited TURN crate is identified, this stub
//! will be replaced with a real implementation. Credentials MUST
//! be zeroized after use.

use bitevachat_types::BitevachatError;
use libp2p::Multiaddr;

/// Local alias to avoid shadowing `std::result::Result`.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// TurnAllocation
// ---------------------------------------------------------------------------

/// Represents a TURN relay allocation (stub).
///
/// In a real implementation this would hold the relayed transport
/// address, lifetime, and refresh handle.
#[derive(Clone, Debug)]
pub struct TurnAllocation {
    /// The relayed address assigned by the TURN server.
    pub relayed_addr: Multiaddr,
}

// ---------------------------------------------------------------------------
// TurnClient
// ---------------------------------------------------------------------------

/// TURN client wrapper (stub).
///
/// All methods return `Err(BitevachatError::NetworkError)` because
/// no production-ready TURN crate has been integrated yet.
pub struct TurnClient {
    /// TURN server URLs (stored for future use).
    _servers: Vec<String>,
}

impl TurnClient {
    /// Creates a new stub TURN client.
    ///
    /// The server list is stored but not used until a real TURN
    /// implementation is integrated.
    pub fn new(servers: Vec<String>) -> Self {
        Self { _servers: servers }
    }

    /// Attempts to allocate a TURN relay address.
    ///
    /// # Errors
    ///
    /// Always returns `BitevachatError::NetworkError` — TURN is not
    /// yet implemented.
    pub async fn allocate(&self) -> BResult<TurnAllocation> {
        Err(BitevachatError::NetworkError {
            reason: "TURN client is not yet implemented; \
                     no production-ready crate has been integrated"
                .into(),
        })
    }

    /// Returns whether this client has any configured servers.
    pub fn has_servers(&self) -> bool {
        !self._servers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allocate_returns_not_implemented() {
        let client = TurnClient::new(vec!["turn:example.com:3478".into()]);
        let result = client.allocate().await;
        assert!(result.is_err());
    }

    #[test]
    fn has_servers_with_empty_list() {
        let client = TurnClient::new(Vec::new());
        assert!(!client.has_servers());
    }

    #[test]
    fn has_servers_with_entries() {
        let client = TurnClient::new(vec!["turn:example.com:3478".into()]);
        assert!(client.has_servers());
    }
}