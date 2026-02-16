//! Hole-punching and connection fallback chain.
//!
//! Integrates libp2p DCUtR (Direct Connection Upgrade through Relay)
//! and defines the ordered fallback strategy for reaching peers
//! behind NATs.
//!
//! # Fallback order
//!
//! 1. **Direct dial** — try direct TCP/QUIC connection (skipped in
//!    relay-only mode).
//! 2. **DCUtR hole punch** — dial via relay, then DCUtR automatically
//!    upgrades to a direct connection if possible.
//! 3. **Relay** — remain on the relay circuit if hole punch fails.
//! 4. **TURN** — TURN fallback (stub, not yet implemented).
//!
//! DCUtR is integrated into the swarm as a `NetworkBehaviour`. When
//! a connection is established through a relay, DCUtR automatically
//! attempts to upgrade it to a direct connection. No explicit call
//! is needed — the behaviour handles it internally.

use libp2p::dcutr;
use libp2p::PeerId;

// ---------------------------------------------------------------------------
// ConnectionStrategy
// ---------------------------------------------------------------------------

/// Strategy for reaching a remote peer.
///
/// Used by the routing layer to track which strategies have been
/// attempted and determine the next fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionStrategy {
    /// Direct TCP/QUIC connection to the peer's address.
    Direct,
    /// Connect via relay circuit (DCUtR will attempt upgrade).
    RelayCircuit,
    /// TURN server relay (stub — always fails).
    Turn,
}

impl std::fmt::Display for ConnectionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::RelayCircuit => write!(f, "RelayCircuit"),
            Self::Turn => write!(f, "Turn"),
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackChain
// ---------------------------------------------------------------------------

/// Ordered sequence of connection strategies to attempt.
///
/// The chain is constructed based on the node's configuration
/// (relay-only mode, TURN enabled, etc.) and tracks which
/// strategies have been attempted for a given peer.
#[derive(Clone, Debug)]
pub struct FallbackChain {
    /// Ordered list of strategies to try.
    strategies: Vec<ConnectionStrategy>,
    /// Index of the next strategy to attempt.
    current_index: usize,
}

impl FallbackChain {
    /// Creates a fallback chain based on configuration.
    ///
    /// # Parameters
    ///
    /// - `relay_only` — if true, skip direct dial.
    /// - `enable_turn` — if true, include TURN as final fallback.
    pub fn new(relay_only: bool, enable_turn: bool) -> Self {
        let mut strategies = Vec::with_capacity(3);

        if !relay_only {
            strategies.push(ConnectionStrategy::Direct);
        }

        strategies.push(ConnectionStrategy::RelayCircuit);

        if enable_turn {
            strategies.push(ConnectionStrategy::Turn);
        }

        Self {
            strategies,
            current_index: 0,
        }
    }

    /// Returns the next strategy to attempt, or `None` if all
    /// strategies have been exhausted.
    pub fn next_strategy(&mut self) -> Option<&ConnectionStrategy> {
        if self.current_index < self.strategies.len() {
            let strategy = &self.strategies[self.current_index];
            self.current_index += 1;
            Some(strategy)
        } else {
            None
        }
    }

    /// Returns the current strategy without advancing.
    pub fn peek(&self) -> Option<&ConnectionStrategy> {
        self.strategies.get(self.current_index)
    }

    /// Returns whether all strategies have been exhausted.
    pub fn exhausted(&self) -> bool {
        self.current_index >= self.strategies.len()
    }

    /// Resets the chain to the beginning.
    pub fn reset(&mut self) {
        self.current_index = 0;
    }

    /// Returns the total number of strategies in the chain.
    pub fn len(&self) -> usize {
        self.strategies.len()
    }

    /// Returns whether the chain has no strategies.
    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DCUtR event logging
// ---------------------------------------------------------------------------

/// Logs DCUtR events at appropriate levels.
///
/// In libp2p 0.54, `dcutr::Event` is a struct with fields:
/// - `remote_peer_id: PeerId`
/// - `connection_id: ConnectionId`
/// - `result: Result<ConnectionId, UpgradeError>`
///
/// Returns `Some(peer_id)` if a direct connection upgrade succeeded,
/// `None` otherwise.
pub fn handle_dcutr_event(event: dcutr::Event) -> Option<PeerId> {
    let remote_peer_id = event.remote_peer_id;

    match event.result {
        Ok(direct_conn_id) => {
            tracing::info!(
                %remote_peer_id,
                ?direct_conn_id,
                "DCUtR: direct connection upgrade succeeded (hole punch)"
            );
            Some(remote_peer_id)
        }
        Err(error) => {
            tracing::warn!(
                %remote_peer_id,
                ?error,
                "DCUtR: direct connection upgrade failed"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_chain_full() {
        let mut chain = FallbackChain::new(false, true);
        assert_eq!(chain.len(), 3);
        assert!(!chain.exhausted());

        assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Direct));
        assert_eq!(
            chain.next_strategy(),
            Some(&ConnectionStrategy::RelayCircuit)
        );
        assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Turn));
        assert!(chain.next_strategy().is_none());
        assert!(chain.exhausted());
    }

    #[test]
    fn fallback_chain_relay_only() {
        let mut chain = FallbackChain::new(true, false);
        assert_eq!(chain.len(), 1);

        assert_eq!(
            chain.next_strategy(),
            Some(&ConnectionStrategy::RelayCircuit)
        );
        assert!(chain.next_strategy().is_none());
        assert!(chain.exhausted());
    }

    #[test]
    fn fallback_chain_relay_only_with_turn() {
        let mut chain = FallbackChain::new(true, true);
        assert_eq!(chain.len(), 2);

        assert_eq!(
            chain.next_strategy(),
            Some(&ConnectionStrategy::RelayCircuit)
        );
        assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Turn));
        assert!(chain.exhausted());
    }

    #[test]
    fn fallback_chain_default_no_turn() {
        let mut chain = FallbackChain::new(false, false);
        assert_eq!(chain.len(), 2);

        assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Direct));
        assert_eq!(
            chain.next_strategy(),
            Some(&ConnectionStrategy::RelayCircuit)
        );
        assert!(chain.exhausted());
    }

    #[test]
    fn fallback_chain_reset() {
        let mut chain = FallbackChain::new(false, false);
        chain.next_strategy();
        chain.next_strategy();
        assert!(chain.exhausted());

        chain.reset();
        assert!(!chain.exhausted());
        assert_eq!(chain.next_strategy(), Some(&ConnectionStrategy::Direct));
    }

    #[test]
    fn fallback_chain_peek() {
        let chain = FallbackChain::new(false, false);
        assert_eq!(chain.peek(), Some(&ConnectionStrategy::Direct));
    }

    #[test]
    fn connection_strategy_display() {
        assert_eq!(format!("{}", ConnectionStrategy::Direct), "Direct");
        assert_eq!(format!("{}", ConnectionStrategy::RelayCircuit), "RelayCircuit");
        assert_eq!(format!("{}", ConnectionStrategy::Turn), "Turn");
    }
}