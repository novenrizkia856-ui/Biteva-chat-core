//! NAT status detection via libp2p AutoNAT.
//!
//! Wraps `libp2p::autonat::Behaviour` event processing into a
//! simple [`NatManager`] that tracks the current [`NatStatus`] and
//! discovered external address.
//!
//! # Design
//!
//! AutoNAT probes connected peers to determine if the local node
//! is publicly reachable. The result is mapped to our own
//! [`NatStatus`] enum which avoids leaking libp2p-internal types
//! to higher layers.

use libp2p::autonat;
use libp2p::Multiaddr;

// ---------------------------------------------------------------------------
// NatStatus
// ---------------------------------------------------------------------------

/// Observed NAT status of the local node.
///
/// Derived from `libp2p::autonat::NatStatus` but decoupled from
/// libp2p internals so higher layers need not depend on libp2p.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatStatus {
    /// Node is publicly reachable at the given address.
    Public,
    /// Node is behind a NAT/firewall and not directly reachable.
    BehindNat,
    /// NAT status has not been determined yet.
    Unknown,
}

impl std::fmt::Display for NatStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::BehindNat => write!(f, "BehindNat"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// NatManager
// ---------------------------------------------------------------------------

/// Manages NAT status detection state.
///
/// Processes `autonat::Event`s emitted by the swarm and exposes
/// the current status and external address.
pub struct NatManager {
    /// Current observed NAT status.
    current_status: NatStatus,
    /// Discovered external address (only set when `Public`).
    external_addr: Option<Multiaddr>,
}

impl NatManager {
    /// Creates a new `NatManager` with `Unknown` status.
    pub fn new() -> Self {
        Self {
            current_status: NatStatus::Unknown,
            external_addr: None,
        }
    }

    /// Returns the current NAT status.
    pub fn current_status(&self) -> &NatStatus {
        &self.current_status
    }

    /// Returns the discovered external address, if any.
    ///
    /// Only `Some` when status is [`NatStatus::Public`].
    pub fn external_address(&self) -> Option<&Multiaddr> {
        self.external_addr.as_ref()
    }

    /// Processes an AutoNAT event and returns `Some(new_status)` if
    /// the NAT status changed, `None` otherwise.
    pub fn on_autonat_event(&mut self, event: autonat::Event) -> Option<NatStatus> {
        match event {
            autonat::Event::StatusChanged { old: _, new } => {
                let mapped = from_libp2p_status(&new);

                // Update external address.
                match &new {
                    autonat::NatStatus::Public(addr) => {
                        self.external_addr = Some(addr.clone());
                    }
                    _ => {
                        self.external_addr = None;
                    }
                }

                let changed = self.current_status != mapped;
                self.current_status = mapped.clone();

                if changed {
                    tracing::info!(
                        status = %self.current_status,
                        external_addr = ?self.external_addr,
                        "NAT status changed"
                    );
                    Some(self.current_status.clone())
                } else {
                    None
                }
            }
            autonat::Event::InboundProbe(probe) => {
                tracing::debug!(?probe, "autonat inbound probe");
                None
            }
            autonat::Event::OutboundProbe(probe) => {
                tracing::debug!(?probe, "autonat outbound probe");
                None
            }
        }
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/// Maps a libp2p `autonat::NatStatus` to our [`NatStatus`].
pub fn from_libp2p_status(status: &autonat::NatStatus) -> NatStatus {
    match status {
        autonat::NatStatus::Public(_) => NatStatus::Public,
        autonat::NatStatus::Private => NatStatus::BehindNat,
        autonat::NatStatus::Unknown => NatStatus::Unknown,
    }
}

// ---------------------------------------------------------------------------
// AutoNAT config builder
// ---------------------------------------------------------------------------

/// Builds an `autonat::Config` with Bitevachat defaults.
///
/// # Parameters
///
/// - `confidence_max` — number of confirmations before the status
///   is considered stable (default: 3).
pub fn build_autonat_config(confidence_max: usize) -> autonat::Config {
    let mut config = autonat::Config::default();
    config.confidence_max = confidence_max;
    config
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_status_is_unknown() {
        let manager = NatManager::new();
        assert_eq!(manager.current_status(), &NatStatus::Unknown);
        assert!(manager.external_address().is_none());
    }

    #[test]
    fn from_libp2p_public() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        let status = from_libp2p_status(&autonat::NatStatus::Public(addr));
        assert_eq!(status, NatStatus::Public);
    }

    #[test]
    fn from_libp2p_private() {
        let status = from_libp2p_status(&autonat::NatStatus::Private);
        assert_eq!(status, NatStatus::BehindNat);
    }

    #[test]
    fn from_libp2p_unknown() {
        let status = from_libp2p_status(&autonat::NatStatus::Unknown);
        assert_eq!(status, NatStatus::Unknown);
    }

    #[test]
    fn status_display() {
        assert_eq!(format!("{}", NatStatus::Public), "Public");
        assert_eq!(format!("{}", NatStatus::BehindNat), "BehindNat");
        assert_eq!(format!("{}", NatStatus::Unknown), "Unknown");
    }

    #[test]
    fn status_changed_event_updates_manager() {
        let mut manager = NatManager::new();
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();

        let event = autonat::Event::StatusChanged {
            old: autonat::NatStatus::Unknown,
            new: autonat::NatStatus::Public(addr.clone()),
        };

        let result = manager.on_autonat_event(event);
        assert_eq!(result, Some(NatStatus::Public));
        assert_eq!(manager.current_status(), &NatStatus::Public);
        assert_eq!(manager.external_address(), Some(&addr));
    }

    #[test]
    fn status_unchanged_returns_none() {
        let mut manager = NatManager::new();

        // First change: Unknown → Unknown (same)
        let event = autonat::Event::StatusChanged {
            old: autonat::NatStatus::Unknown,
            new: autonat::NatStatus::Unknown,
        };

        let result = manager.on_autonat_event(event);
        assert_eq!(result, None);
    }

    #[test]
    fn private_status_clears_external_addr() {
        let mut manager = NatManager::new();
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();

        // First: become Public
        let event1 = autonat::Event::StatusChanged {
            old: autonat::NatStatus::Unknown,
            new: autonat::NatStatus::Public(addr),
        };
        manager.on_autonat_event(event1);
        assert!(manager.external_address().is_some());

        // Then: become Private
        let event2 = autonat::Event::StatusChanged {
            old: autonat::NatStatus::Public("/ip4/1.2.3.4/tcp/4001".parse().unwrap()),
            new: autonat::NatStatus::Private,
        };
        manager.on_autonat_event(event2);
        assert!(manager.external_address().is_none());
        assert_eq!(manager.current_status(), &NatStatus::BehindNat);
    }

    #[test]
    fn build_autonat_config_sets_confidence() {
        let config = build_autonat_config(5);
        assert_eq!(config.confidence_max, 5);
    }
}