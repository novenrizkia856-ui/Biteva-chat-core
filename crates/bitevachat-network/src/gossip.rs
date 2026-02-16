//! Gossipsub wrapper for Bitevachat metadata broadcasting.
//!
//! Provides pub/sub for lightweight, non-critical updates:
//!
//! - `presence` — online/offline status broadcasts.
//! - `profile-updates` — display name, avatar hash changes.
//!
//! Messages exceeding [`MAX_GOSSIP_SIZE`] are rejected to prevent
//! gossip flooding.

use libp2p::gossipsub;
use libp2p::identity;

use bitevachat_types::{BitevachatError, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed gossip message size (64 KiB).
pub const MAX_GOSSIP_SIZE: usize = 65_536;

/// Topic name for presence broadcasts.
pub const TOPIC_PRESENCE: &str = "presence";

/// Topic name for profile update broadcasts.
pub const TOPIC_PROFILE_UPDATES: &str = "profile-updates";

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Builds a configured `gossipsub::Behaviour` with the Bitevachat
/// defaults.
///
/// # Parameters
///
/// - `keypair` — libp2p identity keypair for message signing
///   (`MessageAuthenticity::Signed`).
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if the gossipsub config
/// is invalid (should not happen with hardcoded values).
pub fn build_gossip_behaviour(
    keypair: &identity::Keypair,
) -> Result<gossipsub::Behaviour> {
    let config = gossipsub::ConfigBuilder::default()
        .max_transmit_size(MAX_GOSSIP_SIZE)
        .validate_messages()
        .build()
        .map_err(|e| BitevachatError::NetworkError {
            reason: format!("failed to build gossipsub config: {e}"),
        })?;

    let behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        config,
    )
    .map_err(|e| BitevachatError::NetworkError {
        reason: format!("failed to create gossipsub behaviour: {e}"),
    })?;

    Ok(behaviour)
}

// ---------------------------------------------------------------------------
// Topic helpers
// ---------------------------------------------------------------------------

/// Creates a gossipsub [`IdentTopic`] from a topic string.
pub fn topic(name: &str) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(name)
}

/// Subscribes the behaviour to the default Bitevachat topics
/// (`presence`, `profile-updates`).
///
/// # Errors
///
/// Returns `BitevachatError::NetworkError` if subscription fails.
pub fn subscribe_default_topics(
    behaviour: &mut gossipsub::Behaviour,
) -> Result<()> {
    let topics = [TOPIC_PRESENCE, TOPIC_PROFILE_UPDATES];

    for name in &topics {
        let t = topic(name);
        behaviour.subscribe(&t).map_err(|e| {
            BitevachatError::NetworkError {
                reason: format!("failed to subscribe to topic '{name}': {e}"),
            }
        })?;
    }

    Ok(())
}

/// Publishes data to a gossip topic.
///
/// # Errors
///
/// - [`BitevachatError::NetworkError`] if the data exceeds
///   [`MAX_GOSSIP_SIZE`] or publishing fails.
pub fn publish_metadata(
    behaviour: &mut gossipsub::Behaviour,
    topic_name: &str,
    data: Vec<u8>,
) -> Result<()> {
    if data.len() > MAX_GOSSIP_SIZE {
        return Err(BitevachatError::NetworkError {
            reason: format!(
                "gossip payload size {} exceeds maximum {}",
                data.len(),
                MAX_GOSSIP_SIZE,
            ),
        });
    }

    let t = topic(topic_name);
    behaviour.publish(t, data).map_err(|e| {
        BitevachatError::NetworkError {
            reason: format!("failed to publish to topic '{topic_name}': {e}"),
        }
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_gossip_behaviour_succeeds() {
        let keypair = identity::Keypair::generate_ed25519();
        let result = build_gossip_behaviour(&keypair);
        assert!(result.is_ok());
    }

    #[test]
    fn topic_creation() {
        let t = topic(TOPIC_PRESENCE);
        let hash = t.hash();
        assert!(!hash.as_str().is_empty());
    }

    #[test]
    fn subscribe_default_topics_succeeds() {
        let keypair = identity::Keypair::generate_ed25519();
        let mut behaviour = build_gossip_behaviour(&keypair).unwrap();
        let result = subscribe_default_topics(&mut behaviour);
        assert!(result.is_ok());
    }

    #[test]
    fn oversized_payload_rejected() {
        let keypair = identity::Keypair::generate_ed25519();
        let mut behaviour = build_gossip_behaviour(&keypair).unwrap();
        let _ = subscribe_default_topics(&mut behaviour);

        let big_data = vec![0u8; MAX_GOSSIP_SIZE + 1];
        let result = publish_metadata(&mut behaviour, TOPIC_PRESENCE, big_data);
        assert!(result.is_err());
    }
}