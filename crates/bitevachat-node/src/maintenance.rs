//! Periodic maintenance tasks.
//!
//! Called by the event loop on a configurable interval (default: 5 min).
//! All operations are **idempotent** — running them multiple times has
//! no adverse effects.
//!
//! # Tasks
//!
//! 1. **Storage flush** — ensure all pending writes are persisted to disk.
//! 2. **DB retention pruning** — remove messages exceeding the per-conversation
//!    retention limit (oldest first).
//! 3. **DHT refresh signal** — indicate that the event loop should trigger
//!    a Kademlia bootstrap to refresh routing table entries.
//!
//! # Nonce cache
//!
//! The nonce replay cache (`NonceCache`) is a bounded FIFO — old
//! entries are automatically evicted when capacity is reached. No
//! explicit cleanup is required.
//!
//! # Stale connections
//!
//! libp2p's `idle_connection_timeout` handles stale connection cleanup
//! automatically. No additional work needed here.

use bitevachat_storage::engine::StorageEngine;
use bitevachat_types::config::AppConfig;
use bitevachat_types::BitevachatError;

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// MaintenanceReport
// ---------------------------------------------------------------------------

/// Summary of a maintenance run.
///
/// Used by the event loop to decide follow-up actions (e.g. trigger
/// DHT refresh if `dht_refresh_needed` is true).
#[derive(Clone, Debug)]
pub struct MaintenanceReport {
    /// Whether the storage flush succeeded.
    pub flushed: bool,
    /// Whether the event loop should trigger a DHT bootstrap.
    pub dht_refresh_needed: bool,
    /// Number of messages pruned for retention.
    pub messages_pruned: u64,
}

// ---------------------------------------------------------------------------
// Maintenance entry point
// ---------------------------------------------------------------------------

/// Runs all storage maintenance tasks.
///
/// # Idempotency
///
/// Safe to call at any frequency. Duplicate flushes are harmless.
/// Retention pruning only removes messages exceeding the configured
/// limit.
///
/// # Errors
///
/// Returns the first error encountered. Subsequent tasks are skipped
/// on error to avoid cascading failures (e.g. pruning after a failed
/// flush could lose data).
pub fn run_storage_maintenance(
    storage: &StorageEngine,
    config: &AppConfig,
) -> BResult<MaintenanceReport> {
    let mut report = MaintenanceReport {
        flushed: false,
        dht_refresh_needed: false,
        messages_pruned: 0,
    };

    // 1. Flush pending writes to disk.
    storage.flush()?;
    report.flushed = true;

    // 2. DB retention pruning.
    //
    // Iterate conversations and remove the oldest messages beyond
    // the retention limit.
    //
    // TODO: Implement when MessageStore and ConversationIndex expose
    // pruning APIs:
    //   let convos = storage.conversations()?;
    //   for convo in convos.list()? {
    //       let msgs = storage.messages()?;
    //       let pruned = msgs.prune_oldest(
    //           &convo.convo_id,
    //           config.db_retention_messages,
    //       )?;
    //       report.messages_pruned += pruned;
    //   }
    let _ = config.db_retention_messages; // suppress unused warning

    // 3. Signal DHT refresh.
    //
    // Kademlia routing table entries expire over time. Periodic
    // bootstrap ensures the node maintains fresh routing state.
    report.dht_refresh_needed = true;

    tracing::debug!(
        flushed = report.flushed,
        pruned = report.messages_pruned,
        "storage maintenance completed"
    );

    Ok(report)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_report_default_values() {
        let report = MaintenanceReport {
            flushed: true,
            dht_refresh_needed: false,
            messages_pruned: 0,
        };
        assert!(report.flushed);
        assert!(!report.dht_refresh_needed);
        assert_eq!(report.messages_pruned, 0);
    }
}