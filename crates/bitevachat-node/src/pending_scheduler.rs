//! Periodic scheduler for retrying pending messages.
//!
//! The [`PendingScheduler`] is driven by the node event loop — it
//! does NOT run its own loop or spawn tasks. On each tick:
//!
//! 1. Purge expired entries (TTL exceeded).
//! 2. Dequeue entries whose backoff period has elapsed.
//! 3. Return the ready entries to the event loop for delivery.
//!
//! The event loop handles actual network delivery and calls
//! `PendingQueue::mark_delivered` / `mark_failed` based on the
//! outcome. This design avoids ownership conflicts (the scheduler
//! never touches the swarm) and keeps all mutable state in the
//! event loop.
//!
//! # Backoff
//!
//! Exponential: `min(2^retry_count minutes, cap)`.
//! Sequence: 1m, 2m, 4m, 8m, 16m, 32m, 60m (cap), 60m, …
//!
//! See [`bitevachat_storage::pending::compute_backoff_secs`] for the
//! implementation.

use std::sync::Arc;

use bitevachat_storage::pending::{PendingEntry, PendingQueue};
use bitevachat_types::{BitevachatError, Timestamp};

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// PendingScheduler
// ---------------------------------------------------------------------------

/// Scheduler for pending message delivery retries.
///
/// Holds a shared reference to the [`PendingQueue`] and the TTL
/// configuration. Created once by the event loop and called on
/// each pending tick interval.
pub struct PendingScheduler {
    /// Shared pending queue (thread-safe via internal `Mutex`).
    queue: Arc<PendingQueue>,
    /// TTL for pending entries in days.
    ttl_days: u64,
}

impl PendingScheduler {
    /// Creates a new scheduler.
    ///
    /// # Parameters
    ///
    /// - `queue` — shared pending queue.
    /// - `ttl_days` — message TTL in days. Entries older than this
    ///   are purged on each tick.
    pub fn new(queue: Arc<PendingQueue>, ttl_days: u64) -> Self {
        Self { queue, ttl_days }
    }

    /// Executes a single scheduler tick.
    ///
    /// # Steps
    ///
    /// 1. Purge expired entries (age > TTL).
    /// 2. Dequeue entries whose backoff has elapsed.
    /// 3. Return the ready entries.
    ///
    /// The caller is responsible for attempting delivery and calling
    /// `mark_delivered` / `mark_failed` on the pending queue.
    ///
    /// # Errors
    ///
    /// Returns `BitevachatError::StorageError` if the pending queue
    /// lock is poisoned or file persistence fails.
    pub fn tick(&self) -> BResult<Vec<PendingEntry>> {
        let now = Timestamp::now();

        // 1. Purge expired entries.
        let purged = self.queue.purge_expired(self.ttl_days, &now)?;
        if purged > 0 {
            tracing::info!(
                purged,
                ttl_days = self.ttl_days,
                "pending scheduler: purged expired entries"
            );
        }

        // 2. Dequeue ready entries.
        let ready = self.queue.dequeue_ready(&now)?;

        if !ready.is_empty() {
            tracing::debug!(
                ready = ready.len(),
                "pending scheduler: entries ready for retry"
            );
        }

        Ok(ready)
    }

    /// Returns the current total number of pending entries.
    pub fn pending_count(&self) -> BResult<usize> {
        self.queue.total_count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_struct_is_constructible() {
        // PendingScheduler requires a real PendingQueue backed by a
        // temp file. Full behavior tests live in integration tests.
        // This test verifies the public API surface compiles.
        fn _assert_send<T: Send>() {}
        // PendingScheduler is Send because Arc<PendingQueue> is Send.
        _assert_send::<PendingScheduler>();
    }
}