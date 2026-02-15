//! Periodic scheduler for retrying pending messages.
//!
//! Runs a tokio interval loop that:
//! 1. Purges expired entries.
//! 2. Dequeues ready entries.
//! 3. Attempts delivery (placeholder — network layer not implemented).
//! 4. Marks each entry as delivered or failed.
//!
//! **This module is a structural skeleton.** The actual network send
//! logic will be implemented when the network layer is built.

use std::sync::Arc;

use bitevachat_storage::pending::PendingQueue;
use bitevachat_types::{Result, Timestamp};

// ---------------------------------------------------------------------------
// PendingScheduler
// ---------------------------------------------------------------------------

/// Periodic background scheduler for pending message delivery.
///
/// Holds a shared reference to the [`PendingQueue`] and configuration
/// for TTL and tick interval.
pub struct PendingScheduler {
    /// Shared pending queue (thread-safe via internal `Mutex`).
    queue: Arc<PendingQueue>,
    /// TTL for pending entries in days.
    ttl_days: u64,
    /// Interval between scheduler ticks in seconds.
    tick_interval_secs: u64,
}

impl PendingScheduler {
    /// Creates a new scheduler.
    ///
    /// # Parameters
    ///
    /// - `queue` — shared pending queue.
    /// - `ttl_days` — message TTL in days.
    /// - `tick_interval_secs` — seconds between scheduler ticks.
    pub fn new(
        queue: Arc<PendingQueue>,
        ttl_days: u64,
        tick_interval_secs: u64,
    ) -> Self {
        Self {
            queue,
            ttl_days,
            tick_interval_secs,
        }
    }

    /// Runs the scheduler loop.
    ///
    /// This method runs indefinitely, processing pending messages at
    /// each tick. It should be spawned as a tokio task:
    ///
    /// ```ignore
    /// tokio::spawn(scheduler.run());
    /// ```
    pub async fn run(self) {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(self.tick_interval_secs),
        );

        loop {
            interval.tick().await;

            if let Err(e) = self.tick().await {
                // Log error but do not crash the scheduler.
                // TODO: integrate with structured logging when available.
                eprintln!("pending scheduler tick error: {e}");
            }
        }
    }

    /// Executes a single scheduler tick.
    ///
    /// 1. Purge expired entries.
    /// 2. Dequeue ready entries.
    /// 3. Attempt delivery for each (placeholder).
    /// 4. Mark as delivered or failed.
    async fn tick(&self) -> Result<()> {
        let now = Timestamp::now();

        // 1. Purge expired entries.
        let _purged = self.queue.purge_expired(self.ttl_days, &now)?;

        // 2. Dequeue ready entries.
        let ready = self.queue.dequeue_ready(&now)?;

        // 3+4. Attempt delivery for each ready entry.
        for entry in &ready {
            let msg_id = entry.message_id().clone();

            // TODO: Replace with actual network send when network layer
            // is implemented. The send function should take the
            // entry.envelope and attempt delivery to entry.recipient.
            let delivery_result = Self::try_send(&entry).await;

            match delivery_result {
                Ok(()) => {
                    let _ = self.queue.mark_delivered(&msg_id);
                }
                Err(_) => {
                    let fail_now = Timestamp::now();
                    let _ = self.queue.mark_failed(&msg_id, &fail_now);
                }
            }
        }

        Ok(())
    }

    /// Placeholder for network send logic.
    ///
    /// TODO: Implement actual message delivery via the network layer.
    /// This function should serialize the envelope, resolve the
    /// recipient's node address, and transmit the message.
    async fn try_send(
        _entry: &bitevachat_storage::pending::PendingEntry,
    ) -> std::result::Result<(), ()> {
        // Stub: always fails until network layer is implemented.
        Err(())
    }
}