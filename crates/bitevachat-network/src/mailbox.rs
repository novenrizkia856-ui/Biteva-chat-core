//! Store-and-forward mailbox for NAT-traversed message delivery.
//!
//! When a public/relay node receives a message destined for a peer
//! that is **not currently connected**, the message is stored in the
//! [`Mailbox`] instead of being silently dropped.
//!
//! When the recipient later connects and completes the Identify
//! handshake (proving its address), the mailbox is **flushed** and
//! all pending messages are delivered immediately.
//!
//! # Design decisions
//!
//! - **In-memory only** — relay nodes are not responsible for
//!   persistent storage. The sender's own pending queue handles
//!   durable retry semantics. The mailbox is a best-effort
//!   acceleration layer.
//!
//! - **Bounded** — per-recipient and global limits prevent a single
//!   sender from exhausting relay memory.
//!
//! - **TTL-based expiry** — stale messages are purged periodically
//!   to reclaim memory. Expired messages will be retried by the
//!   sender's pending queue.
//!
//! - **FIFO eviction** — when per-recipient limit is reached, the
//!   oldest message for that recipient is evicted to make room.
//!
//! # Flow
//!
//! ```text
//! Node B (NAT)              Node A (public)              Node C (NAT)
//!    │                          │                            │
//!    │── WireMessage(to=C) ──▶  │                            │
//!    │                          │ is_for_us? NO              │
//!    │                          │ validate_signature: OK      │
//!    │  ◀── Ack::Ok ───────────│                            │
//!    │                          │ forward(C)                  │
//!    │                          │   C connected? NO           │
//!    │                          │   ╔═══════════════════╗     │
//!    │                          │   ║ mailbox.store(C)  ║     │
//!    │                          │   ╚═══════════════════╝     │
//!    │                          │          ...                │
//!    │                          │          ... (time passes)  │
//!    │                          │                            │
//!    │                          │  ◀── C connects ──────────│
//!    │                          │  ◀── Identify(C) ─────────│
//!    │                          │                            │
//!    │                          │ flush_mailbox(C)           │
//!    │                          │── WireMessage(to=C) ──────▶│
//!    │                          │                            │
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::protocol::WireMessage;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Default maximum messages stored per recipient address.
const DEFAULT_MAX_PER_RECIPIENT: usize = 256;

/// Default maximum total messages across all recipients.
const DEFAULT_MAX_TOTAL: usize = 10_000;

/// Default time-to-live for mailbox entries (1 hour).
const DEFAULT_TTL_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// MailboxEntry
// ---------------------------------------------------------------------------

/// A single queued message waiting for its recipient to connect.
struct MailboxEntry {
    /// The original wire message to forward.
    wire: WireMessage,

    /// Monotonic timestamp when this entry was stored.
    stored_at: Instant,
}

// ---------------------------------------------------------------------------
// MailboxStats
// ---------------------------------------------------------------------------

/// Snapshot of mailbox state for monitoring/logging.
#[derive(Clone, Debug)]
pub struct MailboxStats {
    /// Total messages currently stored.
    pub total_messages: usize,
    /// Number of distinct recipient addresses with pending messages.
    pub recipient_count: usize,
}

// ---------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------

/// In-memory store-and-forward mailbox for relay/public nodes.
///
/// Thread safety: accessed exclusively from the swarm event loop
/// task — no `Mutex` needed.
pub struct Mailbox {
    /// Per-recipient FIFO queues, keyed by recipient address bytes.
    queues: HashMap<[u8; 32], VecDeque<MailboxEntry>>,

    /// Current total message count across all queues.
    total_count: usize,

    /// Maximum messages per recipient before FIFO eviction.
    max_per_recipient: usize,

    /// Maximum total messages before rejecting new stores.
    max_total: usize,

    /// Time-to-live for each entry.
    ttl: Duration,
}

impl Mailbox {
    /// Creates a new mailbox with default limits.
    ///
    /// Defaults:
    /// - 256 messages per recipient
    /// - 10,000 messages total
    /// - 1 hour TTL
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            total_count: 0,
            max_per_recipient: DEFAULT_MAX_PER_RECIPIENT,
            max_total: DEFAULT_MAX_TOTAL,
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
        }
    }

    /// Creates a new mailbox with custom limits.
    ///
    /// # Parameters
    ///
    /// - `max_per_recipient` — FIFO eviction threshold per address.
    ///   Clamped to minimum of 1.
    /// - `max_total` — global store limit. Clamped to minimum of 1.
    /// - `ttl_secs` — entry lifetime in seconds. Clamped to minimum
    ///   of 60 (1 minute).
    pub fn with_limits(
        max_per_recipient: usize,
        max_total: usize,
        ttl_secs: u64,
    ) -> Self {
        Self {
            queues: HashMap::new(),
            total_count: 0,
            max_per_recipient: max_per_recipient.max(1),
            max_total: max_total.max(1),
            ttl: Duration::from_secs(ttl_secs.max(60)),
        }
    }

    /// Stores a message for later delivery to the given recipient.
    ///
    /// # Returns
    ///
    /// - `true` if the message was stored successfully.
    /// - `false` if the global limit is reached and the message was
    ///   rejected.
    ///
    /// When the per-recipient limit is reached, the **oldest**
    /// message for that recipient is evicted (FIFO) to make room.
    pub fn store(
        &mut self,
        recipient: &[u8; 32],
        wire: WireMessage,
    ) -> bool {
        // Global limit check.
        if self.total_count >= self.max_total {
            tracing::warn!(
                total = self.total_count,
                max = self.max_total,
                "mailbox: global limit reached, rejecting message"
            );
            return false;
        }

        let queue = self.queues.entry(*recipient).or_default();

        // Per-recipient FIFO eviction.
        if queue.len() >= self.max_per_recipient {
            if queue.pop_front().is_some() {
                // Saturating sub to avoid underflow (should never happen
                // but defensive).
                self.total_count = self.total_count.saturating_sub(1);
                tracing::debug!(
                    "mailbox: evicted oldest message for recipient (FIFO)"
                );
            }
        }

        queue.push_back(MailboxEntry {
            wire,
            stored_at: Instant::now(),
        });

        // Saturating add to avoid overflow (should never happen but
        // defensive).
        self.total_count = self.total_count.saturating_add(1);

        true
    }

    /// Drains all pending messages for the given recipient.
    ///
    /// Returns the messages in FIFO order (oldest first). Expired
    /// entries are silently discarded during drain.
    ///
    /// After this call, the recipient's queue is removed from the
    /// mailbox entirely.
    pub fn drain(&mut self, recipient: &[u8; 32]) -> Vec<WireMessage> {
        let queue = match self.queues.remove(recipient) {
            Some(q) => q,
            None => return Vec::new(),
        };

        let now = Instant::now();
        let mut messages = Vec::with_capacity(queue.len());

        for entry in queue {
            // Skip expired entries.
            if now.duration_since(entry.stored_at) > self.ttl {
                self.total_count = self.total_count.saturating_sub(1);
                continue;
            }

            self.total_count = self.total_count.saturating_sub(1);
            messages.push(entry.wire);
        }

        messages
    }

    /// Returns the number of pending messages for a recipient.
    ///
    /// Note: may include expired entries that have not been purged yet.
    pub fn pending_count_for(&self, recipient: &[u8; 32]) -> usize {
        self.queues.get(recipient).map_or(0, VecDeque::len)
    }

    /// Returns the total number of messages in the mailbox.
    pub fn total_count(&self) -> usize {
        self.total_count
    }

    /// Returns a snapshot of mailbox statistics.
    pub fn stats(&self) -> MailboxStats {
        MailboxStats {
            total_messages: self.total_count,
            recipient_count: self.queues.len(),
        }
    }

    /// Purges all expired entries across all recipients.
    ///
    /// Returns the number of entries removed. Call this periodically
    /// from the maintenance tick to reclaim memory.
    pub fn purge_expired(&mut self) -> usize {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut purged = 0usize;

        // Collect keys that need processing to avoid borrow issues.
        let keys: Vec<[u8; 32]> = self.queues.keys().copied().collect();

        for key in keys {
            if let Some(queue) = self.queues.get_mut(&key) {
                let before = queue.len();

                // Retain only non-expired entries.
                queue.retain(|entry| now.duration_since(entry.stored_at) <= ttl);

                let removed = before.saturating_sub(queue.len());
                purged = purged.saturating_add(removed);
                self.total_count = self.total_count.saturating_sub(removed);

                // Clean up empty queues.
                if queue.is_empty() {
                    self.queues.remove(&key);
                }
            }
        }

        if purged > 0 {
            tracing::debug!(
                purged,
                remaining = self.total_count,
                "mailbox: purged expired entries"
            );
        }

        purged
    }

    /// Returns whether the mailbox has any pending messages.
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

