//! Pending message queue for offline recipient delivery.
//!
//! Messages destined for offline recipients are enqueued here and
//! retried with exponential backoff until delivery succeeds, the
//! recipient comes online, or the TTL expires.
//!
//! # Limits
//!
//! - **Per-recipient**: configurable via `pending_max_per_recipient` (default 500).
//! - **Global**: configurable via `pending_global_max` (default 5000).
//!
//! # Backoff
//!
//! Exponential: `min(2^retry_count minutes, cap)`.
//! Sequence: 1m, 2m, 4m, 8m, 16m, 32m, 60m (cap), 60m, …
//!
//! # Thread Safety
//!
//! All mutations are protected by `std::sync::Mutex`. No `unsafe`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bitevachat_protocol::message::MessageEnvelope;
use bitevachat_types::{Address, BitevachatError, MessageId, Result, Timestamp};
use serde::{Deserialize, Serialize};

use crate::pending_file::PendingFile;

// ---------------------------------------------------------------------------
// PendingEntry
// ---------------------------------------------------------------------------

/// A message awaiting delivery to an offline recipient.
///
/// Wraps a serializable [`MessageEnvelope`] alongside retry metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingEntry {
    /// The signed message envelope (message + Ed25519 signature).
    pub envelope: MessageEnvelope,
    /// Number of delivery attempts so far.
    pub retry_count: u32,
    /// Timestamp of the most recent delivery attempt, if any.
    pub last_attempt: Option<Timestamp>,
    /// When this entry was first enqueued.
    pub created_at: Timestamp,
    /// Intended recipient address.
    pub recipient: Address,
}

impl PendingEntry {
    /// Returns the message ID from the enclosed envelope.
    pub fn message_id(&self) -> &MessageId {
        &self.envelope.message.message_id
    }
}

// ---------------------------------------------------------------------------
// PendingQueue
// ---------------------------------------------------------------------------

/// Thread-safe pending message queue with encrypted file persistence.
///
/// All mutating operations acquire the internal lock, apply the change,
/// and persist the updated queue to disk before returning. This ensures
/// crash-safety: if persisting fails, the error is propagated and the
/// in-memory state is NOT rolled back (the caller should handle retries
/// or recovery).
pub struct PendingQueue {
    inner: Mutex<Vec<PendingEntry>>,
    file_path: PathBuf,
    encryption_key: [u8; 32],
    /// Maximum pending messages per recipient.
    per_recipient_max: usize,
    /// Maximum pending messages globally.
    global_max: usize,
    /// Backoff cap in seconds.
    backoff_cap_secs: u64,
}

impl PendingQueue {
    /// Opens or creates a pending queue backed by an encrypted file.
    ///
    /// If the file exists, its contents are decrypted and loaded.
    /// If the file does not exist, an empty queue is created.
    ///
    /// # Parameters
    ///
    /// - `path` — path to the encrypted `pending.dat` file.
    /// - `encryption_key` — 32-byte key for XChaCha20-Poly1305.
    /// - `per_recipient_max` — max entries per recipient address.
    /// - `global_max` — max total entries across all recipients.
    /// - `backoff_cap_secs` — maximum backoff duration in seconds.
    pub fn open(
        path: &Path,
        encryption_key: &[u8; 32],
        per_recipient_max: usize,
        global_max: usize,
        backoff_cap_secs: u64,
    ) -> Result<Self> {
        let entries = PendingFile::load(path, encryption_key)?;
        Ok(Self {
            inner: Mutex::new(entries),
            file_path: path.to_path_buf(),
            encryption_key: *encryption_key,
            per_recipient_max,
            global_max,
            backoff_cap_secs,
        })
    }

    /// Enqueues a new pending entry.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::StorageError`] if the global or per-recipient
    ///   limit would be exceeded.
    /// - [`BitevachatError::StorageError`] if file persistence fails.
    pub fn enqueue(&self, entry: PendingEntry) -> Result<()> {
        let mut entries = self.lock_entries()?;

        // Check global limit.
        if entries.len() >= self.global_max {
            return Err(BitevachatError::StorageError {
                reason: format!(
                    "pending queue global limit reached: {} >= {}",
                    entries.len(),
                    self.global_max,
                ),
            });
        }

        // Check per-recipient limit.
        let recipient_count = entries
            .iter()
            .filter(|e| e.recipient.as_bytes() == entry.recipient.as_bytes())
            .count();
        if recipient_count >= self.per_recipient_max {
            return Err(BitevachatError::StorageError {
                reason: format!(
                    "pending queue per-recipient limit reached for recipient: {} >= {}",
                    recipient_count, self.per_recipient_max,
                ),
            });
        }

        entries.push(entry);
        self.persist(&entries)
    }

    /// Returns entries that are ready for delivery attempt.
    ///
    /// An entry is ready if:
    /// 1. Its TTL has not expired (caller should purge first).
    /// 2. Its backoff period has elapsed: `last_attempt + backoff <= now`.
    ///
    /// Entries are NOT removed from the queue by this call.
    ///
    /// # Parameters
    ///
    /// - `now` — the current timestamp (injectable for testing).
    pub fn dequeue_ready(&self, now: &Timestamp) -> Result<Vec<PendingEntry>> {
        let entries = self.lock_entries()?;
        let now_millis = now.as_datetime().timestamp_millis();

        let ready: Vec<PendingEntry> = entries
            .iter()
            .filter(|e| {
                let backoff_ms =
                    compute_backoff_secs(e.retry_count, self.backoff_cap_secs)
                        .saturating_mul(1000);

                match &e.last_attempt {
                    None => true, // never attempted → ready
                    Some(last) => {
                        let last_millis = last.as_datetime().timestamp_millis();
                        let ready_at = (last_millis as u64).saturating_add(backoff_ms);
                        (now_millis as u64) >= ready_at
                    }
                }
            })
            .cloned()
            .collect();

        Ok(ready)
    }

    /// Removes a successfully delivered message from the queue.
    ///
    /// # Errors
    ///
    /// - [`BitevachatError::StorageError`] if the message is not found
    ///   or file persistence fails.
    pub fn mark_delivered(&self, msg_id: &MessageId) -> Result<()> {
        let mut entries = self.lock_entries()?;

        let before = entries.len();
        entries.retain(|e| e.message_id().as_bytes() != msg_id.as_bytes());

        if entries.len() == before {
            return Err(BitevachatError::StorageError {
                reason: "message not found in pending queue".into(),
            });
        }

        self.persist(&entries)
    }

    /// Marks a delivery attempt as failed, incrementing retry count.
    ///
    /// # Parameters
    ///
    /// - `msg_id` — the message to mark.
    /// - `now` — the current timestamp (injectable for testing).
    pub fn mark_failed(&self, msg_id: &MessageId, now: &Timestamp) -> Result<()> {
        let mut entries = self.lock_entries()?;

        let entry = entries
            .iter_mut()
            .find(|e| e.message_id().as_bytes() == msg_id.as_bytes())
            .ok_or_else(|| BitevachatError::StorageError {
                reason: "message not found in pending queue".into(),
            })?;

        entry.retry_count = entry.retry_count.saturating_add(1);
        entry.last_attempt = Some(now.clone());

        self.persist(&entries)
    }

    /// Purges entries whose TTL has expired.
    ///
    /// An entry is expired if `now - created_at > ttl_days`.
    ///
    /// # Parameters
    ///
    /// - `ttl_days` — maximum age in days.
    /// - `now` — the current timestamp (injectable for testing).
    ///
    /// # Returns
    ///
    /// The number of entries purged.
    pub fn purge_expired(&self, ttl_days: u64, now: &Timestamp) -> Result<u64> {
        let mut entries = self.lock_entries()?;
        let now_millis = now.as_datetime().timestamp_millis();
        let ttl_millis = ttl_days.saturating_mul(86_400_000) as i64;

        let before = entries.len();
        entries.retain(|e| {
            let created_millis = e.created_at.as_datetime().timestamp_millis();
            (now_millis - created_millis) <= ttl_millis
        });
        let purged = (before - entries.len()) as u64;

        if purged > 0 {
            self.persist(&entries)?;
        }

        Ok(purged)
    }

    /// Returns the number of pending entries for a specific recipient.
    pub fn count_for_recipient(&self, address: &Address) -> Result<usize> {
        let entries = self.lock_entries()?;
        Ok(entries
            .iter()
            .filter(|e| e.recipient.as_bytes() == address.as_bytes())
            .count())
    }

    /// Returns the total number of entries in the queue.
    pub fn total_count(&self) -> Result<usize> {
        let entries = self.lock_entries()?;
        Ok(entries.len())
    }

    // -- Internal ---------------------------------------------------------

    /// Acquires the mutex lock, returning a mutable guard.
    fn lock_entries(&self) -> Result<std::sync::MutexGuard<'_, Vec<PendingEntry>>> {
        self.inner.lock().map_err(|e| BitevachatError::StorageError {
            reason: format!("pending queue lock poisoned: {e}"),
        })
    }

    /// Persists the current entries to the encrypted file.
    fn persist(&self, entries: &[PendingEntry]) -> Result<()> {
        PendingFile::save(&self.file_path, &self.encryption_key, entries)
    }
}

// ---------------------------------------------------------------------------
// Backoff computation
// ---------------------------------------------------------------------------

/// Computes the backoff duration in seconds for a given retry count.
///
/// Formula: `min(2^retry_count minutes, cap_secs)`
///
/// Sequence (cap = 3600s / 60min):
/// retry 0 → 60s (1 min)
/// retry 1 → 120s (2 min)
/// retry 2 → 240s (4 min)
/// retry 3 → 480s (8 min)
/// retry 4 → 960s (16 min)
/// retry 5 → 1920s (32 min)
/// retry 6+ → 3600s (60 min, capped)
///
/// Clamping prevents overflow for large retry counts.
pub fn compute_backoff_secs(retry_count: u32, cap_secs: u64) -> u64 {
    // Clamp to 30 to prevent 1u64 << 31+ from overflowing when
    // multiplied by 60. 2^30 minutes = 1_073_741_824 min ≈ 2041 years,
    // always above any reasonable cap.
    let clamped = retry_count.min(30);
    let minutes = 1u64.checked_shl(clamped).unwrap_or(u64::MAX);
    let secs = minutes.saturating_mul(60);
    secs.min(cap_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_sequence() {
        let cap = 3600u64;
        assert_eq!(compute_backoff_secs(0, cap), 60);    // 1 min
        assert_eq!(compute_backoff_secs(1, cap), 120);   // 2 min
        assert_eq!(compute_backoff_secs(2, cap), 240);   // 4 min
        assert_eq!(compute_backoff_secs(3, cap), 480);   // 8 min
        assert_eq!(compute_backoff_secs(4, cap), 960);   // 16 min
        assert_eq!(compute_backoff_secs(5, cap), 1920);  // 32 min
        assert_eq!(compute_backoff_secs(6, cap), 3600);  // capped at 60 min
        assert_eq!(compute_backoff_secs(7, cap), 3600);  // still capped
        assert_eq!(compute_backoff_secs(100, cap), 3600); // extreme
    }

    #[test]
    fn backoff_no_overflow() {
        let _ = compute_backoff_secs(u32::MAX, 3600);
        let _ = compute_backoff_secs(u32::MAX, u64::MAX);
    }
}