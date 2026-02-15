//! Integration tests for the pending message queue.
//!
//! All tests are deterministic — no real-time sleeps. Timestamps are
//! injected via `Timestamp::from_datetime()`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::{TimeZone, Utc};

use bitevachat_crypto::signing::Signature;
use bitevachat_protocol::message::{Message, MessageEnvelope};
use bitevachat_storage::pending::{compute_backoff_secs, PendingEntry, PendingQueue};
use bitevachat_types::{Address, MessageId, NodeId, Nonce, PayloadType, Timestamp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Returns a unique temporary directory for each test.
fn temp_dir() -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "btvc-pending-test-{}-{}-{}",
        std::process::id(),
        id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn pending_path(dir: &PathBuf) -> PathBuf {
    dir.join("pending.dat")
}

fn test_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, byte) in k.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(0xAB);
    }
    k
}

fn test_address(seed: u8) -> Address {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed.wrapping_add(1);
    Address::new(bytes)
}

fn fixed_timestamp(millis: i64) -> Timestamp {
    let dt = Utc
        .timestamp_millis_opt(millis)
        .single()
        .unwrap_or_else(Utc::now);
    Timestamp::from_datetime(dt)
}

/// Base timestamp: 2025-06-15 12:00:00 UTC.
fn base_time() -> Timestamp {
    let dt = Utc
        .with_ymd_and_hms(2025, 6, 15, 12, 0, 0)
        .single()
        .unwrap_or_else(Utc::now);
    Timestamp::from_datetime(dt)
}

/// Timestamp offset from base by `offset_millis`.
fn time_offset(offset_millis: i64) -> Timestamp {
    let base_millis = base_time().as_datetime().timestamp_millis();
    fixed_timestamp(base_millis + offset_millis)
}

/// Builds a deterministic MessageEnvelope for testing.
fn dummy_envelope(msg_seed: u8, recipient: &Address, ts: &Timestamp) -> MessageEnvelope {
    let sender = test_address(0xFF);
    let msg_id = {
        let mut bytes = [0u8; 32];
        bytes[0] = msg_seed;
        bytes[15] = msg_seed;
        bytes[31] = msg_seed;
        MessageId::new(bytes)
    };

    let message = Message {
        sender,
        recipient: recipient.clone(),
        payload_type: PayloadType::Text,
        payload_ciphertext: vec![0xDE, 0xAD, msg_seed],
        node_id: NodeId::new([0x03; 32]),
        nonce: Nonce::new([msg_seed; 12]),
        timestamp: ts.clone(),
        message_id: msg_id,
    };

    // Dummy signature (not cryptographically valid — tests only).
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0] = msg_seed;
    sig_bytes[63] = msg_seed;
    let signature = Signature::from_bytes(sig_bytes);

    MessageEnvelope { message, signature }
}

/// Creates a dummy `PendingEntry`.
fn dummy_entry(
    msg_seed: u8,
    recipient: &Address,
    created_at: &Timestamp,
) -> PendingEntry {
    PendingEntry {
        envelope: dummy_envelope(msg_seed, recipient, created_at),
        retry_count: 0,
        last_attempt: None,
        created_at: created_at.clone(),
        recipient: recipient.clone(),
    }
}

/// Opens a PendingQueue with default test limits.
fn open_queue(dir: &PathBuf) -> PendingQueue {
    PendingQueue::open(
        &pending_path(dir),
        &test_key(),
        500,  // per_recipient_max
        5000, // global_max
        3600, // backoff_cap_secs
    )
    .unwrap()
}

/// Opens a PendingQueue with custom limits.
fn open_queue_limits(
    dir: &PathBuf,
    per_recipient: usize,
    global: usize,
) -> PendingQueue {
    PendingQueue::open(
        &pending_path(dir),
        &test_key(),
        per_recipient,
        global,
        3600,
    )
    .unwrap()
}

fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_dir_all(path);
}

// ===========================================================================
// 1. Basic enqueue and count
// ===========================================================================

#[test]
fn enqueue_increments_count() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);
    let now = base_time();

    assert_eq!(queue.total_count().unwrap(), 0);

    queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();
    assert_eq!(queue.total_count().unwrap(), 1);

    queue.enqueue(dummy_entry(1, &recipient, &now)).unwrap();
    assert_eq!(queue.total_count().unwrap(), 2);

    cleanup(&dir);
}

#[test]
fn count_for_recipient_accurate() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let alice = test_address(1);
    let bob = test_address(2);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &alice, &now)).unwrap();
    queue.enqueue(dummy_entry(1, &alice, &now)).unwrap();
    queue.enqueue(dummy_entry(2, &bob, &now)).unwrap();

    assert_eq!(queue.count_for_recipient(&alice).unwrap(), 2);
    assert_eq!(queue.count_for_recipient(&bob).unwrap(), 1);
    assert_eq!(queue.total_count().unwrap(), 3);

    cleanup(&dir);
}

// ===========================================================================
// 2. Per-recipient limit rejection
// ===========================================================================

#[test]
fn per_recipient_limit_rejects() {
    let dir = temp_dir();
    let queue = open_queue_limits(&dir, 3, 100);
    let alice = test_address(1);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &alice, &now)).unwrap();
    queue.enqueue(dummy_entry(1, &alice, &now)).unwrap();
    queue.enqueue(dummy_entry(2, &alice, &now)).unwrap();

    // 4th should fail.
    let result = queue.enqueue(dummy_entry(3, &alice, &now));
    assert!(
        result.is_err(),
        "4th enqueue should be rejected (per-recipient limit = 3)"
    );

    // But another recipient should still work.
    let bob = test_address(2);
    assert!(queue.enqueue(dummy_entry(4, &bob, &now)).is_ok());

    cleanup(&dir);
}

// ===========================================================================
// 3. Global limit rejection
// ===========================================================================

#[test]
fn global_limit_rejects() {
    let dir = temp_dir();
    let queue = open_queue_limits(&dir, 100, 5);
    let now = base_time();

    for i in 0..5u8 {
        let recipient = test_address(i + 1);
        queue.enqueue(dummy_entry(i, &recipient, &now)).unwrap();
    }

    assert_eq!(queue.total_count().unwrap(), 5);

    let result = queue.enqueue(dummy_entry(5, &test_address(6), &now));
    assert!(
        result.is_err(),
        "6th enqueue should be rejected (global limit = 5)"
    );

    cleanup(&dir);
}

// ===========================================================================
// 4. TTL expiry purge
// ===========================================================================

#[test]
fn purge_expired_removes_old_entries() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);

    let t0 = base_time();
    queue.enqueue(dummy_entry(0, &recipient, &t0)).unwrap();

    // Entry created 3 days later.
    let t3 = time_offset(3 * 86_400_000);
    queue.enqueue(dummy_entry(1, &recipient, &t3)).unwrap();

    // Now = base + 6 days. TTL=5 days:
    // Entry 0 (age 6 days) → expired
    // Entry 1 (age 3 days) → not expired
    let now = time_offset(6 * 86_400_000);
    let purged = queue.purge_expired(5, &now).unwrap();

    assert_eq!(purged, 1, "should purge 1 expired entry");
    assert_eq!(queue.total_count().unwrap(), 1, "1 entry should remain");

    cleanup(&dir);
}

#[test]
fn purge_noop_when_nothing_expired() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();

    let purged = queue.purge_expired(5, &now).unwrap();
    assert_eq!(purged, 0);
    assert_eq!(queue.total_count().unwrap(), 1);

    cleanup(&dir);
}

// ===========================================================================
// 5. Backoff timing logic
// ===========================================================================

#[test]
fn backoff_computation() {
    let cap = 3600u64;
    assert_eq!(compute_backoff_secs(0, cap), 60);
    assert_eq!(compute_backoff_secs(1, cap), 120);
    assert_eq!(compute_backoff_secs(2, cap), 240);
    assert_eq!(compute_backoff_secs(3, cap), 480);
    assert_eq!(compute_backoff_secs(4, cap), 960);
    assert_eq!(compute_backoff_secs(5, cap), 1920);
    assert_eq!(compute_backoff_secs(6, cap), 3600);
    assert_eq!(compute_backoff_secs(7, cap), 3600);
    assert_eq!(compute_backoff_secs(30, cap), 3600);
    assert_eq!(compute_backoff_secs(u32::MAX, cap), 3600);
}

#[test]
fn dequeue_ready_respects_backoff() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();

    // No last_attempt → ready.
    let ready = queue.dequeue_ready(&now).unwrap();
    assert_eq!(ready.len(), 1, "entry with no last_attempt should be ready");

    // Mark failed (last_attempt = now, retry_count = 1).
    let msg_id = ready[0].message_id().clone();
    queue.mark_failed(&msg_id, &now).unwrap();

    // Immediately after → not ready (backoff = 120s for retry_count=1).
    let ready2 = queue.dequeue_ready(&now).unwrap();
    assert_eq!(ready2.len(), 0, "not ready immediately after failure");

    // 60s later → still not ready.
    let t_60s = time_offset(60_000);
    let ready3 = queue.dequeue_ready(&t_60s).unwrap();
    assert_eq!(ready3.len(), 0, "not ready after only 60s (backoff=120s)");

    // 120s later → ready.
    let t_120s = time_offset(120_000);
    let ready4 = queue.dequeue_ready(&t_120s).unwrap();
    assert_eq!(ready4.len(), 1, "ready after 120s (backoff for retry=1)");

    cleanup(&dir);
}

// ===========================================================================
// 6. mark_failed increments retry count
// ===========================================================================

#[test]
fn mark_failed_increments_retry() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();

    let ready = queue.dequeue_ready(&now).unwrap();
    let msg_id = ready[0].message_id().clone();

    // Fail 3 times at 10-min intervals.
    for i in 0..3 {
        let t = time_offset((i + 1) * 600_000);
        queue.mark_failed(&msg_id, &t).unwrap();
    }

    // After 3 failures: retry_count=3, backoff=480s (8 min).
    // last_attempt = base + 30min.
    // Ready at: base + 30min + 8min = base + 38min.
    let t_37min = time_offset(37 * 60_000);
    let ready_37 = queue.dequeue_ready(&t_37min).unwrap();
    assert_eq!(ready_37.len(), 0, "not ready at 37 min");

    let t_39min = time_offset(39 * 60_000);
    let ready_39 = queue.dequeue_ready(&t_39min).unwrap();
    assert_eq!(ready_39.len(), 1, "ready at 39 min (last_attempt+480s elapsed)");

    cleanup(&dir);
}

#[test]
fn mark_failed_nonexistent_returns_error() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let now = base_time();

    let fake_id = MessageId::new([0xFF; 32]);
    let result = queue.mark_failed(&fake_id, &now);
    assert!(result.is_err(), "mark_failed on nonexistent should error");

    cleanup(&dir);
}

// ===========================================================================
// 7. mark_delivered removes entry
// ===========================================================================

#[test]
fn mark_delivered_removes_entry() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();
    queue.enqueue(dummy_entry(1, &recipient, &now)).unwrap();

    assert_eq!(queue.total_count().unwrap(), 2);

    // Deliver first message (msg_seed=0).
    let msg_id = {
        let mut bytes = [0u8; 32];
        // matches dummy_entry(0, ...) construction
        MessageId::new(bytes)
    };
    queue.mark_delivered(&msg_id).unwrap();

    assert_eq!(queue.total_count().unwrap(), 1);

    cleanup(&dir);
}

#[test]
fn mark_delivered_nonexistent_returns_error() {
    let dir = temp_dir();
    let queue = open_queue(&dir);

    let fake_id = MessageId::new([0xFF; 32]);
    let result = queue.mark_delivered(&fake_id);
    assert!(result.is_err(), "mark_delivered on nonexistent should error");

    cleanup(&dir);
}

// ===========================================================================
// 8. File persistence roundtrip
// ===========================================================================

#[test]
fn file_persistence_roundtrip() {
    let dir = temp_dir();
    let path = pending_path(&dir);
    let key = test_key();
    let recipient = test_address(1);
    let now = base_time();

    // Enqueue and persist.
    {
        let queue = PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap();
        queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();
        queue.enqueue(dummy_entry(1, &recipient, &now)).unwrap();
    }

    // Reopen from file — data should persist.
    {
        let queue = PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap();
        assert_eq!(
            queue.total_count().unwrap(),
            2,
            "entries must persist across reopen"
        );
        assert_eq!(queue.count_for_recipient(&recipient).unwrap(), 2);
    }

    cleanup(&dir);
}

#[test]
fn empty_file_loads_clean() {
    let dir = temp_dir();
    let path = pending_path(&dir);
    let key = test_key();

    let queue = PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap();
    assert_eq!(queue.total_count().unwrap(), 0);

    cleanup(&dir);
}

#[test]
fn wrong_key_cannot_load() {
    let dir = temp_dir();
    let path = pending_path(&dir);
    let key = test_key();
    let recipient = test_address(1);
    let now = base_time();

    {
        let queue = PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap();
        queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();
    }

    let mut wrong = [0u8; 32];
    for (i, byte) in wrong.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(13).wrapping_add(0xCD);
    }
    let result = PendingQueue::open(&path, &wrong, 500, 5000, 3600);
    assert!(
        result.is_err(),
        "opening with wrong key should fail (AEAD authentication)"
    );

    cleanup(&dir);
}

// ===========================================================================
// 9. Full delivery lifecycle
// ===========================================================================

#[test]
fn full_delivery_cycle() {
    let dir = temp_dir();
    let queue = open_queue(&dir);
    let recipient = test_address(1);
    let now = base_time();

    queue.enqueue(dummy_entry(0, &recipient, &now)).unwrap();

    // First attempt: dequeue → fail.
    let ready = queue.dequeue_ready(&now).unwrap();
    assert_eq!(ready.len(), 1);
    let msg_id = ready[0].message_id().clone();
    queue.mark_failed(&msg_id, &now).unwrap();

    // Wait for backoff (retry=1 → 120s).
    let t_later = time_offset(130_000);
    let ready2 = queue.dequeue_ready(&t_later).unwrap();
    assert_eq!(ready2.len(), 1);

    // Second attempt: success.
    queue.mark_delivered(&msg_id).unwrap();
    assert_eq!(queue.total_count().unwrap(), 0, "queue empty after delivery");

    cleanup(&dir);
}

// ===========================================================================
// 10. Concurrent access (basic mutex test)
// ===========================================================================

#[test]
fn concurrent_enqueue_via_arc() {
    use std::sync::Arc;

    let dir = temp_dir();
    let path = pending_path(&dir);
    let key = test_key();
    let now = base_time();

    let queue = Arc::new(
        PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap(),
    );

    let mut handles = Vec::new();
    for i in 0..5u8 {
        let q = Arc::clone(&queue);
        let recipient = test_address(i + 1);
        let t = now.clone();
        handles.push(std::thread::spawn(move || {
            q.enqueue(dummy_entry(i, &recipient, &t)).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(queue.total_count().unwrap(), 5, "all 5 enqueues should succeed");

    cleanup(&dir);
}

// ===========================================================================
// 11. Envelope data integrity
// ===========================================================================

#[test]
fn envelope_preserved_through_persistence() {
    let dir = temp_dir();
    let path = pending_path(&dir);
    let key = test_key();
    let recipient = test_address(1);
    let now = base_time();

    let original_entry = dummy_entry(42, &recipient, &now);
    let original_payload = original_entry.envelope.message.payload_ciphertext.clone();
    let original_sig = *original_entry.envelope.signature.as_bytes();

    {
        let queue = PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap();
        queue.enqueue(original_entry).unwrap();
    }

    {
        let queue = PendingQueue::open(&path, &key, 500, 5000, 3600).unwrap();
        let ready = queue.dequeue_ready(&now).unwrap();
        assert_eq!(ready.len(), 1);

        let loaded = &ready[0];
        assert_eq!(loaded.envelope.message.payload_ciphertext, original_payload);
        assert_eq!(*loaded.envelope.signature.as_bytes(), original_sig);
        assert_eq!(loaded.retry_count, 0);
        assert!(loaded.last_attempt.is_none());
    }

    cleanup(&dir);
}