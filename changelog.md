# Bitevachat Network — Changelog

**Date:** 2026-03-09
**Author:** Noven (DSDN / Biteva Capital)
**Scope:** `bitevachat-network` crate, `bitevachat-node` crate
**Bitevachat+version:** 1.1

---

## Summary

This release solves the core problem where **two private/NAT-ed nodes cannot exchange messages** even when both are connected to a public node. The public node previously dropped messages it couldn't deliver immediately. Now it stores, forwards, and cross-relays messages across the entire network topology.

Additionally, the hardcoded bootstrap node list is replaced with **DNS SRV-based seed discovery**, allowing dynamic network management without binary rebuilds.

---

## New Files

### `dns_seed.rs` (network crate)

DNS SRV-based seed node discovery. On startup, the node queries `_bitevachat._tcp.seed.bitevacapital.id` to discover public seed node IP addresses.

- `resolve_seeds(domain)` — async SRV + A/AAAA resolution with 10s timeout.
- `resolve_and_merge(domain, existing)` — merges DNS results with fallback/config nodes, dedup, capped at 64.
- Sorts by SRV priority (ascending) then weight (descending).
- Falls back to bare domain A/AAAA resolution if SRV query fails.
- DNS failure returns empty vec — never fatal, never blocks startup.
- IPv4 and IPv6 support.

**DNS zone setup:**

```
_bitevachat._tcp.seed.bitevacapital.id.  SRV  10 10 93812 node1.seed.bitevacapital.id.
_bitevachat._tcp.seed.bitevacapital.id.  SRV  10 10 93812 node2.seed.bitevacapital.id.
node1.seed.bitevacapital.id.              A    82.25.62.154
```

### `mailbox.rs` (network crate)

In-memory store-and-forward mailbox for relay/public nodes. When a message cannot be delivered because the recipient is offline, it is stored until the recipient connects.

- Per-recipient FIFO queue with configurable max (default: 256).
- Global message limit (default: 10,000).
- TTL-based expiry (default: 1 hour), purged during maintenance tick.
- FIFO eviction when per-recipient limit is reached.
- `store(recipient, wire)` — returns `true` if stored, `false` if global limit hit.
- `drain(recipient)` — returns all pending messages in FIFO order, skips expired.
- `purge_expired()` — reclaims memory, called from maintenance tick.
- Comprehensive unit tests (11 tests).

---

## Modified Files

### `config.rs` (network crate)

**DNS seed configuration:**

- Removed `DEFAULT_BOOTSTRAP_NODES` (hardcoded IP+PeerId list).
- Added `FALLBACK_BOOTSTRAP_NODES` — hardcoded IPs without PeerId, used when DNS fails. Currently contains `/ip4/82.25.62.154/tcp/93812`.
- Added `DEFAULT_SEED_DOMAIN` constant: `seed.bitevacapital.id`.
- New fields in `NetworkConfig`:
  - `dns_seed_domain: String` — default `seed.bitevacapital.id`.
  - `dns_seed_enabled: bool` — default `true`.
- Default listen port changed from `27300` to `93812`.
- `resolve_bootstrap_nodes()` — new async method: DNS seeds → fallback → config → merge → dedup.
- `fallback_bootstrap_nodes()` — sync method returning fallback + config nodes only.
- `effective_bootstrap_nodes()` — kept for backward compatibility, delegates to `fallback_bootstrap_nodes()`.

**Mailbox configuration:**

- `mailbox_max_per_recipient: usize` — default 256.
- `mailbox_max_total: usize` — default 10,000.
- `mailbox_ttl_secs: u64` — default 3600.
- Validation for all three fields (must be > 0).

### `swarm.rs` (network crate)

**Store-and-forward mailbox integration:**

- `BitevachatSwarm` now owns a `Mailbox` instance.
- `forward_message()` rewritten with 3-strategy delivery:
  1. Direct delivery if recipient is connected.
  2. Store in mailbox for later delivery.
  3. Cross-relay forward to other connected public nodes.
- `flush_mailbox_for_peer(address, peer_id)` — called automatically when Identify handshake resolves a peer's address. Delivers all queued messages in FIFO order.
- `purge_mailbox()` / `mailbox_stats()` — public API for maintenance tick.
- Mailbox initialized from `NetworkConfig` limits.

**Cross-relay message forwarding:**

- New `ForwardCache` struct — bounded `HashSet` + `VecDeque` (FIFO, 10K capacity) for message ID dedup.
- `forward_message()` now accepts `source_peer` parameter to avoid bounce-back.
- After mailbox store, message is forwarded to all other connected relay nodes (excluding source peer and self).
- `ForwardCache` prevents infinite forwarding loops: if message ID already seen, silently dropped.
- `forward_cache_len()` — public accessor for monitoring.

**Auto-relay discovery:**

- New `IdentifyResult` struct returned from `handle_identify_event()` — includes `supports_relay` and `public_listen_addrs`.
- `auto_register_relay(peer_id, supports_relay, public_addrs)` — called after every Identify handshake. If the peer advertises relay hop protocol (`circuit/relay` in protocols list) AND has at least one public IP address, it is automatically registered as a relay node and a relay circuit listen is attempted.
- New helper functions:
  - `addr_has_public_ip(addr)` — checks if a multiaddr contains a routable (non-private) IP.
  - `is_public_ipv4(ip)` — excludes loopback, private, link-local, CGNAT, documentation ranges.
  - `is_public_ipv6(ip)` — excludes loopback, link-local, unique-local.
  - `strip_p2p_component(addr)` — removes `/p2p/<peer_id>` from multiaddr.

**Self-dial prevention:**

- `bootstrap()` — filters out multiaddrs containing the local PeerId before adding to Kademlia.
- `register_relay_nodes()` — skips self-registration.
- `listen_on_relays()` — skips self-listen.

### `node.rs` (node crate)

- `Node::new()` now calls `net_config.resolve_bootstrap_nodes().await` (async DNS resolution) instead of the sync `effective_bootstrap_nodes()`.
- Logs resolved bootstrap count, DNS seed domain, and enabled status at startup.

### `event_loop.rs` (node crate)

- Maintenance tick now calls `rt.network.purge_mailbox()` to reclaim expired mailbox entries.
- Health check log expanded with: `relay_nodes` count, `mailbox_messages`, `mailbox_recipients`, `forward_cache` size.

---

## Architecture

### Message delivery flow (complete)

```
Node A (NAT)      Public C      Public F      Node B (NAT)
    │                │             │               │
    │── msg(to=B) ──▶│             │               │
    │                │ is_for_us? NO              │
    │                │ validate_signature: OK      │
    │  ◀── Ack::Ok ──│             │               │
    │                │                             │
    │                │ forward_message(B):         │
    │                │  ① B connected? NO          │
    │                │  ② mailbox.store(B, msg)    │
    │                │  ③ cross-relay:             │
    │                │── msg(to=B) ─▶│             │
    │                │             │               │
    │                │             │ forward_cache: new? YES
    │                │             │ ① B connected? YES
    │                │             │── msg(to=B) ──▶│
    │                │             │               │ ✓ delivered
```

### Sender-side fallback (try_deliver_to_address)

```
try_deliver_to_address(recipient, envelope, msg_id)
  │
  ├─ ① Direct: recipient in address_book AND connected?
  │     YES → send_message_to_peer → done
  │
  ├─ ② Relay dial: recipient known but not connected?
  │     → dial_via_relay (async, retried from pending queue)
  │
  └─ ③ Store-and-forward: send to any connected relay node
        → relay validates signature → forward/mailbox/cross-relay
```

### Bootstrap resolution order

```
Node startup
  │
  ├─ ① DNS SRV: _bitevachat._tcp.seed.bitevacapital.id
  │     ✓ → resolved IPs at port 93812
  │     ✗ → fallback to bare domain A/AAAA
  │     ✗ → skip (timeout/NXDOMAIN)
  │
  ├─ ② FALLBACK_BOOTSTRAP_NODES (hardcoded)
  │     → /ip4/82.25.62.154/tcp/93812
  │
  ├─ ③ config.bootstrap_nodes (user-configured)
  │
  └─ Merge + dedup + cap 64 → final bootstrap list
```

### Auto-relay discovery flow

```
Peer connects → Identify handshake completes
  │
  ├─ Extract protocols list
  │   └─ Contains "circuit/relay"? → supports_relay = true
  │
  ├─ Extract listen_addrs
  │   └─ Filter: only public IPs (not private/loopback/link-local)
  │
  └─ supports_relay AND has public addrs?
       YES → register_relay_nodes + listen_on_relay_circuit
       NO  → skip (normal peer)
```

---

## Invariants maintained

- Zero `unwrap()`, `expect()`, `panic!()`, `unsafe`, `TODO`.
- All arithmetic uses `saturating_*` operations.
- All errors handled — no silent drops.
- Mailbox bounded (per-recipient + global limits).
- ForwardCache bounded (FIFO eviction at 10K).
- TTL-based expiry prevents memory leaks.
- DNS failure never fatal — graceful fallback.
- Self-dial prevention at bootstrap, relay register, and relay listen.
- Sender's pending queue remains the durable retry mechanism — mailbox is best-effort acceleration.

---

## Integration checklist

1. Add `pub mod mailbox;` to **network crate** `lib.rs`.
2. Add `pub mod dns_seed;` to **network crate** `lib.rs`.
3. All public nodes must listen on port **93812**.
4. Set up DNS SRV record at `_bitevachat._tcp.seed.bitevacapital.id`.
5. Persist node keypairs to disk for stable PeerIds across restarts.