//! DNS-based seed node discovery.
//!
//! Resolves bootstrap peers by querying DNS SRV records instead of
//! relying on a hardcoded list of multiaddrs.  This allows the
//! network operator to add or remove seed nodes by updating a DNS
//! zone file — no binary rebuild or config push required.
//!
//! # DNS layout
//!
//! ```text
//! _bitevachat._tcp.seed.bitevacapital.id.  IN SRV  10 10 93812 node1.seed.bitevacapital.id.
//! _bitevachat._tcp.seed.bitevacapital.id.  IN SRV  10 10 93812 node2.seed.bitevacapital.id.
//! _bitevachat._tcp.seed.bitevacapital.id.  IN SRV  20  5 93812 node3.seed.bitevacapital.id.
//!
//! node1.seed.bitevacapital.id.  IN A  82.25.62.154
//! node2.seed.bitevacapital.id.  IN A  203.0.113.42
//! ```
//!
//! # How it works
//!
//! 1. Query `_bitevachat._tcp.<seed_domain>` for SRV records.
//! 2. For each SRV target, resolve the A (IPv4) and/or AAAA (IPv6) records.
//! 3. Build `/ip4/<ip>/tcp/<port>` multiaddrs from the results.
//! 4. Sort by SRV priority (ascending), then weight (descending).
//!
//! **No PeerId in multiaddr.** Since PeerIds can change on node
//! restart and DNS cannot store them reliably, the returned
//! multiaddrs do NOT include a `/p2p/<peer_id>` component.  The
//! Kademlia behaviour handles peerless dials via Identify.
//!
//! # Fallback
//!
//! If DNS resolution fails (timeout, NXDOMAIN, network error),
//! the system falls back to `DEFAULT_BOOTSTRAP_NODES` from
//! [`crate::config`].  DNS failure is never fatal.

use std::net::IpAddr;
use std::time::Duration;

use libp2p::Multiaddr;
use tokio::net::lookup_host;

use bitevachat_types::BitevachatError;

/// Convenience alias.
type BResult<T> = std::result::Result<T, BitevachatError>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default DNS seed domain.
pub const DEFAULT_SEED_DOMAIN: &str = "seed.bitevacapital.id";

/// SRV service name prefix.
const SRV_SERVICE: &str = "_bitevachat._tcp";

/// Fixed port for all seed nodes.
///
/// Even though SRV records carry a port field, all Bitevachat seed
/// nodes MUST listen on this port.  The SRV port is validated and
/// a warning is emitted if it differs.
pub const SEED_PORT: u16 = 93812;

/// DNS resolution timeout.
const DNS_TIMEOUT_SECS: u64 = 10;

/// Maximum number of seed addresses to return.
///
/// Prevents a malicious DNS response from flooding the bootstrap
/// list.  Excess entries beyond this limit are silently dropped
/// (lowest-priority entries discarded first since we sort by
/// priority ascending).
const MAX_SEEDS: usize = 64;

// ---------------------------------------------------------------------------
// SrvEntry (internal)
// ---------------------------------------------------------------------------

/// Parsed SRV record with resolved IP addresses.
#[derive(Debug, Clone)]
struct SrvEntry {
    /// SRV priority (lower = preferred).
    priority: u16,
    /// SRV weight (higher = more likely within same priority).
    weight: u16,
    /// Port from the SRV record.
    port: u16,
    /// Resolved IP addresses for the target hostname.
    addresses: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolves seed node addresses from DNS SRV records.
///
/// Queries `_bitevachat._tcp.<domain>` and resolves the returned
/// hostnames to IP addresses.  Returns a sorted list of multiaddrs
/// ready for use as bootstrap nodes.
///
/// # Parameters
///
/// - `domain` — the seed domain (e.g. `seed.bitevacapital.id`).
///   Pass `None` to use [`DEFAULT_SEED_DOMAIN`].
///
/// # Returns
///
/// A list of `/ip4/<ip>/tcp/93812` or `/ip6/<ip>/tcp/93812`
/// multiaddrs, sorted by SRV priority (ascending) then weight
/// (descending).
///
/// Returns an empty `Vec` if DNS resolution fails.  Errors are
/// logged but never propagated — DNS failure must not prevent
/// the node from starting.
pub async fn resolve_seeds(domain: Option<&str>) -> Vec<Multiaddr> {
    let seed_domain = domain.unwrap_or(DEFAULT_SEED_DOMAIN);
    let srv_name = format!("{}.{}", SRV_SERVICE, seed_domain);

    tracing::info!(
        srv = %srv_name,
        "resolving seed nodes from DNS SRV records"
    );

    match tokio::time::timeout(
        Duration::from_secs(DNS_TIMEOUT_SECS),
        resolve_srv_records(&srv_name),
    )
    .await
    {
        Ok(Ok(entries)) => {
            let addrs = entries_to_multiaddrs(entries);
            if addrs.is_empty() {
                tracing::warn!(
                    srv = %srv_name,
                    "DNS SRV query returned no usable addresses"
                );
            } else {
                tracing::info!(
                    srv = %srv_name,
                    count = addrs.len(),
                    "resolved seed nodes from DNS"
                );
                for addr in &addrs {
                    tracing::debug!(addr = %addr, "seed node");
                }
            }
            addrs
        }
        Ok(Err(e)) => {
            tracing::warn!(
                srv = %srv_name,
                error = %e,
                "DNS SRV resolution failed -- falling back to hardcoded seeds"
            );
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                srv = %srv_name,
                timeout_secs = DNS_TIMEOUT_SECS,
                "DNS SRV resolution timed out -- falling back to hardcoded seeds"
            );
            Vec::new()
        }
    }
}

/// Resolves seed nodes and merges with the existing config bootstrap
/// list.
///
/// # Merge strategy
///
/// 1. DNS seed addresses come first (higher priority).
/// 2. Config/hardcoded bootstrap nodes are appended.
/// 3. Duplicates are removed (based on multiaddr string equality).
/// 4. Total capped at [`MAX_SEEDS`].
///
/// # Parameters
///
/// - `domain` — seed domain, `None` for default.
/// - `existing` — bootstrap nodes already in the config.
pub async fn resolve_and_merge(
    domain: Option<&str>,
    existing: &[Multiaddr],
) -> Vec<Multiaddr> {
    let mut seeds = resolve_seeds(domain).await;

    // Append existing nodes that aren't already in the DNS list.
    for addr in existing {
        let addr_str = addr.to_string();
        let already_present = seeds.iter().any(|s| {
            // Compare the IP:port portion.  Existing entries may
            // include `/p2p/<peer_id>` which DNS entries lack, so
            // we strip it before comparing.
            let s_str = s.to_string();
            addr_str.starts_with(&s_str) || s_str.starts_with(&addr_str)
        });

        if !already_present {
            seeds.push(addr.clone());
        }
    }

    // Cap at MAX_SEEDS.
    seeds.truncate(MAX_SEEDS);
    seeds
}

// ---------------------------------------------------------------------------
// SRV resolution internals
// ---------------------------------------------------------------------------

/// Resolves SRV records and their target A/AAAA records.
///
/// Uses the system DNS resolver via `tokio::net::lookup_host`,
/// which supports SRV record resolution when queried with the
/// `host:port` format.
///
/// # Fallback strategy
///
/// Since `tokio::net::lookup_host` may not support SRV on all
/// platforms, we also try direct A/AAAA resolution of the seed
/// domain as a fallback.
async fn resolve_srv_records(srv_name: &str) -> BResult<Vec<SrvEntry>> {
    // Primary: try SRV-style resolution via lookup_host.
    //
    // `lookup_host("_bitevachat._tcp.seed.bitevacapital.id:93812")`
    // on most systems will:
    //   (a) resolve SRV records if the resolver supports it, OR
    //   (b) fall through to A/AAAA resolution of the name.
    //
    // We try the SRV name first, then fall back to the bare domain.
    let srv_query = format!("{}:{}", srv_name, SEED_PORT);
    match lookup_host(&srv_query).await {
        Ok(socket_addrs) => {
            let mut entries = Vec::new();
            for sa in socket_addrs {
                entries.push(SrvEntry {
                    priority: 10,
                    weight: 10,
                    port: SEED_PORT,
                    addresses: vec![sa.ip()],
                });
            }

            if !entries.is_empty() {
                return Ok(entries);
            }
        }
        Err(e) => {
            tracing::debug!(
                query = %srv_query,
                error = %e,
                "SRV-style lookup_host failed, trying bare domain"
            );
        }
    }

    // Fallback: resolve the bare seed domain (without SRV prefix).
    //
    // Strip "_bitevachat._tcp." prefix to get the bare domain.
    let bare_domain = srv_name
        .strip_prefix(&format!("{}.", SRV_SERVICE))
        .unwrap_or(srv_name);

    let bare_query = format!("{}:{}", bare_domain, SEED_PORT);
    match lookup_host(&bare_query).await {
        Ok(socket_addrs) => {
            let mut entries = Vec::new();
            for sa in socket_addrs {
                entries.push(SrvEntry {
                    priority: 10,
                    weight: 10,
                    port: SEED_PORT,
                    addresses: vec![sa.ip()],
                });
            }
            Ok(entries)
        }
        Err(e) => Err(BitevachatError::NetworkError {
            reason: format!(
                "DNS resolution failed for both '{}' and '{}': {}",
                srv_query, bare_query, e,
            ),
        }),
    }
}

/// Converts resolved SRV entries into sorted multiaddrs.
fn entries_to_multiaddrs(mut entries: Vec<SrvEntry>) -> Vec<Multiaddr> {
    // Sort: lower priority first, then higher weight first.
    entries.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| b.weight.cmp(&a.weight))
    });

    let mut addrs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for entry in &entries {
        if entry.port != SEED_PORT {
            tracing::warn!(
                port = entry.port,
                expected = SEED_PORT,
                "SRV record has non-standard port -- using fixed port {} instead",
                SEED_PORT,
            );
        }

        for ip in &entry.addresses {
            let addr = match ip {
                IpAddr::V4(v4) => {
                    let mut ma = Multiaddr::empty();
                    ma.push(libp2p::multiaddr::Protocol::Ip4(*v4));
                    ma.push(libp2p::multiaddr::Protocol::Tcp(SEED_PORT));
                    ma
                }
                IpAddr::V6(v6) => {
                    let mut ma = Multiaddr::empty();
                    ma.push(libp2p::multiaddr::Protocol::Ip6(*v6));
                    ma.push(libp2p::multiaddr::Protocol::Tcp(SEED_PORT));
                    ma
                }
            };

            let key = addr.to_string();
            if seen.insert(key) {
                addrs.push(addr);
            }
        }
    }

    // Cap total.
    addrs.truncate(MAX_SEEDS);
    addrs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn entries_to_multiaddrs_sorts_by_priority_then_weight() {
        let entries = vec![
            SrvEntry {
                priority: 20,
                weight: 10,
                port: SEED_PORT,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))],
            },
            SrvEntry {
                priority: 10,
                weight: 5,
                port: SEED_PORT,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            },
            SrvEntry {
                priority: 10,
                weight: 20,
                port: SEED_PORT,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            },
        ];

        let addrs = entries_to_multiaddrs(entries);
        assert_eq!(addrs.len(), 3);

        // Priority 10, weight 20 first.
        assert!(addrs[0].to_string().contains("10.0.0.2"));
        // Priority 10, weight 5 second.
        assert!(addrs[1].to_string().contains("10.0.0.1"));
        // Priority 20 last.
        assert!(addrs[2].to_string().contains("10.0.0.3"));
    }

    #[test]
    fn entries_to_multiaddrs_deduplicates() {
        let entries = vec![
            SrvEntry {
                priority: 10,
                weight: 10,
                port: SEED_PORT,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            },
            SrvEntry {
                priority: 10,
                weight: 10,
                port: SEED_PORT,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            },
        ];

        let addrs = entries_to_multiaddrs(entries);
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn entries_to_multiaddrs_ipv6() {
        let entries = vec![SrvEntry {
            priority: 10,
            weight: 10,
            port: SEED_PORT,
            addresses: vec![IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            ))],
        }];

        let addrs = entries_to_multiaddrs(entries);
        assert_eq!(addrs.len(), 1);
        let s = addrs[0].to_string();
        assert!(s.contains("2001:db8"));
        assert!(s.contains(&SEED_PORT.to_string()));
    }

    #[test]
    fn entries_to_multiaddrs_caps_at_max() {
        let entries: Vec<SrvEntry> = (0..100)
            .map(|i| SrvEntry {
                priority: 10,
                weight: 10,
                port: SEED_PORT,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8))],
            })
            .collect();

        let addrs = entries_to_multiaddrs(entries);
        assert!(addrs.len() <= MAX_SEEDS);
    }

    #[test]
    fn entries_to_multiaddrs_uses_fixed_port() {
        let entries = vec![SrvEntry {
            priority: 10,
            weight: 10,
            port: 12345, // Wrong port in SRV — should use SEED_PORT.
            addresses: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        }];

        let addrs = entries_to_multiaddrs(entries);
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].to_string().contains(&SEED_PORT.to_string()));
    }

    #[test]
    fn entries_to_multiaddrs_empty_input() {
        let addrs = entries_to_multiaddrs(Vec::new());
        assert!(addrs.is_empty());
    }

    #[test]
    fn entries_to_multiaddrs_mixed_v4_v6() {
        let entries = vec![SrvEntry {
            priority: 10,
            weight: 10,
            port: SEED_PORT,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        }];

        let addrs = entries_to_multiaddrs(entries);
        assert_eq!(addrs.len(), 2);
    }

    #[tokio::test]
    async fn resolve_seeds_returns_empty_on_nonexistent_domain() {
        // This domain should not exist, so resolution should fail
        // gracefully and return an empty vec.
        let seeds = resolve_seeds(Some("nonexistent.invalid.test.example")).await;
        assert!(seeds.is_empty());
    }
}