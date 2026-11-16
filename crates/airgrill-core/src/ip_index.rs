//! DNS-observed IP → route index.
//!
//! Domain routing works only while we can see the hostname (TLS SNI / HTTP
//! Host).  For QUIC, games, voice calls and other UDP traffic we remember which
//! answers belong to which rule and replay that decision by destination IP.
//!
//! The map stores the full `Decision` (route, proxy backend, DPI strategy,
//! rule rank), not just a route, so UDP/IP-only traffic keeps per-list
//! backend/strategy overrides.
//!
//! Entries expire with the DNS TTL.

use crate::routing::Decision;
use crate::Route;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Entry {
    decision: Decision,
    until: Instant,
}

#[derive(Debug, Default)]
pub struct IpIndex {
    map: RwLock<HashMap<IpAddr, Entry>>,
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        _ => ip,
    }
}

impl IpIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DNS answer.  A more specific rule (lower `decision.rank`) wins
    /// over a less specific one for the same IP.  A TTL of zero removes the
    /// entry.
    pub fn insert(&self, ip: IpAddr, decision: Decision, ttl: Duration) {
        let ip = normalize(ip);
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        if ttl.is_zero() {
            map.remove(&ip);
            return;
        }
        let now = Instant::now();
        let replace = match map.get(&ip) {
            Some(old) if old.until > now => decision.rank <= old.decision.rank,
            _ => true,
        };
        if replace {
            map.insert(
                ip,
                Entry {
                    decision,
                    until: now + ttl,
                },
            );
        }
    }

    pub fn remove(&self, ip: IpAddr) {
        self.map
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&normalize(ip));
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Decision> {
        let ip = normalize(ip);
        let now = Instant::now();
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        map.get(&ip)
            .filter(|e| e.until > now)
            .map(|e| e.decision.clone())
    }

    /// Convenience for diagnostics/tests.
    pub fn route(&self, ip: IpAddr) -> Option<Route> {
        self.lookup(ip).map(|d| d.route)
    }

    pub fn len(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove expired entries.  Called periodically by the daemon.
    pub fn prune(&self) {
        let now = Instant::now();
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, e| e.until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Route;

    fn decision(route: Route, rank: usize) -> Decision {
        Decision {
            route,
            backend: None,
            strategy: None,
            reason: "test".into(),
            rank,
        }
    }

    #[test]
    fn rank_and_ttl() {
        let idx = IpIndex::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        idx.insert(ip, decision(Route::Direct, 3), Duration::from_secs(60));
        assert_eq!(idx.route(ip), Some(Route::Direct));
        idx.insert(ip, decision(Route::Proxy, 1), Duration::from_secs(60));
        assert_eq!(idx.route(ip), Some(Route::Proxy));
        // A weaker rule must not override a stronger one.
        idx.insert(ip, decision(Route::Block, 9), Duration::from_secs(60));
        assert_eq!(idx.route(ip), Some(Route::Proxy));

        idx.insert(ip, decision(Route::Proxy, 1), Duration::ZERO);
        assert_eq!(idx.route(ip), None);
    }

    #[test]
    fn mapped_ipv4_is_the_same_entry() {
        let idx = IpIndex::new();
        let v4: IpAddr = "10.1.2.3".parse().unwrap();
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        idx.insert(mapped, decision(Route::Dpi, 0), Duration::from_secs(60));
        assert_eq!(idx.route(v4), Some(Route::Dpi));
    }

    #[test]
    fn prune_expired() {
        let idx = IpIndex::new();
        idx.insert(
            "1.1.1.1".parse().unwrap(),
            decision(Route::Proxy, 0),
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(5));
        idx.prune();
        assert!(idx.is_empty());
    }
}
