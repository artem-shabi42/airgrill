//! A small forwarding DNS proxy.
//!
//! It serves two purposes:
//!  * answers queries for the host and the LAN (nftables redirects :53 here);
//!  * remembers which route a hostname resolved to, so UDP/QUIC/game traffic
//!    can be routed by destination IP later.
//!
//! Raw DNS messages are forwarded unchanged (except for the transaction ID on
//! cache hits), which keeps EDNS, DNSSEC and unknown record types intact.  No
//! external DNS library is needed.

use airgrill_core::marks::MARK_SKIP;
use airgrill_core::{Config, Route, Router};
use airgrill_net::sock::{connect_marked, set_mark_fd, tcp_listener, udp_socket_marked};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const MAX_CACHE: usize = 4096;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1800);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    qtype: u16,
}

struct CacheEntry {
    response: Vec<u8>,
    expires: Instant,
    inserted: Instant,
}

struct DnsState {
    cfg: airgrill_core::config::DnsConfig,
    router: Arc<Router>,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
}

pub struct DnsServer {
    listen: SocketAddr,
    state: Arc<DnsState>,
    udp: Arc<tokio::net::UdpSocket>,
    tcp: TcpListener,
}

/// Bind both UDP and TCP DNS sockets.  `None` when DNS is disabled.
/// Binding happens synchronously so a daemon start fails loudly instead of
/// redirecting :53 into a dead port.
pub async fn bind(cfg: &Config, router: Arc<Router>) -> Result<Option<DnsServer>> {
    if !cfg.dns.enabled {
        return Ok(None);
    }
    let listen = cfg.dns.listen;
    let state = Arc::new(DnsState {
        cfg: cfg.dns.clone(),
        router,
        cache: Mutex::new(HashMap::new()),
    });

    let udp = Arc::new(
        udp_socket_marked(listen, MARK_SKIP)
            .with_context(|| format!("binding DNS UDP {listen}"))?,
    );
    let tcp_std =
        tcp_listener(listen, false).with_context(|| format!("binding DNS TCP {listen}"))?;
    let tcp = TcpListener::from_std(tcp_std)
        .with_context(|| format!("registering DNS TCP listener {listen}"))?;

    Ok(Some(DnsServer {
        listen,
        state,
        udp,
        tcp,
    }))
}

impl DnsServer {
    pub fn spawn(self) {
        let DnsServer {
            listen,
            state,
            udp,
            tcp,
        } = self;
        tracing::info!(
            %listen,
            upstreams = ?state.cfg.upstreams,
            "DNS proxy ready"
        );

        let udp_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match udp.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let query = buf[..n].to_vec();
                        let state = Arc::clone(&udp_state);
                        let udp = Arc::clone(&udp);
                        tokio::spawn(async move {
                            match state.handle(&query).await {
                                Ok(resp) => {
                                    let _ = udp.send_to(&resp, peer).await;
                                }
                                Err(e) => {
                                    tracing::debug!(%peer, error = %e, "DNS query failed")
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "DNS UDP receive failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                let (mut conn, peer) = match tcp.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "DNS TCP accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // The reply must bypass the transparent capture rules.
                if let Err(e) = set_mark_fd(std::os::unix::io::AsRawFd::as_raw_fd(&conn), MARK_SKIP)
                {
                    tracing::debug!(error = %e, "cannot mark DNS TCP client socket");
                }
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if conn.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    if n == 0 || n > 65535 {
                        return;
                    }
                    let mut query = vec![0u8; n];
                    if conn.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    match state.handle(&query).await {
                        Ok(resp) => {
                            let _ = conn.write_all(&(resp.len() as u16).to_be_bytes()).await;
                            let _ = conn.write_all(&resp).await;
                        }
                        Err(e) => tracing::debug!(%peer, error = %e, "DNS TCP query failed"),
                    }
                });
            }
        });
    }
}

impl DnsState {
    async fn handle(&self, query: &[u8]) -> Result<Vec<u8>> {
        let Some(q) = parse_query(query) else {
            anyhow::bail!("malformed DNS query");
        };
        let name = q.name.to_ascii_lowercase();
        let decision = self.router.decide_domain(&name);
        if decision.route == Route::Block {
            tracing::debug!(%name, "DNS blocked");
            return Ok(error_response(query, 3)); // NXDOMAIN
        }

        let key = CacheKey {
            name: name.clone(),
            qtype: q.qtype,
        };
        if let Some(resp) = self.cache_get(&key).await {
            let mut out = resp;
            out[0..2].copy_from_slice(&query[0..2]);
            return Ok(out);
        }

        let resp = match self.forward(query).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(%name, error = %e, "upstream DNS failed");
                return Ok(error_response(query, 2)); // SERVFAIL
            }
        };

        let (answers, ttl) = extract_answers(&resp).unwrap_or_default();
        let ttl = ttl.clamp(self.cfg.min_ttl, self.cfg.max_ttl).max(1);
        for (ip, _) in &answers {
            self.router
                .ip_index()
                .insert(*ip, decision.clone(), Duration::from_secs(ttl as u64));
        }
        tracing::debug!(
            %name,
            qtype = q.qtype,
            route = %decision.route,
            reason = %decision.reason,
            ips = answers.len(),
            ttl,
            "DNS classified"
        );

        self.cache_put(key, resp.clone(), ttl).await;
        Ok(resp)
    }

    async fn cache_get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().await;
        match cache.get(key) {
            Some(e) if e.expires > Instant::now() => Some(e.response.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    async fn cache_put(&self, key: CacheKey, response: Vec<u8>, ttl: u32) {
        let mut cache = self.cache.lock().await;
        if cache.len() >= self.cfg.cache_entries.min(MAX_CACHE) {
            let now = Instant::now();
            cache.retain(|_, e| e.expires > now);
            if cache.len() >= self.cfg.cache_entries.min(MAX_CACHE) {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.inserted)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        let now = Instant::now();
        cache.insert(
            key,
            CacheEntry {
                response,
                expires: now + Duration::from_secs(ttl as u64),
                inserted: now,
            },
        );
    }

    async fn forward(&self, query: &[u8]) -> Result<Vec<u8>> {
        let mut last_err = None;
        for upstream in &self.cfg.upstreams {
            match self.query_udp(query, *upstream).await {
                Ok(resp) => {
                    if is_truncated(&resp) {
                        match self.query_tcp(query, *upstream).await {
                            Ok(tcp) => return Ok(tcp),
                            Err(e) => last_err = Some(e),
                        }
                    } else {
                        return Ok(resp);
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no DNS upstream configured")))
    }

    async fn query_udp(&self, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let bind: SocketAddr = if upstream.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = udp_socket_marked(bind, MARK_SKIP)?;
        sock.connect(upstream).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; 65535];
        let n = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS timeout from {upstream}"))??;
        if n < 12 {
            anyhow::bail!("short DNS response from {upstream}");
        }
        buf.truncate(n);
        if !same_id(query, &buf) {
            anyhow::bail!("DNS ID mismatch from {upstream}");
        }
        Ok(buf)
    }

    async fn query_tcp(&self, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let mut stream = connect_marked(upstream, MARK_SKIP, Duration::from_secs(4)).await?;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(query).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let n = u16::from_be_bytes(len) as usize;
        let mut resp = vec![0u8; n];
        stream.read_exact(&mut resp).await?;
        if !same_id(query, &resp) {
            anyhow::bail!("DNS ID mismatch from {upstream} (TCP)");
        }
        Ok(resp)
    }
}

fn same_id(a: &[u8], b: &[u8]) -> bool {
    a.len() >= 2 && b.len() >= 2 && a[0..2] == b[0..2]
}

fn is_truncated(resp: &[u8]) -> bool {
    resp.len() >= 4 && resp[2] & 0x02 != 0
}

#[derive(Debug, Clone)]
struct Query {
    name: String,
    qtype: u16,
    /// Offset just after the question section.
    end: usize,
}

fn parse_query(buf: &[u8]) -> Option<Query> {
    if buf.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd == 0 {
        return None;
    }
    let (name, off) = read_name(buf, 12)?;
    if off + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    Some(Query {
        name,
        qtype,
        end: off + 4,
    })
}

/// Decode a (possibly compressed) DNS name.
fn read_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end = off;
    let mut hops = 0usize;
    loop {
        let len = *buf.get(off)?;
        if len == 0 {
            off += 1;
            if !jumped {
                end = off;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let b2 = *buf.get(off + 1)?;
            let ptr = (((len & 0x3f) as usize) << 8) | b2 as usize;
            if !jumped {
                end = off + 2;
                jumped = true;
            }
            off = ptr;
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        let len = len as usize;
        if len > 63 || off + 1 + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[off + 1..off + 1 + len]).ok()?;
        labels.push(label.to_string());
        off += 1 + len;
        if !jumped {
            end = off;
        }
    }
    Some((labels.join("."), end))
}

/// Extract A/AAAA answers and the minimum TTL.
fn extract_answers(resp: &[u8]) -> Option<(Vec<(IpAddr, u32)>, u32)> {
    if resp.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut off = 12;
    for _ in 0..qd {
        let (_, next) = read_name(resp, off)?;
        off = next + 4;
        if off > resp.len() {
            return None;
        }
    }
    let mut out = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..an {
        let (_, next) = read_name(resp, off)?;
        off = next;
        if off + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[off], resp[off + 1]]);
        let rclass = u16::from_be_bytes([resp[off + 2], resp[off + 3]]);
        let ttl = u32::from_be_bytes([resp[off + 4], resp[off + 5], resp[off + 6], resp[off + 7]]);
        let rdlen = u16::from_be_bytes([resp[off + 8], resp[off + 9]]) as usize;
        off += 10;
        if off + rdlen > resp.len() {
            return None;
        }
        if rclass == 1 && rtype == 1 && rdlen == 4 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                resp[off],
                resp[off + 1],
                resp[off + 2],
                resp[off + 3],
            ));
            out.push((ip, ttl));
            min_ttl = min_ttl.min(ttl);
        } else if rclass == 1 && rtype == 28 && rdlen == 16 {
            if let Ok(bytes) = <[u8; 16]>::try_from(&resp[off..off + 16]) {
                out.push((IpAddr::V6(std::net::Ipv6Addr::from(bytes)), ttl));
                min_ttl = min_ttl.min(ttl);
            }
        }
        off += rdlen;
    }
    let ttl = if min_ttl == u32::MAX { 60 } else { min_ttl };
    Some((out, ttl))
}

fn error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let end = parse_query(query).map(|q| q.end).unwrap_or(12);
    let end = end.min(query.len());
    let mut out = vec![0u8; end];
    out[..end].copy_from_slice(&query[..end]);
    if out.len() >= 12 {
        let rd = u16::from_be_bytes([query[2], query[3]]) & 0x0100;
        let flags = 0x8000 | rd | 0x0080 | (rcode as u16 & 0x0f);
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        out[6..8].copy_from_slice(&0u16.to_be_bytes());
        out[8..10].copy_from_slice(&0u16.to_be_bytes());
        out[10..12].copy_from_slice(&0u16.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response with one A record and a compressed owner name.
    fn response_a(name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut q = Vec::new();
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);

        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        msg[4..6].copy_from_slice(&1u16.to_be_bytes());
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&q);
        msg.extend_from_slice(&1u16.to_be_bytes()); // A
        msg.extend_from_slice(&1u16.to_be_bytes()); // IN
                                                    // answer: pointer to the question name
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&ip);
        msg
    }

    #[test]
    fn parses_query_name() {
        let q = response_a("www.example.com", [1, 2, 3, 4], 300);
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.name, "www.example.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn extracts_a_record() {
        let r = response_a("example.com", [5, 6, 7, 8], 120);
        let (answers, ttl) = extract_answers(&r).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0, "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(ttl, 120);
    }

    #[test]
    fn nxdomain_echoes_question() {
        let q = response_a("blocked.example", [1, 1, 1, 1], 60);
        let e = error_response(&q, 3);
        assert_eq!(&e[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(e[3] & 0x0f, 3);
        assert_eq!(u16::from_be_bytes([e[6], e[7]]), 0);
    }

    #[test]
    fn truncated_compression_pointer_fails() {
        let bad = [0u8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x20];
        assert!(parse_query(&bad).is_none());
    }
}
