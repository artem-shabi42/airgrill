//! Transparent TCP datapath.
//!
//! Both host traffic (nftables REDIRECT in the output hook) and forwarded LAN
//! traffic (TPROXY) arrive at the same listener.  We peek at the first bytes,
//! extract TLS SNI / HTTP Host, choose a route and relay.

use crate::state::AppState;
use airgrill_core::marks::{dpi_mark, MARK_SKIP};
use airgrill_core::Route;
use airgrill_dpi::dpi::{parse_client_hello, parse_http_host};
use airgrill_net::sock::{connect_marked, original_dst, tcp_listener};
use airgrill_proxy::Target;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout_at;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SNIFF_TIMEOUT: Duration = Duration::from_millis(350);

pub fn start(state: Arc<AppState>) -> Result<()> {
    let port = state.tcp_port;
    let mut bound = 0;
    for addr in [format!("0.0.0.0:{port}"), format!("[::]:{port}")] {
        let addr: SocketAddr = addr.parse().expect("static listen addr");
        match tcp_listener(addr, true) {
            Ok(std_listener) => {
                let listener = TcpListener::from_std(std_listener)
                    .with_context(|| format!("registering TCP listener {addr}"))?;
                bound += 1;
                let state = Arc::clone(&state);
                tokio::spawn(async move { accept_loop(listener, state).await });
                tracing::info!(%addr, "TCP listener ready");
            }
            Err(e) if addr.is_ipv6() => {
                tracing::warn!(%addr, error = %e, "IPv6 TCP listener unavailable");
            }
            Err(e) => return Err(e).with_context(|| format!("binding TCP listener {addr}")),
        }
    }
    if bound == 0 {
        anyhow::bail!("could not bind any TCP listener on port {port}");
    }
    Ok(())
}

async fn accept_loop(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, peer, &state).await {
                        tracing::debug!(%peer, error = %e, "TCP connection failed");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "TCP accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle(stream: TcpStream, peer: SocketAddr, state: &Arc<AppState>) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let dst = original_dst(stream.as_raw_fd(), state.tcp_port)
        .with_context(|| format!("recovering original destination for peer {peer}"))?;

    let host = sniff_host(&stream).await;
    let decision = state.router.decide(host.as_deref(), dst.ip());

    tracing::debug!(
        %peer,
        %dst,
        host = host.as_deref().unwrap_or("-"),
        route = %decision.route,
        reason = %decision.reason,
        "TCP route"
    );

    match decision.route {
        Route::Block => {
            tracing::debug!(%dst, host = host.as_deref().unwrap_or("-"), "blocked");
            let mut stream = stream;
            let _ = stream.shutdown().await;
        }
        Route::Proxy => {
            let backend = state.backends.get(decision.backend.as_deref())?;
            let target = Target::new(dst.ip(), dst.port(), host);
            let mut upstream = backend.connect_tcp(&target).await.with_context(|| {
                format!(
                    "proxy connect to {} via {}",
                    target.display(),
                    backend.name()
                )
            })?;
            relay(stream, &mut upstream, &target).await?;
        }
        Route::Direct | Route::Dpi => {
            let mark = if decision.route == Route::Dpi {
                let strategy = decision
                    .strategy
                    .as_deref()
                    .unwrap_or(&state.default_strategy);
                match state.dpi_plan.id(strategy) {
                    Some(id) => dpi_mark(id),
                    None => {
                        tracing::warn!(
                            strategy,
                            "DPI is disabled or unknown for this rule; sending direct"
                        );
                        MARK_SKIP
                    }
                }
            } else {
                MARK_SKIP
            };
            let upstream = connect_marked(dst, mark, CONNECT_TIMEOUT)
                .await
                .with_context(|| format!("direct connect to {dst}"))?;
            let mut upstream: airgrill_proxy::BoxStream = Box::new(upstream);
            let target = Target::new(dst.ip(), dst.port(), host);
            relay(stream, &mut upstream, &target).await?;
        }
    }
    Ok(())
}

async fn relay(
    mut client: TcpStream,
    upstream: &mut airgrill_proxy::BoxStream,
    target: &Target,
) -> Result<()> {
    let (from_client, from_upstream) = tokio::io::copy_bidirectional(&mut client, upstream)
        .await
        .with_context(|| format!("relaying {}", target.display()))?;
    tracing::trace!(
        target = %target.display(),
        from_client,
        from_upstream,
        "TCP relay closed"
    );
    Ok(())
}

/// Peek at the first bytes without consuming them.
async fn sniff_host(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; 16384];
    let deadline = Instant::now() + SNIFF_TIMEOUT;
    loop {
        let n = match timeout_at(
            tokio::time::Instant::from_std(deadline),
            stream.peek(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return None,
            Err(_) => return None,
        };
        if n == 0 {
            return None;
        }

        if let Some(sni) = parse_client_hello(&buf[..n]) {
            return Some(sni.host.to_ascii_lowercase());
        }

        if buf[0] == 0x16 && n >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = 5 + record_len;
            if n < needed && Instant::now() < deadline {
                // The ClientHello arrived split across TCP segments.
                continue;
            }
            // Complete but unparsable (ECH, fragmented handshake, ...).
            return None;
        }

        if let Some(h) = parse_http_host(&buf[..n]) {
            return Some(h.host.to_ascii_lowercase());
        }

        let looks_http = [
            b"GET " as &[u8],
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"CONNECT ",
            b"OPTIONS ",
            b"PATCH ",
            b"DELETE ",
        ]
        .iter()
        .any(|p| buf[..n].starts_with(p));
        if looks_http && !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") && Instant::now() < deadline
        {
            continue;
        }

        // Server-first protocol (SSH, SMTP, ...) or an unknown payload:
        // classifying by destination IP is the best we can do.
        return None;
    }
}
