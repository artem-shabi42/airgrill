//! Local HTTP CONNECT proxy on 127.0.0.1:12334.
//!
//! Many environments (including this agent and Hiddify itself) export
//! `http_proxy=http://127.0.0.1:12334`.  When airgrill replaces Hiddify it
//! keeps that port alive, but routes by the same domain rules instead of
//! proxying everything to the old core.

use crate::state::AppState;
use airgrill_core::marks::{dpi_mark, MARK_SKIP};
use airgrill_core::Route;
use airgrill_net::sock::connect_marked;
use airgrill_proxy::Target;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HEADER: usize = 16 * 1024;

pub fn start(state: Arc<AppState>) -> Result<()> {
    let listen = state.cfg.proxy_inbound.listen;
    let listener = std::net::TcpListener::bind(listen)
        .with_context(|| format!("binding HTTP proxy {listen}"))?;
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle(stream, peer, &state).await {
                            tracing::debug!(%peer, error = %e, "HTTP proxy request failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "HTTP proxy accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    tracing::info!(%listen, "local HTTP CONNECT proxy ready");
    Ok(())
}

async fn handle(mut client: TcpStream, peer: SocketAddr, state: &Arc<AppState>) -> Result<()> {
    let request = read_header(&mut client).await?;
    let first = request
        .split("\r\n")
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('\n');
    let Some((host, port)) = parse_connect(first) else {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await;
        bail!("only CONNECT is supported (request: {first})");
    };

    // A proxied CONNECT does not need a local DNS lookup: the target domain is
    // sent to the VLESS/Xray server, which resolves it in a sane network.  This
    // keeps the local HTTP proxy usable even when direct DNS is poisoned.
    let (ip, host_opt, decision) = match host.parse::<IpAddr>() {
        Ok(ip) => {
            let decision = state.router.decide_ip(ip);
            (ip, None, decision)
        }
        Err(_) => {
            let by_name = state.router.decide_domain(&host);
            if matches!(by_name.route, Route::Proxy | Route::Block) {
                (
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    Some(host.clone()),
                    by_name,
                )
            } else {
                let resolved = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .with_context(|| format!("resolving {host}:{port}"))?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no address for {host}"))?;
                let ip = resolved.ip();
                let decision = state.router.decide(Some(&host), ip);
                (ip, Some(host.clone()), decision)
            }
        }
    };
    tracing::debug!(
        %peer,
        host = %host,
        port,
        route = %decision.route,
        reason = %decision.reason,
        "HTTP CONNECT route"
    );

    match decision.route {
        Route::Block => {
            let _ = client
                .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
        Route::Proxy => {
            let target = Target::new(ip, port, host_opt);
            let backend = state.backends.get(decision.backend.as_deref())?;
            let mut upstream = backend.connect_tcp(&target).await?;
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
        Route::Direct | Route::Dpi => {
            let mark = if decision.route == Route::Dpi {
                let strategy = decision
                    .strategy
                    .as_deref()
                    .unwrap_or(&state.default_strategy);
                match state.dpi_plan.id(strategy) {
                    Some(id) => dpi_mark(id),
                    None => MARK_SKIP,
                }
            } else {
                MARK_SKIP
            };
            let mut upstream = connect_marked(SocketAddr::new(ip, port), mark, CONNECT_TIMEOUT)
                .await
                .with_context(|| format!("direct connect to {ip}:{port}"))?;
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
    }
    Ok(())
}

async fn read_header(stream: &mut TcpStream) -> Result<String> {
    let mut buf = vec![0u8; MAX_HEADER];
    let mut len = 0usize;
    loop {
        let n = tokio::time::timeout(HEADER_TIMEOUT, stream.read(&mut buf[len..]))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP proxy header timeout"))??;
        if n == 0 {
            bail!("HTTP proxy client closed before headers");
        }
        len += n;
        if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if len == MAX_HEADER {
            bail!("HTTP proxy header too large");
        }
    }
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

fn parse_connect(line: &str) -> Option<(String, u16)> {
    let rest = line.strip_prefix("CONNECT ")?;
    let authority = rest.split_whitespace().next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = authority.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}
