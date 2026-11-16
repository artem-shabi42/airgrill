//! Userspace UDP router fed by the TUN device.
//!
//! nftables marks UDP packets (host output and forwarded LAN) and policy
//! routing sends them to the TUN.  Each `(client, destination)` pair becomes a
//! flow.  Direct flows use a marked UDP socket; proxy flows use the selected
//! backend's UDP session (SOCKS5 UDP ASSOCIATE or VLESS UDP).  Replies are
//! injected back into the TUN with the source address the client expects.

use crate::state::AppState;
use airgrill_core::config::QuicMode;
use airgrill_core::marks::MARK_SKIP;
use airgrill_core::Route;
use airgrill_net::sock::udp_socket_marked;
use airgrill_net::tun::{build_udp, parse_udp, Tun};
use airgrill_proxy::{Target, UdpSession};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: SocketAddr,
    dst: SocketAddr,
}

struct FlowEntry {
    generation: u64,
    tx: mpsc::Sender<Vec<u8>>,
}

pub struct UdpRouter {
    router: Arc<airgrill_core::Router>,
    backends: Arc<airgrill_proxy::Backends>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    flows: Mutex<HashMap<FlowKey, FlowEntry>>,
    generation: AtomicU64,
    packet_id: AtomicU16,
    idle: Duration,
    mtu: usize,
    quic: QuicMode,
}

pub fn start(state: Arc<AppState>, tun: Arc<Tun>) -> Result<()> {
    let tun_name = tun.name().to_string();
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(512);

    let writer_tun = Arc::clone(&tun);
    tokio::spawn(async move {
        while let Some(pkt) = tun_rx.recv().await {
            if let Err(e) = writer_tun.send(&pkt).await {
                tracing::debug!(error = %e, "TUN write failed");
            }
        }
    });

    let router = Arc::new(UdpRouter {
        router: Arc::clone(&state.router),
        backends: Arc::clone(&state.backends),
        tun_tx,
        flows: Mutex::new(HashMap::new()),
        generation: AtomicU64::new(1),
        packet_id: AtomicU16::new(1),
        idle: Duration::from_secs(state.cfg.tun.idle_timeout_secs.max(5)),
        mtu: state.cfg.tun.mtu as usize,
        quic: state.cfg.tun.quic,
    });

    let reader_router = Arc::clone(&router);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun.recv(&mut buf).await {
                Ok(n) => {
                    let Some(pkt) = parse_udp(&buf[..n]) else {
                        tracing::trace!(len = n, "TUN packet is not unfragmented UDP");
                        continue;
                    };
                    let src = pkt.src;
                    let dst = pkt.dst;
                    let payload = pkt.payload.to_vec();
                    reader_router.handle(src, dst, payload).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TUN read failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    tracing::info!(
        interface = %tun_name,
        quic = ?router.quic,
        "UDP TUN datapath ready"
    );
    Ok(())
}

impl UdpRouter {
    async fn handle(self: &Arc<Self>, src: SocketAddr, dst: SocketAddr, payload: Vec<u8>) {
        if src == dst {
            return;
        }
        let decision = self.router.decide_ip(dst.ip());
        let backend = decision.backend.clone();
        let mut route = decision.route;
        if dst.port() == 443 {
            route = match self.quic {
                QuicMode::Block => Route::Block,
                QuicMode::Direct => Route::Direct,
                QuicMode::Proxy => Route::Proxy,
            };
        }
        if route == Route::Block {
            tracing::debug!(%src, %dst, "UDP blocked");
            return;
        }

        let key = FlowKey { src, dst };
        let tx = {
            let mut flows = self.flows.lock().await;
            if let Some(entry) = flows.get(&key) {
                entry.tx.clone()
            } else {
                let generation = self.generation.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                flows.insert(
                    key,
                    FlowEntry {
                        generation,
                        tx: tx.clone(),
                    },
                );
                let this = Arc::clone(self);
                tokio::spawn(async move { this.flow(key, generation, route, backend, rx).await });
                tx
            }
        };
        if tx.try_send(payload).is_err() {
            tracing::trace!(%src, %dst, "UDP flow queue full, datagram dropped");
        }
    }

    async fn flow(
        self: Arc<Self>,
        key: FlowKey,
        generation: u64,
        route: Route,
        backend: Option<String>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) {
        let session = match route {
            Route::Proxy => match self.open_proxy(backend.as_deref(), key.dst).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(dst = %key.dst, error = %e, "UDP proxy session failed");
                    self.remove_flow(key, generation).await;
                    return;
                }
            },
            _ => match direct_session(key.dst, MARK_SKIP).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(dst = %key.dst, error = %e, "UDP direct session failed");
                    self.remove_flow(key, generation).await;
                    return;
                }
            },
        };
        let UdpSession {
            outgoing,
            mut incoming,
        } = session;

        loop {
            tokio::select! {
                data = rx.recv() => {
                    let Some(data) = data else { break };
                    if outgoing.send(data).await.is_err() {
                        break;
                    }
                }
                reply = incoming.recv() => {
                    let Some(reply) = reply else { break };
                    if !self.send_reply(key, &reply).await {
                        break;
                    }
                }
                _ = tokio::time::sleep(self.idle) => {
                    tracing::trace!(dst = %key.dst, "UDP flow idle timeout");
                    break;
                }
            }
        }
        self.remove_flow(key, generation).await;
    }

    async fn open_proxy(&self, backend: Option<&str>, dst: SocketAddr) -> Result<UdpSession> {
        let backend = self.backends.get(backend)?;
        let target = Target::new(dst.ip(), dst.port(), None);
        backend.open_udp(&target).await
    }

    async fn send_reply(&self, key: FlowKey, payload: &[u8]) -> bool {
        let id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let Some(pkt) = build_udp(key.dst, key.src, payload, id) else {
            return true;
        };
        if pkt.len() > self.mtu {
            tracing::debug!(
                dst = %key.dst,
                len = pkt.len(),
                mtu = self.mtu,
                "UDP reply exceeds TUN MTU, dropped"
            );
            return true;
        }
        self.tun_tx.send(pkt).await.is_ok()
    }

    async fn remove_flow(&self, key: FlowKey, generation: u64) {
        let mut flows = self.flows.lock().await;
        if flows
            .get(&key)
            .map(|e| e.generation == generation)
            .unwrap_or(false)
        {
            flows.remove(&key);
        }
    }
}

/// A plain UDP socket with SO_MARK, exposed through the same channel interface
/// as a proxy session.
async fn direct_session(dst: SocketAddr, mark: u32) -> Result<UdpSession> {
    let bind: SocketAddr = if dst.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let udp = udp_socket_marked(bind, mark).with_context(|| format!("UDP socket for {dst}"))?;
    udp.connect(dst)
        .await
        .with_context(|| format!("UDP connect to {dst}"))?;

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                data = out_rx.recv() => {
                    let Some(data) = data else { break };
                    if udp.send(&data).await.is_err() {
                        break;
                    }
                }
                res = udp.recv(&mut buf) => {
                    match res {
                        Ok(n) => {
                            if in_tx.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
    Ok(UdpSession {
        outgoing: out_tx,
        incoming: in_rx,
    })
}
