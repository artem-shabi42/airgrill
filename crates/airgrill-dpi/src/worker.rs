//! NFQUEUE worker loop.

use crate::dpi;
use crate::inject::Injector;
use crate::net;
use crate::nfq::{Msg, Queue};
use crate::strategy::{self, Strategy};
use anyhow::{Context, Result};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Everything the packet mangler needs.
#[derive(Debug, Clone)]
pub struct DpiSettings {
    pub queue_num: u16,
    /// Raw packets injected by the engine carry this mark so they do not loop
    /// back into the queue.
    pub mark: u32,
    pub strategy: Strategy,
    pub decoy: String,
    pub delay_ms: u64,
    pub frag_first: usize,
    pub frag_reverse: bool,
}

impl DpiSettings {
    pub fn parse(
        queue_num: u16,
        mark: u32,
        strategy: &str,
        decoy: &str,
        delay_ms: u64,
        frag_first: usize,
        frag_reverse: bool,
    ) -> Result<Self> {
        Ok(Self {
            queue_num,
            mark,
            strategy: Strategy::parse(strategy).map_err(anyhow::Error::msg)?,
            decoy: decoy.to_string(),
            delay_ms,
            frag_first,
            frag_reverse,
        })
    }
}

#[derive(Default)]
struct Stats {
    packets: AtomicU64,
    desynced: AtomicU64,
    skipped: AtomicU64,
}

/// Blocking worker.  Bind the queue *before* installing the nftables rule that
/// feeds it; the queue is configured fail-open, so a crash never bricks the
/// network.
pub fn run_queue(settings: DpiSettings, stop: Arc<AtomicBool>) -> Result<()> {
    let injector =
        Injector::new(settings.mark).context("creating raw injector (need CAP_NET_RAW)")?;
    let mut queue = Queue::open(settings.queue_num, 8192, true)
        .with_context(|| format!("opening NFQUEUE {}", settings.queue_num))?;

    tracing::info!(
        queue = settings.queue_num,
        strategy = ?settings.strategy,
        "DPI engine ready"
    );

    let stats = Stats::default();
    let started = Instant::now();
    let mut last_report = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        match queue.recv() {
            Ok(Some(msg)) => {
                stats.packets.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = handle_packet(&queue, &msg, &settings, &injector, &stats) {
                    tracing::warn!(error = %e, "DPI packet handling failed");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "netlink receive failed; stopping DPI engine");
                return Err(e);
            }
        }
        if last_report.elapsed() >= Duration::from_secs(30) {
            tracing::debug!(
                packets = stats.packets.load(Ordering::Relaxed),
                desynced = stats.desynced.load(Ordering::Relaxed),
                uptime_s = started.elapsed().as_secs(),
                "DPI stats"
            );
            last_report = Instant::now();
        }
    }

    tracing::info!(
        packets = stats.packets.load(Ordering::Relaxed),
        desynced = stats.desynced.load(Ordering::Relaxed),
        "DPI engine stopped"
    );
    Ok(())
}

fn handle_packet(
    queue: &Queue,
    msg: &Msg,
    settings: &DpiSettings,
    injector: &Injector,
    stats: &Stats,
) -> Result<()> {
    let Some(pkt) = net::parse(&msg.payload) else {
        return Ok(queue.accept(msg.id)?);
    };

    // Only the first payload packet of a connection is desynced.  Handshake
    // packets and bare ACKs go straight through.
    if !pkt.has_payload() || pkt.flags & 0x06 != 0 {
        return Ok(queue.accept(msg.id)?);
    }

    let key = pkt.flow();
    let payload = pkt.payload().to_vec();
    let Some(sniff) = dpi::sniff(&payload) else {
        stats.skipped.fetch_add(1, Ordering::Relaxed);
        tracing::trace!(?key, "skip non-TLS/HTTP flow");
        return Ok(queue.accept(msg.id)?);
    };

    let splits = strategy::split_points(&payload, &settings.strategy.pos);

    if settings.strategy.kind == strategy::Kind::IpFrag {
        let mut frags = pkt.build_ip_fragments(&payload, pkt.seq, 64, settings.frag_first);
        if settings.frag_reverse {
            frags.reverse();
        }
        tracing::debug!(
            ?key,
            seq = pkt.seq,
            len = payload.len(),
            fragments = frags.len(),
            first_payload = settings.frag_first,
            "ipfrag"
        );
        let mut sent = 0usize;
        for f in &frags {
            if injector.send(f).is_ok() {
                sent += 1;
            }
        }
        if sent == 0 {
            return Ok(queue.accept(msg.id)?);
        }
        stats.desynced.fetch_add(1, Ordering::Relaxed);
        return Ok(queue.drop(msg.id)?);
    }

    let max_seg = if pkt.v6 { 1200 } else { 1400 };
    let actions = strategy::plan(&payload, &settings.strategy, &settings.decoy, max_seg);
    if actions.is_empty() {
        return Ok(queue.accept(msg.id)?);
    }

    tracing::debug!(
        ?key,
        seq = pkt.seq,
        len = payload.len(),
        what = %strategy::describe(sniff.proto, sniff.host.as_ref(), &splits),
        actions = %actions
            .iter()
            .map(|a| if a.corrupt {
                "decoy".to_string()
            } else {
                format!("{}+{}", a.offset, a.payload.len())
            })
            .collect::<Vec<_>>()
            .join(","),
        "desync"
    );

    let mut sent = 0usize;
    let mut last_err: Option<io::Error> = None;
    for (idx, a) in actions.iter().enumerate() {
        let seq = pkt.seq.wrapping_add(a.offset as u32);
        let seg = pkt.build_segment_urg(&a.payload, seq, a.ttl, a.corrupt, a.urgent);
        match injector.send(&seg) {
            Ok(()) => sent += 1,
            Err(e) => last_err = Some(io::Error::other(e.to_string())),
        }
        if settings.delay_ms > 0 && idx + 1 < actions.len() {
            std::thread::sleep(Duration::from_millis(settings.delay_ms));
        }
    }

    if sent == 0 {
        if let Some(e) = last_err {
            tracing::warn!(?key, error = %e, "raw injection failed");
        }
        return Ok(queue.accept(msg.id)?);
    }
    stats.desynced.fetch_add(1, Ordering::Relaxed);
    Ok(queue.drop(msg.id)?)
}
