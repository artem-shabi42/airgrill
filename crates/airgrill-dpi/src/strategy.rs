//! Desync strategies.
//!
//! Every strategy turns one TCP payload into a list of wire actions.  The
//! caller drops the original packet and emits these actions through a raw
//! socket.  Sequence numbers stay consistent with the original stream, so the
//! peer's TCP accepts the data and the local kernel accepts the ACKs.
//!
//! Supported kinds:
//!  * `split`   — split in order (multiple positions allowed)
//!  * `disorder`— send the pieces in reverse order
//!  * `fake`    — decoy copy with a different SNI/TTL, then disorder
//!  * `overlap` — tail first, decoy head, real head
//!  * `oob`     — first piece carries a TCP URG byte, rest follows
//!  * `disoob`  — tail first, then the URG piece
//!  * `ipfrag`  — split the packet at the IP layer
//!
//! Positions: `sni`, `mid`, `BYTE`, or a comma list `10,100,300`.

use crate::dpi::{self, AppProto, SniInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Split,
    Disorder,
    Fake,
    Overlap,
    Oob,
    Disoob,
    IpFrag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pos {
    /// Split in the middle of the registrable domain inside the SNI.
    Sni,
    /// Split in the middle of the payload.
    Mid,
    /// Explicit byte offset.
    Byte(usize),
    /// Several split points.
    Multi(Vec<Pos>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strategy {
    pub kind: Kind,
    pub pos: Pos,
    /// TTL of the decoy packet for `Fake`.
    pub fake_ttl: u8,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy {
            kind: Kind::Fake,
            pos: Pos::Sni,
            fake_ttl: 3,
        }
    }
}

impl Strategy {
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut parts = s.split(':');
        let kind = match parts.next().unwrap_or("") {
            "split" => Kind::Split,
            "disorder" => Kind::Disorder,
            "fake" => Kind::Fake,
            "overlap" => Kind::Overlap,
            "oob" => Kind::Oob,
            "disoob" => Kind::Disoob,
            "ipfrag" | "frag" => Kind::IpFrag,
            other => {
                return Err(format!(
                    "unknown strategy '{other}' (expected split|disorder|fake|overlap|oob|disoob|ipfrag)"
                ))
            }
        };

        let mut positions: Vec<Pos> = Vec::new();
        let mut fake_ttl: Option<u8> = None;
        for p in parts {
            if p.is_empty() {
                continue;
            }
            if p == "sni" {
                positions.push(Pos::Sni);
                continue;
            }
            if p == "mid" {
                positions.push(Pos::Mid);
                continue;
            }
            if p.contains(',') {
                for item in p.split(',') {
                    let v: usize = item.parse().map_err(|_| {
                        format!("invalid split offset '{item}' (expected BYTE[,BYTE...])")
                    })?;
                    if v == 0 || v > 65535 {
                        return Err(format!("split offset {v} out of range"));
                    }
                    positions.push(Pos::Byte(v));
                }
                continue;
            }
            let v: usize = p
                .parse()
                .map_err(|_| format!("unknown position '{p}' (expected sni|mid|BYTE)"))?;
            if positions.is_empty() {
                if v == 0 || v > 65535 {
                    return Err(format!("split offset {v} out of range"));
                }
                positions.push(Pos::Byte(v));
            } else if kind == Kind::Fake && fake_ttl.is_none() && v <= 255 {
                fake_ttl = Some(v as u8);
            } else {
                if v == 0 || v > 65535 {
                    return Err(format!("split offset {v} out of range"));
                }
                positions.push(Pos::Byte(v));
            }
        }

        let pos = match positions.len() {
            0 => Pos::Sni,
            1 => positions.remove(0),
            _ => Pos::Multi(positions),
        };
        let ttl = fake_ttl.unwrap_or(3).max(1);
        Ok(Strategy {
            kind,
            pos,
            fake_ttl: ttl,
        })
    }
}

/// A single packet to inject.
#[derive(Debug, Clone)]
pub struct Action {
    /// Bytes carried by this segment.
    pub payload: Vec<u8>,
    /// Offset of `payload[0]` inside the original payload.
    pub offset: usize,
    pub ttl: u8,
    /// Send a deliberately invalid TCP checksum (decoy packets).
    pub corrupt: bool,
    /// Set TCP URG and mark the last byte of this segment as urgent.
    pub urgent: bool,
}

impl Action {
    pub fn is_decoy(&self) -> bool {
        self.corrupt
    }
}

/// Offset inside a hostname that splits its registrable domain (last two
/// labels) roughly in half, e.g. `rr3---sn-1.googlevideo.com` ->
/// `rr3---sn-1.googl|evideo.com`.
pub fn sld_split(host: &str) -> usize {
    let len = host.len();
    if len < 4 {
        return len / 2;
    }
    let last_dot = match host.rfind('.') {
        Some(i) if i + 1 < len => i,
        _ => return len / 2,
    };
    let label_start = host[..last_dot].rfind('.').map(|i| i + 1).unwrap_or(0);
    let label_len = last_dot - label_start;
    if label_len < 2 {
        return len / 2;
    }
    (label_start + label_len / 2).clamp(1, len - 1)
}

fn position_offset(payload: &[u8], pos: &Pos) -> usize {
    let len = payload.len();
    match pos {
        Pos::Byte(n) => *n,
        Pos::Mid => len / 2,
        Pos::Sni => {
            if let Some(s) = dpi::parse_client_hello(payload) {
                s.off + sld_split(&s.host)
            } else if let Some(h) = dpi::parse_http_host(payload) {
                h.off + sld_split(&h.host)
            } else {
                len.min(5)
            }
        }
        Pos::Multi(items) => items
            .first()
            .map(|p| position_offset(payload, p))
            .unwrap_or_else(|| len / 2),
    }
}

/// Compute all split points for a payload (sorted, deduplicated, valid).
pub fn split_points(payload: &[u8], pos: &Pos) -> Vec<usize> {
    let len = payload.len();
    if len < 2 {
        return Vec::new();
    }
    let mut points: Vec<usize> = match pos {
        Pos::Multi(items) => items.iter().map(|p| position_offset(payload, p)).collect(),
        _ => vec![position_offset(payload, pos)],
    };
    for p in &mut points {
        *p = (*p).clamp(1, len - 1);
    }
    points.sort_unstable();
    points.dedup();
    points
}

/// First split point (kept for logging/compatibility).
pub fn split_point(payload: &[u8], pos: &Pos) -> usize {
    split_points(payload, pos).into_iter().next().unwrap_or(0)
}

fn chunks(payload: &[u8], splits: &[usize], max_seg: usize) -> Vec<(usize, Vec<u8>)> {
    let max_seg = max_seg.max(64);
    let mut out = Vec::new();
    let mut bounds = Vec::with_capacity(splits.len() + 2);
    bounds.push(0usize);
    bounds.extend_from_slice(splits);
    bounds.push(payload.len());
    bounds.dedup();
    for w in bounds.windows(2) {
        let (start, end) = (w[0], w[1]);
        if end <= start {
            continue;
        }
        let mut off = start;
        while end - off > max_seg {
            out.push((off, payload[off..off + max_seg].to_vec()));
            off += max_seg;
        }
        if end > off {
            out.push((off, payload[off..end].to_vec()));
        }
    }
    out
}

fn bytes_chunks(payload: &[u8], offset: usize, max_seg: usize) -> Vec<(usize, Vec<u8>)> {
    let max_seg = max_seg.max(64);
    let mut out = Vec::new();
    let mut off = offset;
    while payload.len() - off > max_seg {
        out.push((off, payload[off..off + max_seg].to_vec()));
        off += max_seg;
    }
    if off < payload.len() {
        out.push((off, payload[off..].to_vec()));
    }
    out
}

/// Decoy payload: same ClientHello, but the SNI replaced by a harmless host
/// of exactly the same length (length fields must stay valid).
pub fn decoy_payload(payload: &[u8], decoy: &str) -> Vec<u8> {
    let mut out = payload.to_vec();
    let bytes = decoy.as_bytes();
    if bytes.is_empty() {
        return out;
    }
    if let Some(sni) = dpi::parse_client_hello(payload) {
        for i in 0..sni.len {
            out[sni.off + i] = bytes[i % bytes.len()];
        }
    }
    out
}

pub fn plan(payload: &[u8], strat: &Strategy, decoy_host: &str, max_seg: usize) -> Vec<Action> {
    if payload.len() < 2 {
        return Vec::new();
    }
    let splits = split_points(payload, &strat.pos);
    if splits.is_empty() {
        return Vec::new();
    }
    if strat.kind == Kind::IpFrag {
        return vec![Action {
            payload: payload.to_vec(),
            offset: 0,
            ttl: 64,
            corrupt: false,
            urgent: false,
        }];
    }

    let pieces = chunks(payload, &splits, max_seg);
    let first_split = splits[0];
    let mut actions = Vec::new();

    match strat.kind {
        Kind::Overlap => {
            // Real tail, decoy head, real head.
            for (off, p) in &pieces {
                if *off >= first_split {
                    actions.push(Action {
                        payload: p.clone(),
                        offset: *off,
                        ttl: 64,
                        corrupt: false,
                        urgent: false,
                    });
                }
            }
            let decoy_full = decoy_payload(payload, decoy_host);
            actions.push(Action {
                payload: decoy_full[..first_split].to_vec(),
                offset: 0,
                ttl: 64,
                corrupt: true,
                urgent: false,
            });
            for (off, p) in &pieces {
                if *off < first_split {
                    actions.push(Action {
                        payload: p.clone(),
                        offset: *off,
                        ttl: 64,
                        corrupt: false,
                        urgent: false,
                    });
                }
            }
        }
        Kind::Fake => {
            actions.push(Action {
                payload: decoy_payload(payload, decoy_host),
                offset: 0,
                ttl: strat.fake_ttl,
                corrupt: true,
                urgent: false,
            });
            for (off, p) in pieces.iter().rev() {
                actions.push(Action {
                    payload: p.clone(),
                    offset: *off,
                    ttl: 64,
                    corrupt: false,
                    urgent: false,
                });
            }
        }
        Kind::Oob => {
            // First segment includes the urgent byte; the next segment starts
            // at that byte again, so the server receives it in-band.
            actions.push(Action {
                payload: payload[..=first_split].to_vec(),
                offset: 0,
                ttl: 64,
                corrupt: false,
                urgent: true,
            });
            for (off, p) in bytes_chunks(payload, first_split, max_seg) {
                actions.push(Action {
                    payload: p,
                    offset: off,
                    ttl: 64,
                    corrupt: false,
                    urgent: false,
                });
            }
        }
        Kind::Disoob => {
            for (off, p) in bytes_chunks(payload, first_split, max_seg)
                .into_iter()
                .rev()
            {
                actions.push(Action {
                    payload: p,
                    offset: off,
                    ttl: 64,
                    corrupt: false,
                    urgent: false,
                });
            }
            actions.push(Action {
                payload: payload[..=first_split].to_vec(),
                offset: 0,
                ttl: 64,
                corrupt: false,
                urgent: true,
            });
        }
        Kind::Disorder => {
            for (off, p) in pieces.iter().rev() {
                actions.push(Action {
                    payload: p.clone(),
                    offset: *off,
                    ttl: 64,
                    corrupt: false,
                    urgent: false,
                });
            }
        }
        Kind::Split | Kind::IpFrag => {
            for (off, p) in &pieces {
                actions.push(Action {
                    payload: p.clone(),
                    offset: *off,
                    ttl: 64,
                    corrupt: false,
                    urgent: false,
                });
            }
        }
    }
    actions
}

/// Convenience for logs.
pub fn describe(proto: AppProto, host: Option<&SniInfo>, splits: &[usize]) -> String {
    let at = splits
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    match host {
        Some(h) => format!(
            "{:?} host={} sni_off={} split_at={}",
            proto, h.host, h.off, at
        ),
        None => format!("{proto:?} split_at={at}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::tests::make_client_hello;

    fn strategy(kind: Kind, pos: Pos) -> Strategy {
        Strategy {
            kind,
            pos,
            fake_ttl: 3,
        }
    }

    fn reassemble(actions: &[Action], len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        for a in actions.iter().filter(|a| !a.corrupt) {
            buf[a.offset..a.offset + a.payload.len()].copy_from_slice(&a.payload);
        }
        buf
    }

    #[test]
    fn splits_inside_sni() {
        for host in ["www.youtube.com", "rr3---sn-4g5ednsl.googlevideo.com"] {
            let ch = make_client_hello(host);
            let sni = dpi::parse_client_hello(&ch).unwrap();
            let s = split_point(&ch, &Pos::Sni);
            assert!(s > sni.off && s < sni.end(), "split {s} not inside SNI");
            let rel = s - sni.off;
            let (a, b) = host.split_at(rel);
            let sld = &host[host[..host.rfind('.').unwrap()]
                .rfind('.')
                .map(|i| i + 1)
                .unwrap_or(0)..];
            assert!(!a.contains(sld), "{a:?} still contains {sld:?}");
            assert!(!b.contains(sld), "{b:?} still contains {sld:?}");
        }
    }

    #[test]
    fn sld_split_offsets() {
        assert_eq!(sld_split("youtube.com"), 3);
        assert_eq!(sld_split("www.youtube.com"), 7);
        assert_eq!(sld_split("rr3---sn-4g5ednsl.googlevideo.com"), 23);
        assert_eq!(sld_split("a.b"), 1);
    }

    #[test]
    fn split_actions_reassemble_exactly() {
        let ch = make_client_hello("www.youtube.com");
        for (kind, pos) in [
            (Kind::Split, Pos::Sni),
            (Kind::Disorder, Pos::Sni),
            (Kind::Fake, Pos::Sni),
            (Kind::Oob, Pos::Sni),
            (Kind::Disoob, Pos::Sni),
            (Kind::Split, Pos::Multi(vec![Pos::Byte(50), Pos::Byte(100)])),
        ] {
            let acts = plan(&ch, &strategy(kind, pos), "example.org", 1400);
            assert_eq!(
                reassemble(&acts, ch.len()),
                ch,
                "reassembly failed for {kind:?}"
            );
        }
    }

    #[test]
    fn disorder_sends_second_half_first() {
        let ch = make_client_hello("youtube.com");
        let acts = plan(
            &ch,
            &strategy(Kind::Disorder, Pos::Sni),
            "example.org",
            1400,
        );
        assert!(acts.len() >= 2);
        assert!(acts[0].offset > 0);
        assert_eq!(acts.last().unwrap().offset, 0);
    }

    #[test]
    fn fake_has_decoy_sni_and_bad_checksum() {
        let ch = make_client_hello("www.youtube.com");
        let acts = plan(&ch, &Strategy::default(), "example.org", 1400);
        assert!(acts[0].corrupt);
        assert_eq!(acts[0].ttl, 3);
        let decoy = &acts[0].payload;
        let h = dpi::parse_client_hello(decoy).unwrap();
        assert_ne!(h.host, "www.youtube.com");
        assert_eq!(h.len, "www.youtube.com".len());
        assert!(h.host.starts_with("example.org"));
    }

    #[test]
    fn http_split_inside_host() {
        let req = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
        let s = split_point(req, &Pos::Sni);
        let h = dpi::parse_http_host(req).unwrap();
        assert!(s > h.off && s < h.end());
    }

    #[test]
    fn parses_strategy_strings() {
        assert_eq!(Strategy::parse("split:sni").unwrap().kind, Kind::Split);
        assert_eq!(Strategy::parse("fake:mid:7").unwrap().fake_ttl, 7);
        assert_eq!(Strategy::parse("disorder:100").unwrap().pos, Pos::Byte(100));
        assert_eq!(
            Strategy::parse("split:50,100").unwrap().pos,
            Pos::Multi(vec![Pos::Byte(50), Pos::Byte(100)])
        );
        assert_eq!(Strategy::parse("oob:1").unwrap().kind, Kind::Oob);
        assert!(Strategy::parse("bogus").is_err());
    }
}
