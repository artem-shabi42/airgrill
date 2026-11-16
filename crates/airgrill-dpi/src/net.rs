//! Minimal IPv4/IPv6 + TCP parser and segment builder.
//!
//! We deliberately avoid a heavy packet crate: gdpi only needs to read and
//! re-emit TCP segments with a modified payload layout and a fresh checksum.

use std::fmt;

pub const PROTO_TCP: u8 = 6;

#[inline]
pub fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn put16(dst: &mut [u8], v: u16) {
    dst[..2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn put32(dst: &mut [u8], v: u32) {
    dst[..4].copy_from_slice(&v.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// One's-complement sum of 16-bit big-endian words, with a starting value.
fn sum16(data: &[u8], init: u32) -> u32 {
    let mut sum = init;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    sum
}

#[inline]
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ipv4_checksum(header: &[u8]) -> u16 {
    fold(sum16(header, 0))
}

fn tcp_checksum_v4(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = sum16(&src, sum);
    sum = sum16(&dst, sum);
    sum += PROTO_TCP as u32;
    sum += tcp.len() as u32;
    fold(sum16(tcp, sum))
}

fn tcp_checksum_v6(src: [u8; 16], dst: [u8; 16], tcp: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = sum16(&src, sum);
    sum = sum16(&dst, sum);
    sum += tcp.len() as u32;
    sum += PROTO_TCP as u32;
    fold(sum16(tcp, sum))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub v6: bool,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}

impl fmt::Debug for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (s, d) = if self.v6 {
            (
                std::net::Ipv6Addr::from(self.src).to_string(),
                std::net::Ipv6Addr::from(self.dst).to_string(),
            )
        } else {
            (
                std::net::Ipv4Addr::new(self.src[0], self.src[1], self.src[2], self.src[3])
                    .to_string(),
                std::net::Ipv4Addr::new(self.dst[0], self.dst[1], self.dst[2], self.dst[3])
                    .to_string(),
            )
        };
        write!(f, "{s}:{} -> {d}:{}", self.sport, self.dport)
    }
}

#[derive(Clone)]
pub struct Parsed {
    pub buf: Vec<u8>,
    pub v6: bool,
    /// Offset of the TCP header.
    pub l4_off: usize,
    pub payload_off: usize,
    pub payload_end: usize,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub tos: u8,
    pub ttl: u8,
    pub ip_id: u16,
    pub df: bool,
    // TCP
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub urg: u16,
    pub options: Vec<u8>,
}

impl Parsed {
    pub fn payload(&self) -> &[u8] {
        &self.buf[self.payload_off..self.payload_end]
    }

    pub fn flow(&self) -> FlowKey {
        FlowKey {
            v6: self.v6,
            src: self.src,
            dst: self.dst,
            sport: self.sport,
            dport: self.dport,
        }
    }

    pub fn has_payload(&self) -> bool {
        self.payload_end > self.payload_off
    }

    /// TCP flags as a human readable list (for debug logs).
    pub fn flag_names(&self) -> String {
        let mut s = String::new();
        for (bit, name) in [
            (0x01, "F"),
            (0x02, "S"),
            (0x04, "R"),
            (0x08, "P"),
            (0x10, "A"),
            (0x20, "U"),
            (0x40, "E"),
            (0x80, "C"),
        ] {
            if self.flags & bit != 0 {
                s.push_str(name);
            }
        }
        s
    }
}

/// Parse an IP packet. Returns `None` for anything we cannot safely rewrite
/// (non-TCP, IP fragments, truncated packets, exotic IPv6 extension chains).
pub fn parse(buf: &[u8]) -> Option<Parsed> {
    if buf.len() < 20 {
        return None;
    }
    match buf[0] >> 4 {
        4 => parse_v4(buf),
        6 => parse_v6(buf),
        _ => None,
    }
}

fn parse_v4(buf: &[u8]) -> Option<Parsed> {
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let total_len = be16(&buf[2..4]) as usize;
    if total_len < ihl {
        return None;
    }
    let frag = be16(&buf[6..8]);
    // MF flag or a non-zero fragment offset: never rewrite fragments.
    if frag & 0x3fff != 0 {
        return None;
    }
    if buf[9] != PROTO_TCP {
        return None;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src[..4].copy_from_slice(&buf[12..16]);
    dst[..4].copy_from_slice(&buf[16..20]);

    let end = total_len.min(buf.len());
    let tcp = parse_tcp(buf, ihl, end, false)?;
    Some(Parsed {
        buf: buf[..end].to_vec(),
        v6: false,
        src,
        dst,
        tos: buf[1],
        ttl: buf[8],
        ip_id: be16(&buf[4..6]),
        df: frag & 0x4000 != 0,
        ..tcp
    })
}

fn parse_v6(buf: &[u8]) -> Option<Parsed> {
    if buf.len() < 40 {
        return None;
    }
    let payload_len = be16(&buf[4..6]) as usize;
    let end = (40 + payload_len).min(buf.len());
    let mut next = buf[6];
    let mut off = 40usize;

    // Walk a (short) chain of extension headers.
    let mut guard = 0;
    while matches!(next, 0 | 43 | 44 | 60) {
        guard += 1;
        if guard > 4 || off + 8 > end {
            return None;
        }
        if next == 44 {
            // Fragmented IPv6: bail out.
            return None;
        }
        let hdr_len = (buf[off + 1] as usize + 1) * 8;
        next = buf[off];
        off += hdr_len;
        if off > end {
            return None;
        }
    }
    if next != PROTO_TCP || off + 20 > end {
        return None;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    dst.copy_from_slice(&buf[24..40]);

    let tc = buf[0] & 0x0f;
    let flow = be32(&buf[0..4]) & 0x000f_ffff;
    let tcp = parse_tcp(buf, off, end, true)?;
    let parsed = Parsed {
        buf: buf[..end].to_vec(),
        v6: true,
        src,
        dst,
        tos: ((tc << 4) | (flow >> 16) as u8) & 0xfc,
        ttl: buf[7],
        ip_id: 0,
        df: false,
        ..tcp
    };
    Some(parsed)
}

fn parse_tcp(buf: &[u8], off: usize, end: usize, _v6: bool) -> Option<Parsed> {
    if off + 20 > end {
        return None;
    }
    let data_off = (buf[off + 12] >> 4) as usize * 4;
    if data_off < 20 || off + data_off > end {
        return None;
    }
    let options = buf[off + 20..off + data_off].to_vec();
    Some(Parsed {
        buf: Vec::new(),
        v6: false,
        l4_off: off,
        payload_off: off + data_off,
        payload_end: end,
        src: [0; 16],
        dst: [0; 16],
        tos: 0,
        ttl: 0,
        ip_id: 0,
        df: false,
        sport: be16(&buf[off..off + 2]),
        dport: be16(&buf[off + 2..off + 4]),
        seq: be32(&buf[off + 4..off + 8]),
        ack: be32(&buf[off + 8..off + 12]),
        flags: buf[off + 13],
        window: be16(&buf[off + 14..off + 16]),
        urg: be16(&buf[off + 18..off + 20]),
        options,
    })
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

impl Parsed {
    /// Same packet with source/destination and ports/seq/ack swapped.
    /// Useful for injecting packets towards the client from a middlebox.
    pub fn reversed(&self) -> Parsed {
        let mut p = self.clone();
        std::mem::swap(&mut p.src, &mut p.dst);
        std::mem::swap(&mut p.sport, &mut p.dport);
        p.seq = self.ack;
        p.ack = self.seq;
        p
    }

    /// Build a complete IP packet carrying `payload` with sequence number
    /// `seq` (absolute) and the given TTL. `corrupt` flips the TCP checksum,
    /// producing a packet that every real TCP stack will drop but a lazy DPI
    /// will still parse.
    pub fn build_segment(&self, payload: &[u8], seq: u32, ttl: u8, corrupt: bool) -> Vec<u8> {
        self.build_segment_urg(payload, seq, ttl, corrupt, false)
    }

    /// Build a segment, optionally setting TCP URG.  The urgent pointer
    /// points at the last payload byte; the caller normally resends that byte
    /// in the following segment so the peer's TCP stream stays intact.
    pub fn build_segment_urg(
        &self,
        payload: &[u8],
        seq: u32,
        ttl: u8,
        corrupt: bool,
        urgent: bool,
    ) -> Vec<u8> {
        let mut flags = self.flags;
        let urg = if urgent && !payload.is_empty() {
            flags |= 0x20;
            Some(payload.len().min(u16::MAX as usize) as u16)
        } else {
            None
        };
        self.build_flags_urg(payload, seq, ttl, flags, corrupt, urg)
    }

    pub fn build_flags(
        &self,
        payload: &[u8],
        seq: u32,
        ttl: u8,
        flags: u8,
        corrupt: bool,
    ) -> Vec<u8> {
        self.build_flags_urg(payload, seq, ttl, flags, corrupt, None)
    }

    fn build_flags_urg(
        &self,
        payload: &[u8],
        seq: u32,
        ttl: u8,
        flags: u8,
        corrupt: bool,
        urgent: Option<u16>,
    ) -> Vec<u8> {
        let tcp_len = 20 + self.options.len() + payload.len();
        let mut out = vec![0u8; if self.v6 { 40 + tcp_len } else { 20 + tcp_len }];
        let tcp_off = if self.v6 { 40 } else { 20 };

        // --- TCP header ---------------------------------------------------
        {
            let t = &mut out[tcp_off..];
            put16(&mut t[0..2], self.sport);
            put16(&mut t[2..4], self.dport);
            put32(&mut t[4..8], seq);
            put32(&mut t[8..12], self.ack);
            let doff = ((20 + self.options.len()) / 4) as u8;
            t[12] = doff << 4;
            t[13] = flags;
            put16(&mut t[14..16], self.window);
            put16(&mut t[16..18], 0); // checksum placeholder
            put16(&mut t[18..20], urgent.unwrap_or(self.urg));
            t[20..20 + self.options.len()].copy_from_slice(&self.options);
            t[20 + self.options.len()..].copy_from_slice(payload);
        }

        let csum = if self.v6 {
            tcp_checksum_v6(self.src, self.dst, &out[40..])
        } else {
            tcp_checksum_v4(
                [self.src[0], self.src[1], self.src[2], self.src[3]],
                [self.dst[0], self.dst[1], self.dst[2], self.dst[3]],
                &out[20..],
            )
        };
        let csum = if corrupt { csum ^ 0x0101 } else { csum };
        put16(&mut out[tcp_off + 16..tcp_off + 18], csum);

        // --- IP header ----------------------------------------------------
        if self.v6 {
            out[0] = 0x60 | (self.tos >> 4);
            out[1] = (self.tos << 4) & 0xf0;
            out[2] = 0;
            out[3] = 0;
            put16(&mut out[4..6], tcp_len as u16);
            out[6] = PROTO_TCP;
            out[7] = ttl;
            out[8..24].copy_from_slice(&self.src);
            out[24..40].copy_from_slice(&self.dst);
        } else {
            out[0] = 0x45;
            out[1] = self.tos;
            put16(&mut out[2..4], (20 + tcp_len) as u16);
            put16(&mut out[4..6], self.ip_id);
            // Preserve the original DF bit: if the path MTU is smaller than
            // the segment we must let the kernel fragment.
            let flags_frag = if self.df { 0x4000u16 } else { 0 };
            put16(&mut out[6..8], flags_frag);
            out[8] = ttl;
            out[9] = PROTO_TCP;
            put16(&mut out[10..12], 0);
            out[12..16].copy_from_slice(&self.src[..4]);
            out[16..20].copy_from_slice(&self.dst[..4]);
            let hdr_sum = ipv4_checksum(&out[..20]);
            put16(&mut out[10..12], hdr_sum);
        }
        out
    }
}

impl Parsed {
    /// Split a fully built TCP segment into two IP fragments.
    ///
    /// `first_payload` is the number of TCP *payload* bytes carried by the
    /// first fragment (rounded up to an 8-byte boundary). The TCP header and
    /// the complete TCP checksum stay in the first fragment; the receiver's
    /// IP stack reassembles before TCP checksum validation.
    ///
    /// Many DPI middleboxes do not reassemble IP fragments (it is expensive),
    /// while the destination host always does.
    pub fn build_ip_fragments(
        &self,
        payload: &[u8],
        seq: u32,
        ttl: u8,
        first_payload: usize,
    ) -> Vec<Vec<u8>> {
        let full = self.build_segment(payload, seq, ttl, false);
        let l3 = if self.v6 { 40 } else { 20 };
        let tcp_len = 20 + self.options.len() + payload.len();
        let tcp_hdr = 20 + self.options.len();
        let mut first = tcp_hdr + first_payload.max(1);
        first = (first + 7) & !7; // fragment offsets are in 8-byte units
        if first >= tcp_len {
            return vec![full];
        }
        let body = &full[l3..];

        if self.v6 {
            // IPv6 fragment header (8 bytes), next header = TCP.
            let frag_id = (seq ^ ((self.sport as u32) << 16) ^ self.dport as u32) & 0x7fff_ffff;
            let mut out = Vec::with_capacity(2);
            let mut off = 0usize;
            while off < body.len() {
                let take = if off == 0 { first } else { body.len() - off };
                let more = off + take < body.len();
                let mut pkt = vec![0u8; 40 + 8 + take];
                // IPv6 header
                pkt[0] = 0x60;
                put16(&mut pkt[4..6], (8 + take) as u16);
                pkt[6] = 44; // fragment header
                pkt[7] = ttl;
                pkt[8..24].copy_from_slice(&self.src);
                pkt[24..40].copy_from_slice(&self.dst);
                // fragment header
                pkt[40] = PROTO_TCP;
                pkt[41] = 0;
                let offflags = (((off / 8) as u16) << 3) | u16::from(more);
                put16(&mut pkt[42..44], offflags);
                put32(&mut pkt[44..48], frag_id);
                pkt[48..].copy_from_slice(&body[off..off + take]);
                out.push(pkt);
                off += take;
            }
            out
        } else {
            let mut out = Vec::with_capacity(2);
            let mut off = 0usize;
            while off < body.len() {
                let take = if off == 0 { first } else { body.len() - off };
                let more = off + take < body.len();
                let mut pkt = vec![0u8; 20 + take];
                pkt[0] = 0x45;
                pkt[1] = self.tos;
                put16(&mut pkt[2..4], (20 + take) as u16);
                put16(&mut pkt[4..6], self.ip_id);
                let flags_frag = (((off / 8) as u16) & 0x1fff) | if more { 0x2000 } else { 0 };
                put16(&mut pkt[6..8], flags_frag);
                pkt[8] = ttl;
                pkt[9] = PROTO_TCP;
                pkt[12..16].copy_from_slice(&self.src[..4]);
                pkt[16..20].copy_from_slice(&self.dst[..4]);
                let sum = ipv4_checksum(&pkt[..20]);
                put16(&mut pkt[10..12], sum);
                pkt[20..].copy_from_slice(&body[off..off + take]);
                out.push(pkt);
                off += take;
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v4(payload: &[u8], seq: u32) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        put16(&mut p[2..4], total as u16);
        put16(&mut p[4..6], 0x1234);
        put16(&mut p[6..8], 0x4000);
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        let t = &mut p[20..];
        put16(&mut t[0..2], 54321);
        put16(&mut t[2..4], 443);
        put32(&mut t[4..8], seq);
        put32(&mut t[8..12], 0xdead_beef);
        t[12] = 5 << 4;
        t[13] = 0x18; // PSH|ACK
        put16(&mut t[14..16], 502);
        t[20..].copy_from_slice(payload);
        let sum = tcp_checksum_v4([10, 0, 0, 1], [93, 184, 216, 34], &p[20..]);
        put16(&mut p[36..38], sum);
        let h = ipv4_checksum(&p[..20]);
        put16(&mut p[10..12], h);
        p
    }

    #[test]
    fn roundtrip_parse() {
        let raw = sample_v4(b"hello world", 1000);
        let p = parse(&raw).expect("parse");
        assert_eq!(p.payload(), b"hello world");
        assert_eq!(p.sport, 54321);
        assert_eq!(p.dport, 443);
        assert_eq!(p.seq, 1000);
        assert!(p.has_payload());
        assert_eq!(p.flag_names(), "PA");
    }

    #[test]
    fn checksum_is_valid_after_rebuild() {
        let raw = sample_v4(b"abcdef", 7);
        let p = parse(&raw).unwrap();
        let seg = p.build_segment(b"abcdef", 7, 64, false);
        let q = parse(&seg).unwrap();
        assert_eq!(q.payload(), b"abcdef");
        // Recompute and compare: a zero checksum field would mean "no checksum"
        // for TCP, so verify the sum over the whole TCP segment folds to 0xffff.
        let sum = {
            let mut s = 0u32;
            s = sum16(&[10, 0, 0, 1], s);
            s = sum16(&[93, 184, 216, 34], s);
            s += PROTO_TCP as u32;
            s += (seg.len() - 20) as u32;
            sum16(&seg[20..], s)
        };
        assert_eq!(fold(sum), 0);
        let ip_sum = ipv4_checksum(&seg[..20]);
        assert_eq!(ip_sum, 0);
    }

    #[test]
    fn corrupt_checksum_differs() {
        let raw = sample_v4(b"abcdef", 7);
        let p = parse(&raw).unwrap();
        let good = p.build_segment(b"abcdef", 7, 64, false);
        let bad = p.build_segment(b"abcdef", 7, 64, true);
        assert_ne!(&good[36..38], &bad[36..38]);
    }

    #[test]
    fn rejects_fragments() {
        let mut raw = sample_v4(b"abcdef", 7);
        raw[6] = 0x20; // MF
        assert!(parse(&raw).is_none());
    }

    #[test]
    fn ipv4_fragments_reassemble() {
        let raw = sample_v4(b"hello world, this is a test payload!", 4242);
        let p = parse(&raw).unwrap();
        let frags = p.build_ip_fragments(p.payload(), p.seq, 64, 8);
        assert_eq!(frags.len(), 2);
        // Reassemble the IP payloads (TCP header + data) from both fragments.
        let mut body = Vec::new();
        for f in &frags {
            body.extend_from_slice(&f[20..]);
        }
        let full = p.build_segment(p.payload(), p.seq, 64, false);
        assert_eq!(body, full[20..]);
        // Fragment 1 carries MF, fragment 2 carries the offset.
        assert_ne!(u16::from_be_bytes([frags[0][6], frags[0][7]]) & 0x2000, 0);
        let expect_off = ((frags[0].len() - 20) / 8) as u16;
        assert_eq!(
            u16::from_be_bytes([frags[1][6], frags[1][7]]) & 0x1fff,
            expect_off
        );
        // The tail of the payload (where an SNI would live) is only in
        // fragment 2.
        assert!(!frags[0][20..].windows(7).any(|w| w == b"payload"));
        assert!(frags[1][20..].windows(7).any(|w| w == b"payload"));
    }

    #[test]
    fn ipv6_fragments_parse_as_fragments() {
        // Build a v6 TCP packet, fragment it, and check the fragment headers.
        let mut p = vec![0u8; 40 + 20 + 16];
        p[0] = 0x60;
        put16(&mut p[4..6], 36);
        p[6] = PROTO_TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let t = &mut p[40..];
        t[0..2].copy_from_slice(&1000u16.to_be_bytes());
        t[2..4].copy_from_slice(&443u16.to_be_bytes());
        t[4..8].copy_from_slice(&7u32.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x18;
        t[14..16].copy_from_slice(&1000u16.to_be_bytes());
        t[20..].copy_from_slice(b"abcdefghijklmnop");
        let c = tcp_checksum_v6(
            p[8..24].try_into().unwrap(),
            p[24..40].try_into().unwrap(),
            &p[40..],
        );
        put16(&mut p[56..58], c);
        let parsed = parse(&p).unwrap();
        let frags = parsed.build_ip_fragments(parsed.payload(), parsed.seq, 64, 8);
        assert_eq!(frags.len(), 2);
        for f in &frags {
            assert_eq!(f[6], 44); // Fragment header
            assert_eq!(f[40], PROTO_TCP);
        }
        let mut body = Vec::new();
        for f in &frags {
            body.extend_from_slice(&f[48..]);
        }
        assert_eq!(&body[20..], b"abcdefghijklmnop");
    }

    #[test]
    fn ipv6_roundtrip_and_rebuild() {
        let mut p = vec![0u8; 40 + 20 + 4];
        p[0] = 0x60;
        put16(&mut p[4..6], 24);
        p[6] = PROTO_TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let t = &mut p[40..];
        t[0..2].copy_from_slice(&1000u16.to_be_bytes());
        t[2..4].copy_from_slice(&443u16.to_be_bytes());
        t[4..8].copy_from_slice(&5u32.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x18;
        t[14..16].copy_from_slice(&1000u16.to_be_bytes());
        t[20..].copy_from_slice(b"ping");
        let c = tcp_checksum_v6(
            p[8..24].try_into().unwrap(),
            p[24..40].try_into().unwrap(),
            &p[40..],
        );
        put16(&mut p[56..58], c);

        let parsed = parse(&p).expect("parse v6");
        assert!(parsed.v6);
        assert_eq!(parsed.payload(), b"ping");
        let seg = parsed.build_segment(b"pong", 5, 64, false);
        let q = parse(&seg).expect("reparse v6");
        assert_eq!(q.payload(), b"pong");
        assert!(q.v6);
        assert_eq!(q.dport, 443);
    }
}
