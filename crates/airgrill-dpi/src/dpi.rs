//! Application-layer sniffers used to choose a desync position.
//!
//! We only need to know where the "interesting" bytes are:
//!  * TLS ClientHello  -> the SNI hostname (blocked domain)
//!  * HTTP request     -> the Host header
//!  * QUIC Initial     -> first packet of a connection

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniInfo {
    /// Offset of the hostname inside the TCP payload.
    pub off: usize,
    /// Length of the hostname in bytes.
    pub len: usize,
    /// Hostname as UTF-8 (should always be ASCII in practice).
    pub host: String,
}

impl SniInfo {
    pub fn end(&self) -> usize {
        self.off + self.len
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppProto {
    Tls,
    Http,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniff {
    pub proto: AppProto,
    /// Offset of the host/authority inside the payload, if known.
    pub host: Option<SniInfo>,
}

fn u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

/// Parse the first TLS record of a stream. Returns `None` when the payload is
/// not (the beginning of) a TLS ClientHello.
pub fn parse_client_hello(p: &[u8]) -> Option<SniInfo> {
    // TLS record: type(1) version(2) length(2)
    if p.len() < 9 || p[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([p[3], p[4]]) as usize;
    if rec_len == 0 {
        return None;
    }
    // Handshake header: type(1) length(3)
    if p[5] != 0x01 {
        return None;
    }
    let hs_len = u24(&p[6..9]);
    if hs_len == 0 {
        return None;
    }

    let mut i = 9usize;
    let end = p.len().min(9 + hs_len);

    // legacy_version(2) + random(32)
    i = i.checked_add(34)?;
    if i > end {
        return None;
    }
    // session_id
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    if i + 2 > end {
        return None;
    }
    // cipher_suites
    let cs = u16::from_be_bytes([p[i], p[i + 1]]) as usize;
    i += 2 + cs;
    if i + 1 > end {
        return None;
    }
    // compression_methods
    let cm = *p.get(i)? as usize;
    i += 1 + cm;
    if i + 2 > end {
        return None;
    }
    // extensions
    let ext_len = u16::from_be_bytes([p[i], p[i + 1]]) as usize;
    i += 2;
    let ext_end = (i + ext_len).min(end);

    while i + 4 <= ext_end {
        let etype = u16::from_be_bytes([p[i], p[i + 1]]);
        let elen = u16::from_be_bytes([p[i + 2], p[i + 3]]) as usize;
        let body = i + 4;
        if body + elen > ext_end {
            return None;
        }
        if etype == 0x0000 {
            // server_name extension: list_len(2) [ type(1) len(2) name ]
            let mut j = body;
            if j + 2 > body + elen {
                return None;
            }
            let _list_len = u16::from_be_bytes([p[j], p[j + 1]]) as usize;
            j += 2;
            while j + 3 <= body + elen {
                let ntype = p[j];
                let nlen = u16::from_be_bytes([p[j + 1], p[j + 2]]) as usize;
                j += 3;
                if j + nlen > body + elen {
                    return None;
                }
                if ntype == 0 && nlen > 0 {
                    let host = std::str::from_utf8(&p[j..j + nlen]).ok()?.to_string();
                    return Some(SniInfo {
                        off: j,
                        len: nlen,
                        host,
                    });
                }
                j += nlen;
            }
        }
        i = body + elen;
    }
    None
}

/// Find the Host header of an HTTP/1.x request, case-insensitively.
pub fn parse_http_host(p: &[u8]) -> Option<SniInfo> {
    if p.len() < 8 {
        return None;
    }
    // Rough method check: GET/POST/PUT/HEAD/CONNECT/OPTIONS/PATCH/DELETE
    let head = &p[..p.len().min(16)];
    let is_req = [
        &b"GET "[..],
        &b"POST "[..],
        &b"PUT "[..],
        &b"HEAD "[..],
        &b"CONNECT "[..],
        &b"OPTIONS "[..],
        &b"PATCH "[..],
        &b"DELETE "[..],
    ]
    .iter()
    .any(|m| head.starts_with(m));
    if !is_req {
        return None;
    }
    let upper = p.to_ascii_lowercase();
    let needle = b"\r\nhost:";
    let pos = upper.windows(needle.len()).position(|w| w == needle)?;
    let mut i = pos + needle.len();
    while i < p.len() && (p[i] == b' ' || p[i] == b'\t') {
        i += 1;
    }
    let start = i;
    while i < p.len() && p[i] != b'\r' && p[i] != b'\n' {
        i += 1;
    }
    while i > start && (p[i - 1] == b' ' || p[i - 1] == b'\t') {
        i -= 1;
    }
    if i > start {
        Some(SniInfo {
            off: start,
            len: i - start,
            host: String::from_utf8_lossy(&p[start..i]).into_owned(),
        })
    } else {
        None
    }
}

/// Heuristically identify a QUIC long-header Initial packet.
pub fn is_quic_initial(p: &[u8]) -> bool {
    p.len() >= 7 && p[0] & 0x80 != 0 && p[1..5] != [0, 0, 0, 0]
}

/// Classify an outbound TCP payload.
pub fn sniff(payload: &[u8]) -> Option<Sniff> {
    if let Some(sni) = parse_client_hello(payload) {
        return Some(Sniff {
            proto: AppProto::Tls,
            host: Some(sni),
        });
    }
    if let Some(host) = parse_http_host(payload) {
        return Some(Sniff {
            proto: AppProto::Http,
            host: Some(host),
        });
    }
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Build a minimal but structurally valid TLS ClientHello with an SNI.
    pub fn make_client_hello(host: &str) -> Vec<u8> {
        let mut sni_ext = Vec::new();
        let list_len = 1 + 2 + host.len();
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host.as_bytes());

        let mut exts = Vec::new();
        // SNI extension first (like most clients)
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        // supported_versions
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.extend_from_slice(&[2, 0x03, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x42; 32]); // random
        body.push(32); // session id len
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // ciphers
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni() {
        let ch = make_client_hello("www.youtube.com");
        let sni = parse_client_hello(&ch).expect("sni");
        assert_eq!(sni.host, "www.youtube.com");
        assert_eq!(&ch[sni.off..sni.end()], b"www.youtube.com");
    }

    #[test]
    fn finds_sni_after_other_extensions() {
        let mut ch = make_client_hello("discord.com");
        // Sanity: mutating the host keeps offsets coherent.
        let sni = parse_client_hello(&ch).unwrap();
        ch[sni.off] = b'D';
        let sni = parse_client_hello(&ch).unwrap();
        assert_eq!(sni.host, "Discord.com");
    }

    #[test]
    fn non_tls_is_not_client_hello() {
        assert!(parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn finds_http_host() {
        let req = b"GET /watch?v=1 HTTP/1.1\r\nUser-Agent: x\r\nHost: www.youtube.com\r\n\r\n";
        let h = parse_http_host(req).expect("host");
        assert_eq!(h.host, "www.youtube.com");
        assert_eq!(&req[h.off..h.end()], b"www.youtube.com");
    }

    #[test]
    fn http_host_case_insensitive() {
        let req = b"POST / HTTP/1.1\r\nhOsT:   example.org \r\n\r\n";
        let h = parse_http_host(req).unwrap();
        assert_eq!(h.host, "example.org");
    }

    #[test]
    fn quic_detection() {
        assert!(is_quic_initial(&[0xc0, 0, 0, 0, 1, 0x08, 0x00]));
        assert!(!is_quic_initial(&[0x00, 0, 0, 0, 1, 0x08, 0x00]));
    }
}
