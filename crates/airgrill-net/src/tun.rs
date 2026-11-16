//! A minimal TUN datapath for UDP.
//!
//! TCP is intercepted with REDIRECT/TPROXY, but those mechanisms are awkward
//! for locally generated UDP.  Instead, nftables marks UDP packets and policy
//! routing sends them to this TUN device.  We parse the IP/UDP headers, relay
//! the datagram (direct or through a proxy) and inject the reply back into the
//! TUN device, where the kernel routes it to the original socket.
//!
//! No full IP stack: only unfragmented UDP is handled, which covers QUIC,
//! Discord/Telegram voice and game traffic.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;
use tokio::io::unix::AsyncFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for TunFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// A TUN device wrapped for async reads/writes.
pub struct Tun {
    inner: AsyncFd<TunFd>,
    name: String,
    table: u32,
    mark: u32,
}

fn cmd(program: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program} {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn cmd_ignore(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}

fn sysctl(key: &str, value: &str) {
    let _ = Command::new("sysctl")
        .args(["-qw", &format!("{key}={value}")])
        .output();
}

impl Tun {
    /// Create the device and bring the policy routing for `mark` online.
    pub fn create(
        name: &str,
        address_v4: Ipv4Addr,
        address_v6: Ipv6Addr,
        mtu: u16,
        table: u32,
        mark: u32,
    ) -> Result<Self> {
        let path = CString::new("/dev/net/tun").expect("static path");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("opening /dev/net/tun (need CAP_NET_ADMIN)");
        }

        let mut ifr = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let bytes = name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            unsafe { libc::close(fd) };
            bail!("interface name '{name}' is too long");
        }
        for (i, b) in bytes.iter().enumerate() {
            ifr.name[i] = *b as libc::c_char;
        }
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err).context("TUNSETIFF (need CAP_NET_ADMIN)");
        }
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let tun = Tun {
            #[allow(deprecated)]
            inner: AsyncFd::new(TunFd(fd))?,
            name: name.to_string(),
            table,
            mark,
        };

        // Configure the link.  /32 and /128 addresses are enough: the only
        // route through the device is the marked default route in `table`.
        cmd(
            "ip",
            &["addr", "replace", &format!("{address_v4}/32"), "dev", name],
        )?;
        cmd(
            "ip",
            &[
                "-6",
                "addr",
                "replace",
                &format!("{address_v6}/128"),
                "dev",
                name,
            ],
        )?;
        cmd(
            "ip",
            &["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"],
        )?;
        // Injected replies carry a spoofed public source address.  Strict
        // reverse-path filtering would drop them on ingress.
        sysctl("net.ipv4.conf.all.rp_filter", "0");
        sysctl("net.ipv4.conf.default.rp_filter", "0");
        sysctl(&format!("net.ipv4.conf.{name}.rp_filter"), "0");
        sysctl(&format!("net.ipv4.conf.{name}.accept_local"), "1");
        sysctl(&format!("net.ipv4.conf.{name}.forwarding"), "1");
        sysctl(&format!("net.ipv6.conf.{name}.forwarding"), "1");

        let fwmark = format!("0x{mark:x}");
        let table_s = table.to_string();
        // Remove leftovers from a previous run, then install the rules.
        cmd_ignore(
            "ip",
            &[
                "rule", "del", "fwmark", &fwmark, "lookup", &table_s, "priority", "1000",
            ],
        );
        cmd_ignore(
            "ip",
            &[
                "-6", "rule", "del", "fwmark", &fwmark, "lookup", &table_s, "priority", "1000",
            ],
        );
        cmd(
            "ip",
            &[
                "rule", "add", "fwmark", &fwmark, "lookup", &table_s, "priority", "1000",
            ],
        )?;
        cmd(
            "ip",
            &[
                "-6", "rule", "add", "fwmark", &fwmark, "lookup", &table_s, "priority", "1000",
            ],
        )?;
        cmd(
            "ip",
            &[
                "route", "replace", "default", "dev", name, "table", &table_s,
            ],
        )?;
        cmd(
            "ip",
            &[
                "-6", "route", "replace", "default", "dev", name, "table", &table_s,
            ],
        )?;
        Ok(tun)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let rc = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(rc as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let rc = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(rc as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        // The fd closes after this drop, but remove policy routing first so no
        // packet is sent to a disappearing device.
        let table = self.table.to_string();
        let mark = format!("0x{:x}", self.mark);
        cmd_ignore(
            "ip",
            &[
                "rule", "del", "fwmark", &mark, "lookup", &table, "priority", "1000",
            ],
        );
        cmd_ignore(
            "ip",
            &[
                "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", "1000",
            ],
        );
        cmd_ignore("ip", &["route", "flush", "table", &table]);
        cmd_ignore("ip", &["-6", "route", "flush", "table", &table]);
        cmd_ignore("ip", &["link", "del", &self.name]);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UdpPacket<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: &'a [u8],
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Parse an unfragmented IPv4/IPv6 UDP datagram.
pub fn parse_udp(buf: &[u8]) -> Option<UdpPacket<'_>> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => {
            if buf.len() < 20 {
                return None;
            }
            let ihl = ((buf[0] & 0x0f) as usize) * 4;
            if ihl < 20 || buf.len() < ihl + 8 {
                return None;
            }
            let total = be16(&buf[2..4]) as usize;
            if total < ihl + 8 || total > buf.len() {
                return None;
            }
            let frag = be16(&buf[6..8]);
            if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
                // more-fragments or non-zero offset: fragments are not
                // reassembled in this lightweight datapath.
                return None;
            }
            if buf[9] != 17 {
                return None;
            }
            let src_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[12..16]).ok()?);
            let dst_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[16..20]).ok()?);
            let udp_off = ihl;
            let src_port = be16(&buf[udp_off..udp_off + 2]);
            let dst_port = be16(&buf[udp_off + 2..udp_off + 4]);
            let ulen = be16(&buf[udp_off + 4..udp_off + 6]) as usize;
            if ulen < 8 || udp_off + ulen > total {
                return None;
            }
            Some(UdpPacket {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                payload: &buf[udp_off + 8..udp_off + ulen],
            })
        }
        6 => {
            if buf.len() < 40 + 8 {
                return None;
            }
            let plen = be16(&buf[4..6]) as usize;
            if plen + 40 > buf.len() || buf[6] != 17 {
                return None;
            }
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
            let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).ok()?);
            let udp_off = 40;
            let src_port = be16(&buf[udp_off..udp_off + 2]);
            let dst_port = be16(&buf[udp_off + 2..udp_off + 4]);
            let ulen = be16(&buf[udp_off + 4..udp_off + 6]) as usize;
            if ulen < 8 || udp_off + ulen > 40 + plen {
                return None;
            }
            Some(UdpPacket {
                src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                payload: &buf[udp_off + 8..udp_off + ulen],
            })
        }
        _ => None,
    }
}

fn add_bytes(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        *sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        *sum += (b as u32) << 8;
    }
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(pseudo: &[u8], udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_bytes(&mut sum, pseudo);
    add_bytes(&mut sum, udp);
    let c = fold(sum);
    if c == 0 {
        0xffff
    } else {
        c
    }
}

/// Build an IPv4 UDP packet (DF set).  Returns `None` when it exceeds 65535.
pub fn build_udp_v4(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
    id: u16,
) -> Option<Vec<u8>> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    if total > u16::MAX as usize {
        return None;
    }
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());

    // header checksum
    let mut sum = 0u32;
    add_bytes(&mut sum, &pkt[..20]);
    let hc = fold(sum);
    pkt[10..12].copy_from_slice(&hc.to_be_bytes());

    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.ip().octets());
    pseudo.extend_from_slice(&dst.ip().octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    let c = udp_checksum(&pseudo, &pkt[20..]);
    pkt[26..28].copy_from_slice(&c.to_be_bytes());
    Some(pkt)
}

/// Build an IPv6 UDP packet.  UDP checksums are mandatory for IPv6.
pub fn build_udp_v6(
    src: SocketAddrV6,
    dst: SocketAddrV6,
    payload: &[u8],
    _id: u16,
) -> Option<Vec<u8>> {
    let udp_len = 8 + payload.len();
    if udp_len > u16::MAX as usize {
        return None;
    }
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.ip().octets());
    pkt[24..40].copy_from_slice(&dst.ip().octets());
    pkt[40..42].copy_from_slice(&src.port().to_be_bytes());
    pkt[42..44].copy_from_slice(&dst.port().to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.ip().octets());
    pseudo.extend_from_slice(&dst.ip().octets());
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let c = udp_checksum(&pseudo, &pkt[40..]);
    pkt[46..48].copy_from_slice(&c.to_be_bytes());
    Some(pkt)
}

pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8], id: u16) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => build_udp_v4(s, d, payload, id),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => build_udp_v6(s, d, payload, id),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip() {
        let src: SocketAddr = "10.0.0.2:12345".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let pkt = build_udp(src, dst, b"hello", 7).unwrap();
        let p = parse_udp(&pkt).unwrap();
        assert_eq!(p.src, src);
        assert_eq!(p.dst, dst);
        assert_eq!(p.payload, b"hello");
    }

    #[test]
    fn v6_roundtrip() {
        let src: SocketAddr = "[fd00::2]:12345".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let pkt = build_udp(src, dst, b"ping", 1).unwrap();
        let p = parse_udp(&pkt).unwrap();
        assert_eq!(p.src, src);
        assert_eq!(p.dst, dst);
        assert_eq!(p.payload, b"ping");
    }

    #[test]
    fn rejects_fragments_and_tcp() {
        let src: SocketAddr = "10.0.0.2:1".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:2".parse().unwrap();
        let mut pkt = build_udp(src, dst, b"x", 0).unwrap();
        pkt[6] |= 0x20; // MF
        assert!(parse_udp(&pkt).is_none());
        let mut pkt = build_udp(src, dst, b"x", 0).unwrap();
        pkt[9] = 6;
        assert!(parse_udp(&pkt).is_none());
    }
}
