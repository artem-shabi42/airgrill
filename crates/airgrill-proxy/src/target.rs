//! Destination description shared by all backends.

use anyhow::{bail, Result};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Hostname from TLS SNI / HTTP Host / DNS, when known.
    pub host: Option<String>,
    pub ip: IpAddr,
    pub port: u16,
}

impl Target {
    pub fn new(ip: IpAddr, port: u16, host: Option<String>) -> Self {
        Self { host, ip, port }
    }

    pub fn display(&self) -> String {
        match &self.host {
            Some(h) => format!("{h}:{}", self.port),
            None => format!("{}:{}", self.ip, self.port),
        }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// Encode an address for SOCKS5 (`ATYP address port`).  A domain is
    /// preferred so that the remote server can resolve it (and pick a nearby
    /// CDN node).
    pub fn encode_addr(&self, out: &mut Vec<u8>) -> Result<()> {
        if let Some(host) = &self.host {
            let bytes = host.as_bytes();
            if !bytes.is_empty() && bytes.len() <= 255 && !host.contains('\0') {
                out.push(3);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                out.extend_from_slice(&self.port.to_be_bytes());
                return Ok(());
            }
        }
        match self.ip {
            IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(4);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }

    /// VLESS request header address: `port` comes first, then a *different*
    /// address type numbering (2 = domain, 3 = IPv6, unlike SOCKS5's 3/4).
    pub fn encode_vless_addr(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.port.to_be_bytes());
        if let Some(host) = &self.host {
            let bytes = host.as_bytes();
            if !bytes.is_empty() && bytes.len() <= 255 && !host.contains('\0') {
                out.push(2);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                return Ok(());
            }
        }
        match self.ip {
            IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(3);
                out.extend_from_slice(&v6.octets());
            }
        }
        Ok(())
    }
}

/// Parse a SOCKS5 address (ATYP + addr + port) from a buffer.
/// Returns the address and how many bytes were consumed.
pub fn parse_socks_addr(buf: &[u8]) -> Result<(String, u16, usize)> {
    if buf.is_empty() {
        bail!("empty SOCKS address");
    }
    match buf[0] {
        1 => {
            if buf.len() < 1 + 4 + 2 {
                bail!("short IPv4 SOCKS address");
            }
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((ip.to_string(), port, 7))
        }
        3 => {
            if buf.len() < 2 {
                bail!("short domain SOCKS address");
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                bail!("short domain SOCKS address");
            }
            let host = String::from_utf8(buf[2..2 + len].to_vec())
                .map_err(|e| anyhow::anyhow!("invalid SOCKS domain: {e}"))?;
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((host, port, 2 + len + 2))
        }
        4 => {
            if buf.len() < 1 + 16 + 2 {
                bail!("short IPv6 SOCKS address");
            }
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[1..17]).unwrap());
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((ip.to_string(), port, 19))
        }
        other => bail!("unknown SOCKS address type {other}"),
    }
}
