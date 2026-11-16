//! Minimal SOCKS5 client (CONNECT + UDP ASSOCIATE).
//!
//! This is the bridge to an external Xray core: Xray implements VLESS,
//! Reality, Vision, gRPC, ... and exposes a SOCKS5 inbound; we only need the
//! small protocol.

use crate::backend::{ProxyBackend, UdpSession};
use crate::target::{parse_socks_addr, Target};
use airgrill_net::sock::connect_marked;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks5Backend {
    name: String,
    socks: SocketAddr,
    mark: u32,
}

impl Socks5Backend {
    pub fn new(name: impl Into<String>, socks: SocketAddr, mark: u32) -> Self {
        Self {
            name: name.into(),
            socks,
            mark,
        }
    }

    async fn handshake(&self) -> Result<TcpStream> {
        let mut stream = connect_marked(self.socks, self.mark, CONNECT_TIMEOUT)
            .await
            .with_context(|| format!("connecting to SOCKS5 at {}", self.socks))?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp != [5, 0] {
            bail!("SOCKS5 auth negotiation failed: {resp:?}");
        }
        Ok(stream)
    }

    async fn associate_udp(&self) -> Result<(TcpStream, SocketAddr)> {
        let mut control = self.handshake().await?;
        let mut req = vec![5u8, 3, 0]; // UDP ASSOCIATE
        Target::new("0.0.0.0".parse().unwrap(), 0, None).encode_addr(&mut req)?;
        control.write_all(&req).await?;

        let mut head = [0u8; 4];
        control.read_exact(&mut head).await?;
        if head[0] != 5 {
            bail!("bad SOCKS5 UDP reply version {}", head[0]);
        }
        if head[1] != 0 {
            bail!("SOCKS5 UDP ASSOCIATE failed with code {}", head[1]);
        }
        let relay = read_socks_reply_addr(&mut control, head[3]).await?;
        let relay = if relay.ip().is_unspecified() || relay.port() == 0 {
            SocketAddr::new(self.socks.ip(), relay.port())
        } else {
            relay
        };
        if relay.port() == 0 {
            bail!("SOCKS5 server returned an empty UDP relay address");
        }
        Ok((control, relay))
    }
}

async fn read_socks_reply_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
    let (host, port) = match atyp {
        1 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            (ip.to_string(), u16::from_be_bytes([b[4], b[5]]))
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut b = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut b).await?;
            let host = String::from_utf8(b[..len[0] as usize].to_vec())?;
            let port = u16::from_be_bytes([b[len[0] as usize], b[len[0] as usize + 1]]);
            (host, port)
        }
        4 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
            (ip.to_string(), u16::from_be_bytes([b[16], b[17]]))
        }
        other => bail!("unknown SOCKS5 address type {other}"),
    };
    let ip = host
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    Ok(SocketAddr::new(ip, port))
}

#[async_trait]
impl ProxyBackend for Socks5Backend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "socks5"
    }

    async fn connect_tcp(&self, target: &Target) -> Result<crate::vless::BoxStream> {
        let mut stream = self.handshake().await?;
        let mut req = vec![5u8, 1, 0];
        target.encode_addr(&mut req)?;
        stream.write_all(&req).await?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != 5 {
            bail!("bad SOCKS5 reply version {}", head[0]);
        }
        if head[1] != 0 {
            bail!(
                "SOCKS5 CONNECT to {} failed with code {}",
                target.display(),
                head[1]
            );
        }
        // Drain the bound address.
        match head[3] {
            1 => {
                let mut b = [0u8; 6];
                stream.read_exact(&mut b).await?;
            }
            3 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut b = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut b).await?;
            }
            4 => {
                let mut b = [0u8; 18];
                stream.read_exact(&mut b).await?;
            }
            other => bail!("unknown SOCKS5 address type {other}"),
        }
        Ok(Box::new(stream))
    }

    async fn open_udp(&self, target: &Target) -> Result<UdpSession> {
        let (mut control, relay) = self.associate_udp().await?;
        let bind: SocketAddr = if relay.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let udp = Arc::new(airgrill_net::sock::udp_socket_marked(bind, self.mark)?);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let target = target.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut ctrl_buf = [0u8; 1];
            loop {
                tokio::select! {
                    data = out_rx.recv() => {
                        let Some(data) = data else { break };
                        let mut dgram = vec![0u8, 0, 0];
                        if target.encode_addr(&mut dgram).is_err() {
                            continue;
                        }
                        dgram.extend_from_slice(&data);
                        if let Err(e) = udp.send_to(&dgram, relay).await {
                            tracing::debug!(error = %e, "SOCKS5 UDP send failed");
                            break;
                        }
                    }
                    res = udp.recv_from(&mut buf) => {
                        let Ok((n, _from)) = res else { break };
                        match socks_payload(&buf[..n]) {
                            Ok(payload) if !payload.is_empty() => {
                                if in_tx.send(payload.to_vec()).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => tracing::trace!(error = %e, "bad SOCKS5 UDP datagram"),
                        }
                    }
                    res = control.read(&mut ctrl_buf) => {
                        // The server closes the control connection when the
                        // association ends.
                        match res {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
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
}

fn socks_payload(dgram: &[u8]) -> Result<&[u8]> {
    if dgram.len() < 4 {
        bail!("short SOCKS5 UDP datagram");
    }
    if dgram[0] != 0 || dgram[1] != 0 {
        bail!("reserved bytes set");
    }
    if dgram[2] != 0 {
        bail!("fragmented SOCKS5 UDP datagrams are not supported");
    }
    let (_, _, used) = parse_socks_addr(&dgram[3..])?;
    Ok(&dgram[3 + used..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_payload() {
        let mut d = vec![0, 0, 0, 1, 1, 2, 3, 4, 0x01, 0xbb];
        d.extend_from_slice(b"hello");
        assert_eq!(socks_payload(&d).unwrap(), b"hello");
    }

    #[test]
    fn rejects_fragments() {
        let d = [0u8, 0, 1, 1, 1, 2, 3, 4, 0, 80];
        assert!(socks_payload(&d).is_err());
    }
}
