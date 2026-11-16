//! Native VLESS client: TCP, TLS and WebSocket transports.
//!
//! Limitations are explicit rather than silent:
//!  * Reality (`security=reality`) is **not** implemented here — it needs a
//!    custom TLS ClientHello and uTLS fingerprinting.  Use `kind = "xray"` for
//!    Reality servers.
//!  * XTLS Vision (`flow=xtls-rprx-vision`) is not implemented.  Use xray.
//!  * UDP uses the classic VLESS UDP framing (2-byte length per datagram).

use crate::backend::{ProxyBackend, UdpSession};
use crate::target::Target;

use airgrill_net::sock::connect_marked;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use url::{Host, Url};
use uuid::Uuid;

pub type BoxStream = Box<dyn AsyncReadWrite>;
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Ws,
    Grpc,
    HttpUpgrade,
}

#[derive(Debug, Clone)]
pub struct VlessUrl {
    pub uuid: Uuid,
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub network: Network,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    pub flow: Option<String>,
    pub path: String,
    pub ws_host: Option<String>,
    /// Xray WS early-data header (Hiddify uses `Sec-WebSocket-Protocol`).
    pub early_data_header: Option<String>,
    pub service_name: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
    pub insecure: bool,
    /// Modern Xray: pin the peer certificate, hex SHA-256 of the DER cert.
    pub pinned_sha256: Option<String>,
    /// Modern Xray: verify the certificate against this name.
    pub verify_name: Option<String>,
    pub encryption: String,
}

impl VlessUrl {
    pub fn parse(link: &str) -> Result<Self> {
        let url = Url::parse(link).with_context(|| "parsing VLESS URL")?;
        if url.scheme() != "vless" {
            bail!("expected a vless:// URL, got scheme '{}'", url.scheme());
        }
        let uuid = Uuid::parse_str(url.username())
            .with_context(|| format!("invalid UUID '{}'", url.username()))?;
        let host = match url.host() {
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(ip)) => ip.to_string(),
            Some(Host::Domain(d)) => d.to_string(),
            None => bail!("VLESS URL has no host"),
        };
        let q: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let security = match q.get("security").map(String::as_str).unwrap_or("none") {
            "" | "none" => Security::None,
            "tls" => Security::Tls,
            "reality" => Security::Reality,
            other => bail!("unsupported security '{other}'"),
        };
        let network = match q.get("type").map(String::as_str).unwrap_or("tcp") {
            "" | "tcp" | "raw" => Network::Tcp,
            "ws" | "websocket" => Network::Ws,
            "grpc" | "gun" => Network::Grpc,
            "httpupgrade" => Network::HttpUpgrade,
            other => bail!("unsupported transport '{other}'"),
        };
        let port = url.port().unwrap_or(match security {
            Security::Tls | Security::Reality => 443,
            Security::None => 80,
        });
        let sni = q
            .get("sni")
            .cloned()
            .or_else(|| q.get("peer").cloned())
            .or_else(|| q.get("host").cloned())
            .or_else(|| Some(host.clone()).filter(|h| h.parse::<std::net::IpAddr>().is_err()));
        let alpn = q
            .get("alpn")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let insecure = matches!(
            q.get("allowInsecure")
                .map(String::as_str)
                .or(q.get("insecure").map(String::as_str)),
            Some("1" | "true" | "yes")
        );
        let path = q
            .get("path")
            .cloned()
            .map(|p| {
                if p.starts_with('/') {
                    p
                } else {
                    format!("/{p}")
                }
            })
            .unwrap_or_else(|| "/".into());
        let ws_host = q.get("host").cloned().filter(|h| !h.is_empty());
        let early_data_header = q
            .get("eh")
            .cloned()
            .or_else(|| q.get("earlyDataHeaderName").cloned())
            .filter(|h| !h.is_empty());
        Ok(Self {
            uuid,
            host,
            port,
            security,
            network,
            sni,
            alpn,
            fingerprint: q.get("fp").cloned(),
            flow: q.get("flow").cloned().filter(|f| !f.is_empty()),
            path,
            ws_host,
            early_data_header,
            service_name: q.get("serviceName").cloned(),
            public_key: q.get("pbk").cloned(),
            short_id: q.get("sid").cloned(),
            spider_x: q.get("spx").cloned(),
            insecure,
            pinned_sha256: q
                .get("pcs")
                .cloned()
                .or_else(|| q.get("pinnedPeerCertSha256").cloned()),
            verify_name: q
                .get("vcn")
                .cloned()
                .or_else(|| q.get("verifyPeerCertByName").cloned()),
            encryption: q
                .get("encryption")
                .cloned()
                .unwrap_or_else(|| "none".into()),
        })
    }
}

pub struct VlessBackend {
    name: String,
    url: VlessUrl,
    tls: Option<Arc<rustls::ClientConfig>>,
    mark: u32,
}

impl VlessBackend {
    pub fn new(name: String, link: &str, insecure_override: bool, mark: u32) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut url = VlessUrl::parse(link)?;
        if url.encryption != "none" && !url.encryption.is_empty() {
            bail!("native VLESS supports encryption=none only");
        }
        if url.security == Security::Reality {
            bail!("native backend does not implement Reality; set kind = \"xray\" for this server");
        }
        if url.flow.is_some() {
            bail!(
                "native backend does not implement flow={}; set kind = \"xray\"",
                url.flow.as_deref().unwrap_or("")
            );
        }
        if matches!(url.network, Network::Grpc | Network::HttpUpgrade) {
            bail!(
                "native backend supports tcp and ws transports only; got {:?}",
                url.network
            );
        }
        if insecure_override {
            url.insecure = true;
        }

        let tls = (url.security == Security::Tls).then(|| {
            let provider = rustls::crypto::ring::default_provider();
            let mut cfg = if url.insecure {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify { provider }))
                    .with_no_client_auth()
            } else {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            };
            cfg.alpn_protocols = url.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
            Arc::new(cfg)
        });

        Ok(Self {
            name,
            url,
            tls,
            mark,
        })
    }

    pub fn url(&self) -> &VlessUrl {
        &self.url
    }

    async fn tcp_connect(&self) -> Result<TcpStream> {
        let addr = if let Ok(ip) = self.url.host.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, self.url.port)
        } else {
            let mut it = tokio::net::lookup_host((self.url.host.as_str(), self.url.port))
                .await
                .with_context(|| format!("resolving {}", self.url.host))?;
            it.next()
                .ok_or_else(|| anyhow::anyhow!("no address for {}", self.url.host))?
        };
        connect_marked(addr, self.mark, Duration::from_secs(10))
            .await
            .with_context(|| format!("connecting to {}:{}", self.url.host, self.url.port))
    }

    async fn open_stream(&self, target: &Target, cmd: u8) -> Result<BoxStream> {
        let tcp = self.tcp_connect().await?;
        let mut stream: BoxStream = match (self.url.security, &self.tls) {
            (Security::Tls, Some(cfg)) => {
                let sni = self
                    .url
                    .sni
                    .clone()
                    .unwrap_or_else(|| self.url.host.clone());
                let server_name = if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
                    ServerName::from(ip)
                } else {
                    ServerName::try_from(sni.clone())
                        .map_err(|e| anyhow::anyhow!("invalid TLS server name '{sni}': {e}"))?
                };
                let connector = TlsConnector::from(Arc::clone(cfg));
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .with_context(|| format!("TLS handshake with {sni}"))?;
                Box::new(tls)
            }
            (Security::None, _) => Box::new(tcp),
            (Security::Tls, None) => bail!("internal: TLS config missing"),
            (Security::Reality, _) => unreachable!("rejected in constructor"),
        };

        if self.url.network == Network::Ws {
            stream = ws_connect(stream, &self.url).await?;
        }

        let mut header = Vec::with_capacity(32);
        header.push(0); // VLESS version
        header.extend_from_slice(self.url.uuid.as_bytes());
        header.push(0); // no addons
        header.push(cmd); // 1 = TCP, 2 = UDP
        target.encode_vless_addr(&mut header)?;
        stream.write_all(&header).await?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != 0 {
            bail!("VLESS server replied with version {}", resp[0]);
        }
        if resp[1] > 0 {
            let mut addons = vec![0u8; resp[1] as usize];
            stream.read_exact(&mut addons).await?;
        }
        Ok(stream)
    }
}

#[async_trait]
impl ProxyBackend for VlessBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vless"
    }

    async fn connect_tcp(&self, target: &Target) -> Result<BoxStream> {
        self.open_stream(target, 1).await
    }

    async fn open_udp(&self, target: &Target) -> Result<UdpSession> {
        let stream = self.open_stream(target, 2).await?;
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);

        tokio::spawn(async move {
            let read = async {
                loop {
                    let mut len = [0u8; 2];
                    if rd.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    if n == 0 {
                        continue;
                    }
                    let mut buf = vec![0u8; n];
                    if rd.read_exact(&mut buf).await.is_err() {
                        break;
                    }
                    if in_tx.send(buf).await.is_err() {
                        break;
                    }
                }
            };
            let write = async {
                while let Some(data) = out_rx.recv().await {
                    if data.len() > u16::MAX as usize {
                        continue;
                    }
                    if wr
                        .write_all(&(data.len() as u16).to_be_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if wr.write_all(&data).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = read => {},
                _ = write => {},
            }
        });

        Ok(UdpSession {
            outgoing: out_tx,
            incoming: in_rx,
        })
    }
}

async fn ws_connect(stream: BoxStream, url: &VlessUrl) -> Result<BoxStream> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    let host_header = url.ws_host.clone().unwrap_or_else(|| {
        let default_port = matches!(url.security, Security::Tls | Security::Reality);
        if (default_port && url.port == 443) || (!default_port && url.port == 80) {
            url.host.clone()
        } else if url.host.contains(':') {
            format!("[{}]:{}", url.host, url.port)
        } else {
            format!("{}:{}", url.host, url.port)
        }
    });
    let mut req = format!("ws://{host_header}{}", url.path).into_client_request()?;
    req.headers_mut().insert(
        "Host",
        HeaderValue::from_str(&host_header)
            .with_context(|| format!("invalid WS Host header '{host_header}'"))?,
    );

    let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
        .await
        .context("WebSocket handshake")?;

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (client, server) = tokio::io::duplex(256 * 1024);
    // `from_client` carries bytes written by the VLESS client; `to_client`
    // receives WebSocket frames destined for the client.
    let (mut from_client, mut to_client) = tokio::io::split(server);

    tokio::spawn(async move {
        let read = async {
            while let Some(msg) = ws_rx.next().await {
                match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Binary(data)) => {
                        if to_client.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                        if to_client.write_all(text.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
        };
        let write = async {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = match from_client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let msg = tokio_tungstenite::tungstenite::Message::Binary(buf[..n].to_vec().into());
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
        };
        tokio::select! {
            _ = read => {},
            _ = write => {},
        }
    });

    Ok(Box::new(client))
}

#[derive(Debug)]
struct NoVerify {
    provider: rustls::crypto::CryptoProvider,
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_url() {
        let u = VlessUrl::parse(
            "vless://11111111-2222-3333-4444-555555555555@vps.example:443?security=tls&type=ws&path=%2Fws&host=cdn.example&sni=cdn.example&alpn=h2%2Chttp%2F1.1&fp=chrome#name",
        )
        .unwrap();
        assert_eq!(u.host, "vps.example");
        assert_eq!(u.port, 443);
        assert_eq!(u.security, Security::Tls);
        assert_eq!(u.network, Network::Ws);
        assert_eq!(u.path, "/ws");
        assert_eq!(u.ws_host.as_deref(), Some("cdn.example"));
        assert_eq!(u.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn rejects_reality_in_native_backend() {
        let e = VlessBackend::new(
            "x".into(),
            "vless://11111111-2222-3333-4444-555555555555@vps.example:443?security=reality&pbk=abc&sid=00",
            false,
            airgrill_core::marks::MARK_SKIP,
        );
        assert!(e.is_err());
    }

    #[test]
    fn parses_ipv6_host() {
        let u = VlessUrl::parse(
            "vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:8443?security=tls&sni=example.com",
        )
        .unwrap();
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.port, 8443);
    }
}
