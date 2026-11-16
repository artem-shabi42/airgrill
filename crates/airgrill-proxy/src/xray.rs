//! External Xray-core process.
//!
//! Xray gives us the full protocol matrix (VLESS, VMess, Trojan, Reality,
//! XTLS Vision, gRPC, ...).  It listens on a local SOCKS5 port; airgrill sends
//! the connections that belong to the `proxy` route there.
//!
//! Xray deliberately runs under a non-root uid: its own outbound sockets are
//! then skipped by the nftables rules (`meta skuid`), avoiding a redirect loop.

use crate::backend::ProxyBackend;
use crate::vless::{Network, Security, VlessUrl};
use airgrill_core::config::BackendConfig;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct XrayProcess {
    child: Option<Child>,
    dir: tempfile::TempDir,
    socks: SocketAddr,
    name: String,
}

impl XrayProcess {
    pub async fn start(cfg: &BackendConfig, _mark: u32) -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("airgrill-xray-")
            .tempdir()
            .context("creating xray config directory")?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;

        let config = build_config(cfg)?;
        let path = dir.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&config)?)
            .with_context(|| format!("writing {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

        let mut cmd = Command::new(&cfg.xray_binary);
        cmd.arg("run")
            .arg("-c")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if cfg.run_as_uid != 0 {
            cmd.uid(cfg.run_as_uid).gid(cfg.run_as_uid);
        }
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "spawning '{}' (set proxy.backends[].xray_binary to an absolute path if it is not in PATH)",
                cfg.xray_binary
            )
        })?;

        // Wait for the SOCKS inbound.
        let deadline = std::time::Instant::now() + Duration::from_secs(7);
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("xray exited during startup: {status}");
            }
            match tokio::net::TcpStream::connect(cfg.socks_addr).await {
                Ok(_) => break,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => {
                    let _ = child.kill();
                    bail!(
                        "xray did not open SOCKS5 on {} within 7s: {e}",
                        cfg.socks_addr
                    );
                }
            }
        }

        tracing::info!(
            backend = %cfg.name,
            socks = %cfg.socks_addr,
            uid = cfg.run_as_uid,
            "xray started"
        );
        Ok(Self {
            child: Some(child),
            dir,
            socks: cfg.socks_addr,
            name: cfg.name.clone(),
        })
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks
    }

    pub fn config_dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!(backend = %self.name, "xray stopped");
        }
    }
}

fn build_config(cfg: &BackendConfig) -> Result<Value> {
    let socks_inbound = json!({
        "tag": "airgrill-socks",
        "listen": cfg.socks_addr.ip().to_string(),
        "port": cfg.socks_addr.port(),
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": true
        }
    });

    let mut root: Value = if let Some(path) = &cfg.xray_config {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading xray config {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("parsing xray config {}", path.display()))?
    } else {
        json!({})
    };
    if !root.is_object() {
        bail!("xray config must be a JSON object");
    }

    if let Some(url_text) = crate::backend::load_url(cfg)? {
        let url = VlessUrl::parse(&url_text)?;
        if root.get("outbounds").is_none() {
            root["outbounds"] = json!([outbound_json(&url)]);
        }
    }
    if root
        .get("outbounds")
        .and_then(Value::as_array)
        .map(|a| a.is_empty())
        .unwrap_or(true)
    {
        bail!("no outbounds: set url = \"vless://...\" or provide xray_config with outbounds");
    }
    root["inbounds"] = json!([socks_inbound]);
    if root.get("log").is_none() {
        root["log"] = json!({ "loglevel": "warning" });
    }
    Ok(root)
}

/// Translate a `vless://` link into an Xray outbound object.
pub fn outbound_json(url: &VlessUrl) -> Value {
    let mut user = Map::new();
    user.insert("id".into(), json!(url.uuid.to_string()));
    user.insert("encryption".into(), json!("none"));
    if let Some(flow) = &url.flow {
        user.insert("flow".into(), json!(flow));
    }

    let mut ss = Map::new();
    let network = match url.network {
        Network::Tcp => "tcp",
        Network::Ws => "ws",
        Network::Grpc => "grpc",
        Network::HttpUpgrade => "httpupgrade",
    };
    ss.insert("network".into(), json!(network));
    match url.security {
        Security::None => {
            ss.insert("security".into(), json!("none"));
        }
        Security::Tls => {
            ss.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            if let Some(sni) = &url.sni {
                tls.insert("serverName".into(), json!(sni));
            }
            if let Some(fp) = &url.fingerprint {
                tls.insert("fingerprint".into(), json!(fp));
            }
            if let Some(pcs) = &url.pinned_sha256 {
                tls.insert("pinnedPeerCertSha256".into(), json!(pcs));
            }
            if let Some(vcn) = &url.verify_name {
                tls.insert("verifyPeerCertByName".into(), json!(vcn));
            }
            if url.insecure && url.pinned_sha256.is_none() && url.verify_name.is_none() {
                tracing::warn!(
                    "allowInsecure was removed from recent Xray versions; use pcs=<sha256> (pinnedPeerCertSha256) in the VLESS URL"
                );
            }
            if !url.alpn.is_empty() {
                tls.insert("alpn".into(), json!(url.alpn));
            }
            ss.insert("tlsSettings".into(), Value::Object(tls));
        }
        Security::Reality => {
            ss.insert("security".into(), json!("reality"));
            let mut reality = Map::new();
            if let Some(sni) = &url.sni {
                reality.insert("serverName".into(), json!(sni));
            }
            reality.insert(
                "fingerprint".into(),
                json!(url.fingerprint.clone().unwrap_or_else(|| "chrome".into())),
            );
            if let Some(pbk) = &url.public_key {
                reality.insert("publicKey".into(), json!(pbk));
            }
            if let Some(sid) = &url.short_id {
                reality.insert("shortId".into(), json!(sid));
            }
            if let Some(spx) = &url.spider_x {
                reality.insert("spiderX".into(), json!(spx));
            }
            ss.insert("realitySettings".into(), Value::Object(reality));
        }
    }

    match url.network {
        Network::Ws => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(url.path));
            if let Some(host) = url.ws_host.clone().or_else(|| url.sni.clone()) {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            if let Some(eh) = &url.early_data_header {
                ws.insert("earlyDataHeaderName".into(), json!(eh));
            }
            ss.insert("wsSettings".into(), Value::Object(ws));
        }
        Network::Grpc => {
            let mut grpc = Map::new();
            if let Some(service) = &url.service_name {
                grpc.insert("serviceName".into(), json!(service));
            }
            ss.insert("grpcSettings".into(), Value::Object(grpc));
        }
        _ => {}
    }

    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": url.host,
                "port": url.port,
                "users": [Value::Object(user)]
            }]
        },
        "streamSettings": Value::Object(ss)
    })
}

/// A backend that is only used for its process handle / docs; the actual
/// SOCKS5 client lives in `socks5.rs`.
#[allow(dead_code)]
pub fn assert_backend(_: &dyn ProxyBackend) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_reality_json() {
        let u = VlessUrl::parse(
            "vless://11111111-2222-3333-4444-555555555555@vps.example:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=abc&sid=01&flow=xtls-rprx-vision&type=tcp",
        )
        .unwrap();
        let out = outbound_json(&u);
        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["streamSettings"]["security"], "reality");
        assert_eq!(out["streamSettings"]["realitySettings"]["publicKey"], "abc");
        assert_eq!(
            out["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
    }

    #[test]
    fn ws_host_header() {
        let u = VlessUrl::parse(
            "vless://11111111-2222-3333-4444-555555555555@vps.example:443?security=tls&type=ws&path=/x&host=cdn.example",
        )
        .unwrap();
        let out = outbound_json(&u);
        assert_eq!(
            out["streamSettings"]["wsSettings"]["headers"]["Host"],
            "cdn.example"
        );
    }
}
