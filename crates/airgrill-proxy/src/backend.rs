//! Backend trait and the UDP session handle.

use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A bidirectional UDP flow.  The backend owns the actual socket / stream and
/// pumps datagrams through the two channels.
pub struct UdpSession {
    pub outgoing: mpsc::Sender<Vec<u8>>,
    pub incoming: mpsc::Receiver<Vec<u8>>,
}

#[async_trait]
pub trait ProxyBackend: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    async fn connect_tcp(&self, target: &Target) -> Result<crate::vless::BoxStream>;
    async fn open_udp(&self, target: &Target) -> Result<UdpSession>;
}

/// All configured backends plus the spawned Xray children.
pub struct Backends {
    map: HashMap<String, Arc<dyn ProxyBackend>>,
    default: Option<String>,
    _xray: Vec<crate::xray::XrayProcess>,
}

impl Backends {
    pub async fn start(cfg: &airgrill_core::config::ProxyConfig, mark: u32) -> Result<Self> {
        let mut map: HashMap<String, Arc<dyn ProxyBackend>> = HashMap::new();
        let mut xray = Vec::new();

        for b in &cfg.backends {
            let backend: Arc<dyn ProxyBackend> = match b.kind {
                airgrill_core::config::BackendKind::Xray => {
                    let proc = crate::xray::XrayProcess::start(b, mark)
                        .await
                        .map_err(|e| anyhow::anyhow!("backend '{}': {e:#}", b.name))?;
                    let socks = proc.socks_addr();
                    xray.push(proc);
                    Arc::new(crate::socks5::Socks5Backend::new(
                        b.name.clone(),
                        socks,
                        mark,
                    ))
                }
                airgrill_core::config::BackendKind::Native => {
                    let url = load_url(b)?.ok_or_else(|| {
                        anyhow::anyhow!("native backend '{}' requires url or url_file", b.name)
                    })?;
                    Arc::new(crate::vless::VlessBackend::new(
                        b.name.clone(),
                        &url,
                        b.insecure,
                        mark,
                    )?)
                }
            };
            tracing::info!(backend = %b.name, kind = backend.kind(), "proxy backend ready");
            if map.insert(b.name.clone(), backend).is_some() {
                anyhow::bail!("duplicate proxy backend name '{}'", b.name);
            }
        }

        let default = cfg
            .default_backend
            .clone()
            .or_else(|| (map.len() == 1).then(|| map.keys().next().cloned().expect("one backend")));
        if let Some(name) = &default {
            if !map.contains_key(name) {
                anyhow::bail!("default_backend '{name}' is not defined");
            }
        }
        Ok(Self {
            map,
            default,
            _xray: xray,
        })
    }

    pub fn get(&self, name: Option<&str>) -> Result<Arc<dyn ProxyBackend>> {
        let name = name
            .map(str::to_string)
            .or_else(|| self.default.clone())
            .ok_or_else(|| anyhow::anyhow!("no proxy backend selected"))?;
        self.map
            .get(&name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown proxy backend '{name}'"))
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Resolve `url` or read `url_file` (the secret stays outside the Nix store).
pub(crate) fn load_url(b: &airgrill_core::config::BackendConfig) -> Result<Option<String>> {
    if let Some(url) = &b.url {
        return Ok(Some(url.clone()));
    }
    if let Some(path) = &b.url_file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading url_file {}: {e}", path.display()))?;
        let text = text.trim();
        if text.is_empty() {
            anyhow::bail!("url_file {} is empty", path.display());
        }
        return Ok(Some(text.to_string()));
    }
    Ok(None)
}
