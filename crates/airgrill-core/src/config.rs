//! airgrill configuration.
//!
//! Everything the daemon needs lives in one TOML file.  Unknown keys are
//! rejected so that a typo in a rule list never silently disables routing.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// A final action for a flow.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    #[default]
    Direct,
    /// Direct, but TCP payloads are reshaped by the DPI-evasion engine.
    Dpi,
    /// Through the configured VLESS/VMess/... backend.
    Proxy,
    Block,
}

impl Route {
    pub const ALL: [Route; 4] = [Route::Direct, Route::Dpi, Route::Proxy, Route::Block];

    pub fn index(self) -> usize {
        match self {
            Route::Direct => 0,
            Route::Dpi => 1,
            Route::Proxy => 2,
            Route::Block => 3,
        }
    }

    /// Order used when the same host/IP matches several lists.
    /// Block wins over everything, then proxy, then dpi, then direct.
    pub const PRECEDENCE: [Route; 4] = [Route::Block, Route::Proxy, Route::Dpi, Route::Direct];

    pub fn as_str(self) -> &'static str {
        match self {
            Route::Direct => "direct",
            Route::Dpi => "dpi",
            Route::Proxy => "proxy",
            Route::Block => "block",
        }
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Route {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "direct" => Ok(Route::Direct),
            "dpi" | "goodbye" | "desync" => Ok(Route::Dpi),
            "proxy" | "vpn" => Ok(Route::Proxy),
            "block" | "drop" => Ok(Route::Block),
            other => Err(format!(
                "unknown route '{other}' (expected direct|dpi|proxy|block)"
            )),
        }
    }
}

/// How the routing table is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Every list is authoritative; unmatched traffic goes to `default_route`.
    #[default]
    Lists,
    /// Unmatched traffic is proxied.  `lists.direct` / `lists.dpi` / `lists.block`
    /// still act as exceptions.
    ProxyDefault,
    /// Unmatched traffic is sent directly with DPI evasion.
    DpiDefault,
    /// Unmatched traffic is sent directly.
    DirectDefault,
    /// Unmatched traffic is dropped.
    BlockDefault,
}

impl Mode {
    pub fn default_route(self, lists_default: Route) -> Route {
        match self {
            Mode::Lists => lists_default,
            Mode::ProxyDefault => Route::Proxy,
            Mode::DpiDefault => Route::Dpi,
            Mode::DirectDefault => Route::Direct,
            Mode::BlockDefault => Route::Block,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// `error`, `warn`, `info`, `debug` or `trace`.
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListConfig {
    #[serde(default)]
    pub proxy: Vec<String>,
    #[serde(default)]
    pub dpi: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

impl ListConfig {
    pub fn get(&self, route: Route) -> &[String] {
        match route {
            Route::Direct => &self.direct,
            Route::Dpi => &self.dpi,
            Route::Proxy => &self.proxy,
            Route::Block => &self.block,
        }
    }
}

/// One arbitrary named rule/list.  Rules are evaluated in `priority` order
/// (higher first), then in declaration order; the first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Optional name used in logs and `airgrill route`.
    #[serde(default)]
    pub name: Option<String>,
    pub route: Route,
    /// Domain/CIDR rules.  `domains = [...]` and `match = [...]` are accepted
    /// as aliases of `entries`.
    #[serde(default, alias = "domains", alias = "match", alias = "list")]
    pub entries: Vec<String>,
    /// Proxy backend override for this list (route = "proxy").
    #[serde(default)]
    pub backend: Option<String>,
    /// DPI strategy override for this list (route = "dpi").
    #[serde(default)]
    pub strategy: Option<String>,
    /// Larger values are checked first.  Equal priorities keep declaration
    /// order.
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub default_route: Route,
    /// Arbitrary named lists with their own route.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Legacy fixed lists (`proxy`/`dpi`/`direct`/`block`); imported after
    /// explicit `rules` with the historical block > proxy > dpi > direct
    /// precedence.
    #[serde(default)]
    pub lists: ListConfig,
    /// Backend used for `proxy` routes.  Defaults to `proxy.default_backend`.
    #[serde(default)]
    pub proxy_backend: Option<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Lists,
            default_route: Route::Direct,
            rules: Vec::new(),
            lists: ListConfig::default(),
            proxy_backend: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `disorder:sni`, `fake:sni`, `split:sni`, `overlap:sni`, `ipfrag:sni`.
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default = "default_decoy")]
    pub decoy: String,
    #[serde(default = "default_queue")]
    pub queue_num: u16,
    /// How many packets of a connection may enter NFQUEUE.  The ClientHello is
    /// always in the first few packets.
    #[serde(default = "default_max_packets")]
    pub max_packets: u32,
    #[serde(default)]
    pub delay_ms: u64,
    /// Bytes of payload in the first IP fragment (`0` = half).
    #[serde(default)]
    pub frag_first: usize,
    #[serde(default)]
    pub frag_reverse: bool,
}

fn default_true() -> bool {
    true
}
fn default_strategy() -> String {
    "disorder:sni".into()
}
fn default_decoy() -> String {
    "example.com".into()
}
fn default_queue() -> u16 {
    200
}
fn default_max_packets() -> u32 {
    16
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: default_strategy(),
            decoy: default_decoy(),
            queue_num: default_queue(),
            max_packets: default_max_packets(),
            delay_ms: 0,
            frag_first: 0,
            frag_reverse: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Listen address.  :53 is hijacked by nftables and redirected here, so
    /// the daemon itself does not need to bind a privileged port.
    #[serde(default = "default_dns_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<SocketAddr>,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
    /// Cache size in entries.
    #[serde(default = "default_dns_cache")]
    pub cache_entries: usize,
}

fn default_dns_listen() -> SocketAddr {
    "0.0.0.0:15353".parse().expect("static addr")
}
fn default_upstreams() -> Vec<SocketAddr> {
    vec![
        "1.1.1.1:53".parse().expect("static addr"),
        "8.8.8.8:53".parse().expect("static addr"),
    ]
}
fn default_min_ttl() -> u32 {
    30
}
fn default_max_ttl() -> u32 {
    3600
}
fn default_dns_cache() -> usize {
    4096
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_dns_listen(),
            upstreams: default_upstreams(),
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            cache_entries: default_dns_cache(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    /// Spawn an external Xray core and use its SOCKS5 inbound.
    #[default]
    Xray,
    /// In-process VLESS implementation (TCP/TLS/WS; no Reality yet).
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub name: String,
    #[serde(default)]
    pub kind: BackendKind,
    /// `vless://...` link.  Used by both backends.
    #[serde(default)]
    pub url: Option<String>,
    /// Read the VLESS link from a file at runtime.  Keeps the secret out of
    /// the Nix store / world-readable config.
    #[serde(default)]
    pub url_file: Option<std::path::PathBuf>,
    /// Raw Xray JSON config (outbounds etc.).  Xray backend only; when set it
    /// is used verbatim instead of generating an outbound from `url`.
    #[serde(default)]
    pub xray_config: Option<std::path::PathBuf>,
    #[serde(default = "default_xray_binary")]
    pub xray_binary: String,
    #[serde(default = "default_socks_addr")]
    pub socks_addr: SocketAddr,
    /// Xray runs under this uid so its own outbound traffic is not captured by
    /// the transparent rules.  0 means "do not change uid" (only safe when the
    /// nftables rules skip traffic by cgroup/mark instead).
    #[serde(default = "default_xray_uid")]
    pub run_as_uid: u32,
    /// Allow invalid TLS certificates (native backend).
    #[serde(default)]
    pub insecure: bool,
}

fn default_xray_binary() -> String {
    "xray".into()
}
fn default_socks_addr() -> SocketAddr {
    "127.0.0.1:10808".parse().expect("static addr")
}
fn default_xray_uid() -> u32 {
    65534
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInboundConfig {
    /// Local HTTP CONNECT proxy.  Hiddify/ByeDPI-style environments often set
    /// `http_proxy=http://127.0.0.1:12334`; keeping this port alive means the
    /// agent/tools survive the switch away from Hiddify.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mixed_listen")]
    pub listen: SocketAddr,
}

fn default_mixed_listen() -> SocketAddr {
    "127.0.0.1:12334".parse().expect("static addr")
}

impl Default for ProxyInboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_mixed_listen(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub default_backend: Option<String>,
    #[serde(default)]
    pub backends: Vec<BackendConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// When false, only this host's traffic is handled.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces whose forwarded traffic should be intercepted.
    #[serde(default = "default_lan_ifaces")]
    pub lan_interfaces: Vec<String>,
    /// Source networks considered LAN (used for exclusions / docs).
    #[serde(default = "default_lan_cidrs")]
    pub lan_cidrs: Vec<ipnet::IpNet>,
    /// Transparent listener for both host (REDIRECT) and LAN (TPROXY) TCP.
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
    /// Intercept these destination ports for traffic originating on this host.
    #[serde(default = "default_host_ports")]
    pub host_tcp_ports: Vec<u16>,
    /// Intercept *all* outbound TCP on the host (except the exclusions below).
    #[serde(default)]
    pub host_all_tcp: bool,
    /// Intercept all forwarded TCP from the LAN.
    #[serde(default = "default_true")]
    pub lan_all_tcp: bool,
    /// Never intercept traffic to private destinations (LAN peers, printers...).
    #[serde(default = "default_true")]
    pub bypass_private: bool,
    /// Add a masquerade rule for non-intercepted forwarded traffic.
    #[serde(default)]
    pub masquerade: bool,
}

fn default_lan_ifaces() -> Vec<String> {
    vec!["eno2".into()]
}
fn default_lan_cidrs() -> Vec<ipnet::IpNet> {
    vec!["10.10.10.0/24".parse().expect("static cidr")]
}
fn default_tcp_port() -> u16 {
    16000
}
fn default_host_ports() -> Vec<u16> {
    vec![80, 443]
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lan_interfaces: default_lan_ifaces(),
            lan_cidrs: default_lan_cidrs(),
            tcp_port: default_tcp_port(),
            host_tcp_ports: default_host_ports(),
            host_all_tcp: false,
            lan_all_tcp: true,
            bypass_private: true,
            masquerade: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum QuicMode {
    /// Drop UDP/443; browsers fall back to TCP, which we can route and desync.
    #[default]
    Block,
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Intercept UDP (host and LAN) into a userspace TUN datapath.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_v4")]
    pub address_v4: Ipv4Addr,
    #[serde(default = "default_tun_v6")]
    pub address_v6: Ipv6Addr,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// Policy-routing table used for marked UDP.
    #[serde(default = "default_tun_table")]
    pub table: u32,
    #[serde(default)]
    pub quic: QuicMode,
    #[serde(default = "default_udp_idle")]
    pub idle_timeout_secs: u64,
}

fn default_tun_name() -> String {
    "airgrill0".into()
}
fn default_tun_v4() -> Ipv4Addr {
    Ipv4Addr::new(198, 18, 0, 1)
}
fn default_tun_v6() -> Ipv6Addr {
    "fd00:6169:7267::1".parse().expect("static addr")
}
fn default_tun_mtu() -> u16 {
    1500
}
fn default_tun_table() -> u32 {
    100
}
fn default_udp_idle() -> u64 {
    60
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: default_tun_name(),
            address_v4: default_tun_v4(),
            address_v6: default_tun_v6(),
            mtu: default_tun_mtu(),
            table: default_tun_table(),
            quic: QuicMode::Block,
            idle_timeout_secs: default_udp_idle(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub dpi: DpiConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub proxy_inbound: ProxyInboundConfig,
    #[serde(default)]
    pub router: RouterConfig,
    #[serde(default)]
    pub tun: TunConfig,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text).context("parsing TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("config {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.dpi.enabled {
            crate::rules::parse_strategy(&self.dpi.strategy)
                .map_err(|e| anyhow::anyhow!("dpi.strategy: {e}"))?;
        }
        if (self.routing.mode == Mode::ProxyDefault || self.routing.default_route == Route::Proxy)
            && self.proxy.backends.is_empty()
        {
            bail!("routing mode requires a proxy backend, but [proxy].backends is empty");
        }
        if let Some(name) = self
            .routing
            .proxy_backend
            .as_deref()
            .or(self.proxy.default_backend.as_deref())
        {
            if !self.proxy.backends.iter().any(|b| b.name == name) {
                bail!("proxy backend '{name}' is not defined in [[proxy.backends]]");
            }
        }
        let mut names = std::collections::HashSet::new();
        let mut socks_addrs = std::collections::HashSet::new();
        for b in &self.proxy.backends {
            if !names.insert(b.name.clone()) {
                bail!("duplicate proxy backend name '{}'", b.name);
            }
            if b.kind == BackendKind::Xray && !socks_addrs.insert(b.socks_addr) {
                bail!("two xray backends use the same socks_addr {}", b.socks_addr);
            }
        }
        for b in &self.proxy.backends {
            if b.url.is_none() && b.url_file.is_none() && b.xray_config.is_none() {
                bail!(
                    "proxy backend '{}' needs url = \"vless://...\", url_file = \"/path\" or xray_config = \"...\"",
                    b.name
                );
            }
            if b.kind == BackendKind::Xray && b.run_as_uid == 0 {
                tracing::warn!(
                    backend = %b.name,
                    "xray backend runs as root; its outbound traffic may be captured by the transparent rules"
                );
            }
        }
        let mut rule_names = std::collections::HashSet::new();
        for (i, rule) in self.routing.rules.iter().enumerate() {
            let label = rule
                .name
                .clone()
                .unwrap_or_else(|| format!("routing.rules[{i}]"));
            if rule.entries.is_empty() {
                bail!("{label}: entries/domains is empty");
            }
            for item in &rule.entries {
                crate::rules::validate_rule(item)
                    .with_context(|| format!("{label}: rule '{item}'"))?;
            }
            if let Some(name) = &rule.name {
                if !name.is_empty() && !rule_names.insert(name.clone()) {
                    bail!("duplicate rule name '{name}'");
                }
            }
            if let Some(backend) = &rule.backend {
                if !self.proxy.backends.iter().any(|b| &b.name == backend) {
                    bail!("{label}: unknown backend '{backend}'");
                }
            }
            if rule.route == Route::Proxy && self.proxy.backends.is_empty() {
                bail!("{label}: route = proxy, but no [[proxy.backends]] are configured");
            }
            if rule.route == Route::Dpi {
                let strategy = rule.strategy.as_deref().unwrap_or(&self.dpi.strategy);
                crate::rules::parse_strategy(strategy)
                    .map_err(|e| anyhow::anyhow!("{label}: strategy: {e}"))?;
            }
        }
        if !self.routing.rules.is_empty()
            && self.routing.rules.iter().any(|r| r.route == Route::Proxy)
            && self.proxy.backends.is_empty()
        {
            bail!("proxy rules are configured, but [[proxy.backends]] is empty");
        }
        let needs_default = self.routing.mode == Mode::ProxyDefault
            || self.routing.default_route == Route::Proxy
            || !self.routing.lists.proxy.is_empty()
            || self
                .routing
                .rules
                .iter()
                .any(|r| r.route == Route::Proxy && r.backend.is_none());
        if needs_default
            && self.proxy.backends.len() > 1
            && self.routing.proxy_backend.is_none()
            && self.proxy.default_backend.is_none()
        {
            bail!(
                "several proxy backends are configured; set proxy.default_backend or routing.proxy_backend"
            );
        }
        if self.tun.enabled && (self.tun.name.is_empty() || self.tun.name.len() > 15) {
            bail!("tun.name must be 1..=15 characters (Linux interface name limit)");
        }
        if self.router.enabled && self.router.lan_interfaces.is_empty() {
            bail!("router.enabled = true requires router.lan_interfaces");
        }
        if self.router.enabled && self.dns.enabled && self.dns.listen.ip().is_loopback() {
            tracing::warn!(
                listen = %self.dns.listen,
                "DNS listens on loopback but router.enabled = true; LAN clients cannot reach it"
            );
        }
        if self.router.tcp_port == 0 {
            bail!("router.tcp_port must not be 0");
        }
        if self.proxy_inbound.enabled && self.proxy_inbound.listen.port() == 0 {
            bail!("proxy_inbound.listen must not use port 0");
        }
        for net in &self.router.lan_cidrs {
            if !net.addr().is_ipv4() && !net.addr().is_ipv6() {
                bail!("invalid LAN network {net}");
            }
        }
        for list in [
            &self.routing.lists.proxy,
            &self.routing.lists.dpi,
            &self.routing.lists.direct,
            &self.routing.lists.block,
        ] {
            // Compile once here so `airgrill check` fails early and the daemon
            // never starts with a broken regex.
            for item in list {
                crate::rules::validate_rule(item)?;
            }
        }
        Ok(())
    }

    /// All private/loopback/link-local networks that should never enter the
    /// tunnel.
    pub fn bypass_nets(&self) -> Vec<ipnet::IpNet> {
        let mut nets: Vec<ipnet::IpNet> = Vec::new();
        if self.router.bypass_private {
            for s in [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "224.0.0.0/4",
                "255.255.255.255/32",
                "::1/128",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
            ] {
                nets.push(s.parse().expect("static cidr"));
            }
        }
        nets.extend(self.router.lan_cidrs.iter().copied());
        merge_nets(nets)
    }

    pub fn listen_dns_ip(&self) -> IpAddr {
        self.dns.listen.ip()
    }
}

/// Sort and remove networks contained in a more general one.  nftables
/// interval sets reject overlapping elements.
pub fn merge_nets(mut nets: Vec<ipnet::IpNet>) -> Vec<ipnet::IpNet> {
    nets.sort_by_key(|n| (n.addr().is_ipv6(), n.prefix_len(), n.addr()));
    nets.dedup();
    let mut out: Vec<ipnet::IpNet> = Vec::with_capacity(nets.len());
    for net in nets {
        let covered = out.iter().any(|prev| {
            prev.addr().is_ipv4() == net.addr().is_ipv4()
                && prev.prefix_len() <= net.prefix_len()
                && prev.contains(&net.addr())
        });
        if !covered {
            out.push(net);
        }
    }
    out
}
