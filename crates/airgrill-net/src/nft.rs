//! nftables rules and policy routing for the transparent datapath.
//!
//! Everything lives in one table, `inet airgrill`, so cleanup is a single
//! `delete table`.  The rules only *capture* traffic; all routing decisions
//! happen in userspace (TLS SNI, HTTP Host, DNS-observed IP map).

use airgrill_core::marks;
use airgrill_core::{Config, DpiPlan, Route};
use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

pub const TPROXY_TABLE: u32 = 101;
pub const TPROXY_RULE_PRIORITY: u32 = 1001;
pub const TUN_RULE_PRIORITY: u32 = 1000;

#[derive(Debug, Clone)]
pub struct NftRules {
    pub table: String,
    pub host_ports: Vec<u16>,
    pub host_all_tcp: bool,
    pub lan_interfaces: Vec<String>,
    pub lan_all_tcp: bool,
    pub lan_enabled: bool,
    pub tcp_port: u16,
    pub dns_port: Option<u16>,
    /// `(NFQUEUE number, socket mark)` for each distinct DPI strategy.
    pub dpi_queues: Vec<(u16, u32)>,
    pub dpi_max_packets: u32,
    pub tun_enabled: bool,
    pub skip_mark: u32,
    pub tun_mark: u32,
    pub tproxy_mark: u32,
    pub xray_uids: Vec<u32>,
    pub bypass_v4: Vec<IpNet>,
    pub bypass_v6: Vec<IpNet>,
    pub lan_v4: Vec<IpNet>,
    pub lan_v6: Vec<IpNet>,
    pub masquerade: bool,
    pub default_route: Route,
}

impl NftRules {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let bypass = cfg.bypass_nets();
        let bypass_v4 = bypass
            .iter()
            .filter(|n| n.addr().is_ipv4())
            .copied()
            .collect();
        let bypass_v6 = bypass
            .iter()
            .filter(|n| n.addr().is_ipv6())
            .copied()
            .collect();
        let lan_v4 = airgrill_core::config::merge_nets(
            cfg.router
                .lan_cidrs
                .iter()
                .filter(|n| n.addr().is_ipv4())
                .copied()
                .collect(),
        );
        let lan_v6 = airgrill_core::config::merge_nets(
            cfg.router
                .lan_cidrs
                .iter()
                .filter(|n| n.addr().is_ipv6())
                .copied()
                .collect(),
        );
        let mut xray_uids: Vec<u32> = cfg
            .proxy
            .backends
            .iter()
            .filter(|b| b.kind == airgrill_core::config::BackendKind::Xray && b.run_as_uid != 0)
            .map(|b| b.run_as_uid)
            .collect();
        xray_uids.sort_unstable();
        xray_uids.dedup();

        let mut host_ports = cfg.router.host_tcp_ports.clone();
        // Port 53 is handled by the DNS redirect chain; never route it into
        // the TCP relay.
        host_ports.retain(|p| *p != 53);
        host_ports.sort_unstable();
        host_ports.dedup();

        let dpi_plan = DpiPlan::build(cfg)?;
        let dpi_queues = dpi_plan
            .routes()
            .iter()
            .map(|r| (r.queue, marks::dpi_mark(r.id)))
            .collect();

        Ok(Self {
            table: marks::TABLE.into(),
            host_ports,
            host_all_tcp: cfg.router.host_all_tcp,
            lan_interfaces: cfg.router.lan_interfaces.clone(),
            lan_all_tcp: cfg.router.lan_all_tcp,
            lan_enabled: cfg.router.enabled,
            tcp_port: cfg.router.tcp_port,
            dns_port: cfg.dns.enabled.then_some(cfg.dns.listen.port()),
            dpi_queues,
            dpi_max_packets: cfg.dpi.max_packets,
            tun_enabled: cfg.tun.enabled,
            skip_mark: marks::MARK_SKIP,
            tun_mark: marks::MARK_UDP,
            tproxy_mark: marks::MARK_TPROXY,
            xray_uids,
            bypass_v4,
            bypass_v6,
            lan_v4,
            lan_v6,
            masquerade: cfg.router.masquerade,
            default_route: cfg.routing.mode.default_route(cfg.routing.default_route),
        })
    }

    fn set_elements(nets: &[IpNet]) -> String {
        nets.iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn lan_iface_set(&self) -> String {
        self.lan_interfaces
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn skuid_match(&self) -> String {
        if self.xray_uids.is_empty() {
            String::new()
        } else {
            let list = self
                .xray_uids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("meta skuid {{ {list} }} return\n")
        }
    }

    fn port_set(&self) -> String {
        self.host_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn script(&self) -> String {
        let t = &self.table;
        let mut s = String::new();
        s.push_str(&format!("add table inet {t}\n"));
        for (name, ty, nets) in [
            ("bypass_v4", "ipv4_addr", &self.bypass_v4),
            ("bypass_v6", "ipv6_addr", &self.bypass_v6),
            ("lan_v4", "ipv4_addr", &self.lan_v4),
            ("lan_v6", "ipv6_addr", &self.lan_v6),
        ] {
            if nets.is_empty() {
                s.push_str(&format!(
                    "add set inet {t} {name} {{ type {ty}; flags interval; }}\n"
                ));
            } else {
                s.push_str(&format!(
                    "add set inet {t} {name} {{ type {ty}; flags interval; elements = {{ {} }} }}\n",
                    Self::set_elements(nets)
                ));
            }
        }
        if self.lan_interfaces.is_empty() {
            s.push_str(&format!("add set inet {t} lan_ifaces {{ type ifname; }}\n"));
        } else {
            s.push_str(&format!(
                "add set inet {t} lan_ifaces {{ type ifname; elements = {{ {} }} }}\n",
                self.lan_iface_set()
            ));
        }

        // ---- host TCP: REDIRECT into the listener ----
        s.push_str(&format!(
            "add chain inet {t} host_redirect {{ type nat hook output priority -100 ; policy accept ; }}\n"
        ));
        s.push_str(&format!(
            "add rule inet {t} host_redirect meta mark & 0x{:x} == 0x{:x} return\n",
            self.skip_mark, self.skip_mark
        ));
        let skuid = self.skuid_match();
        if !skuid.is_empty() {
            s.push_str(&format!("add rule inet {t} host_redirect {skuid}"));
        }
        s.push_str(&format!(
            "add rule inet {t} host_redirect fib daddr type local return\n"
        ));
        s.push_str(&format!(
            "add rule inet {t} host_redirect ip daddr @bypass_v4 return\n"
        ));
        s.push_str(&format!(
            "add rule inet {t} host_redirect ip6 daddr @bypass_v6 return\n"
        ));
        if self.host_all_tcp {
            s.push_str(&format!(
                "add rule inet {t} host_redirect meta l4proto tcp tcp dport != 53 redirect to :{}\n",
                self.tcp_port
            ));
        } else if !self.host_ports.is_empty() {
            s.push_str(&format!(
                "add rule inet {t} host_redirect meta l4proto tcp tcp dport {{ {} }} redirect to :{}\n",
                self.port_set(),
                self.tcp_port
            ));
        }

        // ---- DNS from this host ----
        if let Some(dns) = self.dns_port {
            s.push_str(&format!(
                "add chain inet {t} host_dns {{ type nat hook output priority -100 ; policy accept ; }}\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} host_dns meta mark & 0x{:x} == 0x{:x} return\n",
                self.skip_mark, self.skip_mark
            ));
            s.push_str(&format!(
                "add rule inet {t} host_dns udp dport 53 redirect to :{dns}\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} host_dns tcp dport 53 redirect to :{dns}\n"
            ));
        }

        // ---- LAN: DNS redirect + TCP TPROXY + UDP mark ----
        if self.lan_enabled {
            if let Some(dns) = self.dns_port {
                s.push_str(&format!(
                    "add chain inet {t} lan_dns {{ type nat hook prerouting priority -100 ; policy accept ; }}\n"
                ));
                s.push_str(&format!(
                    "add rule inet {t} lan_dns iifname @lan_ifaces udp dport 53 redirect to :{dns}\n"
                ));
                s.push_str(&format!(
                    "add rule inet {t} lan_dns iifname @lan_ifaces tcp dport 53 redirect to :{dns}\n"
                ));
            }

            s.push_str(&format!(
                "add chain inet {t} lan_pre {{ type filter hook prerouting priority mangle ; policy accept ; }}\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} lan_pre iifname @lan_ifaces meta mark & 0x{:x} == 0x{:x} return\n",
                self.skip_mark, self.skip_mark
            ));
            s.push_str(&format!(
                "add rule inet {t} lan_pre iifname @lan_ifaces fib daddr type local return\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} lan_pre iifname @lan_ifaces ip daddr @bypass_v4 return\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} lan_pre iifname @lan_ifaces ip6 daddr @bypass_v6 return\n"
            ));
            // DNS is redirected in the nat chain; tproxy runs earlier, so it
            // must not swallow port 53.
            if self.lan_all_tcp {
                s.push_str(&format!(
                    "add rule inet {t} lan_pre iifname @lan_ifaces meta l4proto tcp tcp dport != 53 meta mark set 0x{:x} tproxy to :{} accept\n",
                    self.tproxy_mark, self.tcp_port
                ));
            } else if !self.host_ports.is_empty() {
                s.push_str(&format!(
                    "add rule inet {t} lan_pre iifname @lan_ifaces meta l4proto tcp tcp dport {{ {} }} meta mark set 0x{:x} tproxy to :{} accept\n",
                    self.port_set(),
                    self.tproxy_mark,
                    self.tcp_port
                ));
            }
            if self.tun_enabled {
                s.push_str(&format!(
                    "add rule inet {t} lan_pre iifname @lan_ifaces meta l4proto udp udp dport != 53 meta mark set 0x{:x}\n",
                    self.tun_mark
                ));
            }
        }

        // ---- host UDP -> TUN ----
        if self.tun_enabled {
            s.push_str(&format!(
                "add chain inet {t} udp_out {{ type filter hook output priority mangle ; policy accept ; }}\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} udp_out meta mark & 0x{:x} == 0x{:x} return\n",
                self.skip_mark, self.skip_mark
            ));
            let skuid = self.skuid_match();
            if !skuid.is_empty() {
                s.push_str(&format!("add rule inet {t} udp_out {skuid}"));
            }
            s.push_str(&format!(
                "add rule inet {t} udp_out fib daddr type local return\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} udp_out ip daddr @bypass_v4 return\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} udp_out ip6 daddr @bypass_v6 return\n"
            ));
            s.push_str(&format!("add rule inet {t} udp_out udp dport 53 return\n"));
            s.push_str(&format!(
                "add rule inet {t} udp_out meta l4proto udp meta mark set 0x{:x}\n",
                self.tun_mark
            ));
        }

        // ---- DPI queues: one per distinct strategy ----
        if !self.dpi_queues.is_empty() {
            let ct = if self.dpi_max_packets == 0 {
                String::new()
            } else {
                format!("ct packets 0-{} ", self.dpi_max_packets)
            };
            s.push_str(&format!(
                "add chain inet {t} dpi_out {{ type filter hook output priority mangle ; policy accept ; }}\n"
            ));
            for (queue, mark) in &self.dpi_queues {
                s.push_str(&format!(
                    "add rule inet {t} dpi_out meta mark & 0x{:x} == 0x{:x} {ct}tcp flags & (syn | rst) == 0 queue num {queue} bypass\n",
                    marks::DPI_MASK,
                    mark & marks::DPI_MASK
                ));
            }
        }

        // ---- optional masquerade for non-intercepted forwarded traffic ----
        if self.masquerade {
            s.push_str(&format!(
                "add chain inet {t} postrouting {{ type nat hook postrouting priority srcnat ; policy accept ; }}\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} postrouting meta mark & 0x{:x} == 0x{:x} return\n",
                self.tun_mark, self.tun_mark
            ));
            s.push_str(&format!(
                "add rule inet {t} postrouting ip saddr @lan_v4 oifname != @lan_ifaces masquerade\n"
            ));
            s.push_str(&format!(
                "add rule inet {t} postrouting ip6 saddr @lan_v6 oifname != @lan_ifaces masquerade\n"
            ));
        }

        s
    }

    pub fn install(&self, nft_bin: &str) -> Result<()> {
        let _ = Command::new(nft_bin)
            .args(["delete", "table", "inet", &self.table])
            .output();
        let script = self.script();
        tracing::debug!(%script, "installing nftables rules");
        let mut child = Command::new(nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning `{nft_bin} -f -`"))?;
        child
            .stdin
            .as_mut()
            .context("nft stdin")?
            .write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "nft failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    pub fn remove(&self, nft_bin: &str) -> Result<()> {
        let out = Command::new(nft_bin)
            .args(["delete", "table", "inet", &self.table])
            .output()
            .with_context(|| format!("running `{nft_bin} delete table`"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.contains("No such file or directory") {
                bail!("nft failed: {}", err.trim());
            }
        }
        Ok(())
    }
}

/// Parse `ip rule show` and return routing tables that are not the kernel's
/// standard tables or airgrill's own.
fn parse_foreign_tables(text: &str) -> Vec<u32> {
    let mut tables = Vec::new();
    for line in text.lines() {
        let Some(pos) = line.find("lookup ") else {
            continue;
        };
        let rest = &line[pos + "lookup ".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(table) = digits.parse::<u32>() else {
            continue;
        };
        if matches!(table, 253..=255) || table == TPROXY_TABLE || table == 100 {
            continue;
        }
        if !tables.contains(&table) {
            tables.push(table);
        }
    }
    tables
}

/// Detects another policy-routing VPN (Hiddify/sing-box/wireguard with a
/// custom table).  Starting airgrill in that state can intercept the VPN's own
/// outbound connections and take the whole host offline.
pub fn foreign_policy_routes() -> Result<Vec<(u32, String)>> {
    let out = Command::new("ip")
        .args(["rule", "show"])
        .output()
        .context("running `ip rule show`")?;
    if !out.status.success() {
        bail!(
            "ip rule show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for table in parse_foreign_tables(&text) {
        let out = Command::new("ip")
            .args(["route", "show", "table", &table.to_string()])
            .output()
            .with_context(|| format!("running `ip route show table {table}`"))?;
        let routes = String::from_utf8_lossy(&out.stdout);
        if routes
            .lines()
            .any(|l| l.trim_start().starts_with("default "))
        {
            let iface = routes
                .lines()
                .find(|l| l.trim_start().starts_with("default "))
                .and_then(|l| {
                    l.split_whitespace()
                        .find(|w| w.starts_with("tun") || w.starts_with("wg"))
                })
                .unwrap_or("foreign")
                .to_string();
            found.push((table, iface));
        }
    }
    Ok(found)
}

fn run_ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("running ip {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn try_ip(args: &[&str]) {
    let _ = Command::new("ip").args(args).output();
}

/// `ip rule` / `ip route` entries needed by TPROXY and the UDP TUN.
pub struct PolicyRoutes {
    pub tproxy_table: u32,
    pub tproxy_mark: u32,
    pub tproxy_priority: u32,
    pub tun_table: u32,
    pub tun_mark: u32,
    pub tun_priority: u32,
    pub tun_name: Option<String>,
}

impl PolicyRoutes {
    pub fn install(&self) -> Result<()> {
        let mark = format!("0x{:x}", self.tproxy_mark);
        let table = self.tproxy_table.to_string();
        let prio = self.tproxy_priority.to_string();
        try_ip(&[
            "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ]);
        try_ip(&[
            "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ]);
        run_ip(&[
            "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ])?;
        run_ip(&[
            "-6", "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ])?;
        run_ip(&[
            "route",
            "replace",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            &table,
        ])?;
        run_ip(&[
            "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", &table,
        ])?;

        if let Some(name) = &self.tun_name {
            let mark = format!("0x{:x}", self.tun_mark);
            let table = self.tun_table.to_string();
            let prio = self.tun_priority.to_string();
            try_ip(&[
                "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
            ]);
            try_ip(&[
                "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
            ]);
            run_ip(&[
                "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &prio,
            ])?;
            run_ip(&[
                "-6", "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &prio,
            ])?;
            run_ip(&["route", "replace", "default", "dev", name, "table", &table])?;
            run_ip(&[
                "-6", "route", "replace", "default", "dev", name, "table", &table,
            ])?;
        }
        Ok(())
    }
}

impl Drop for PolicyRoutes {
    fn drop(&mut self) {
        let mark = format!("0x{:x}", self.tproxy_mark);
        let table = self.tproxy_table.to_string();
        let prio = self.tproxy_priority.to_string();
        try_ip(&[
            "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ]);
        try_ip(&[
            "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ]);
        try_ip(&["route", "flush", "table", &table]);
        try_ip(&["-6", "route", "flush", "table", &table]);

        if self.tun_name.is_some() {
            let mark = format!("0x{:x}", self.tun_mark);
            let table = self.tun_table.to_string();
            let prio = self.tun_priority.to_string();
            try_ip(&[
                "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
            ]);
            try_ip(&[
                "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
            ]);
            try_ip(&["route", "flush", "table", &table]);
            try_ip(&["-6", "route", "flush", "table", &table]);
        }
    }
}

/// Parse an address only for diagnostics (`airgrill route`).
pub fn ip_family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airgrill_core::Config;

    fn rules() -> NftRules {
        let cfg = Config::parse(
            r#"
[routing]
mode = "lists"
[routing.lists]
proxy = ["proxy.example"]
dpi = ["dpi.example"]
[router]
enabled = true
lan_interfaces = ["eno2"]
lan_cidrs = ["10.10.10.0/24"]

[[proxy.backends]]
name = "vps"
kind = "xray"
url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=tcp"
run_as_uid = 65534
"#,
        )
        .unwrap();
        NftRules::from_config(&cfg).unwrap()
    }

    #[test]
    fn captures_and_marks() {
        let s = rules().script();
        assert!(s.contains("host_redirect"));
        assert!(s.contains("redirect to :16000"));
        assert!(s.contains("tproxy to :16000"));
        assert!(s.contains("meta mark set 0x10"));
        assert!(s.contains("meta mark & 0xff02 == 0x2 ct packets 0-16"));
        assert!(s.contains("queue num 200 bypass"));
        assert!(s.contains("meta skuid { 65534 } return"));
        assert!(s.contains("iifname @lan_ifaces"));
        assert!(s.contains("bypass_v4"));
        assert!(s.contains("udp dport 53 redirect to :15353"));
    }

    #[test]
    fn no_lan_rules_when_disabled() {
        let mut r = rules();
        r.lan_enabled = false;
        let s = r.script();
        assert!(!s.contains("lan_pre"));
        assert!(!s.contains("lan_dns"));
        assert!(s.contains("host_redirect"));
    }

    #[test]
    fn parses_foreign_policy_tables() {
        let text = "0:\tfrom all lookup local\n9001:\tfrom all lookup 2022\n1001: from all fwmark 0x1 lookup 101\n32766:\tfrom all lookup main\n";
        assert_eq!(super::parse_foreign_tables(text), vec![2022]);
    }

    #[test]
    fn dpi_absent_when_disabled() {
        let mut r = rules();
        r.dpi_queues.clear();
        assert!(!r.script().contains("dpi_out"));
    }
}
