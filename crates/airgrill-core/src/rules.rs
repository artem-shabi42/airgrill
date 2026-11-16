//! Domain / IP rule lists and matching.
//!
//! Supported rule forms (case-insensitive):
//!
//! | rule                       | meaning                                   |
//! |----------------------------|-------------------------------------------|
//! | `example.com`              | example.com and all subdomains            |
//! | `domain:example.com`       | same (Xray/v2ray style)                   |
//! | `suffix:example.com`       | same                                      |
//! | `full:example.com`         | exactly example.com                       |
//! | `keyword:tracker`          | any host containing `tracker`             |
//! | `regex:^ads?\\.`           | regular expression                        |
//! | `cidr:10.0.0.0/8`          | IPv4/IPv6 network                         |
//! | `10.0.0.0/8`, `1.2.3.4`    | CIDR / single IP                          |
//! | `*`                        | everything                                |
//!
//! `geosite:` / `geoip:` are intentionally rejected: this client does not ship
//! a geo database.

use crate::config::Route;
use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
enum Rule {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(Regex),
    Cidr(IpNet),
}

#[derive(Debug, Clone, Default)]
pub struct Matcher {
    rules: Vec<Rule>,
    /// `*` was present.
    all: bool,
}

fn normalize_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn norm_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        _ => ip,
    }
}

pub fn validate_rule(raw: &str) -> Result<()> {
    compile_rule(raw).map(|_| ())
}

fn compile_rule(raw: &str) -> Result<Rule> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty rule");
    }
    if s == "*" {
        // handled by the caller, but keep a value for validation
        return Ok(Rule::Keyword(String::new()));
    }
    // Parse addresses before looking for a `type:` prefix: otherwise an IPv6
    // literal such as `2001:db8::1` looks like a rule type.
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(Rule::Cidr(net));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        let normalized = norm_ip(ip);
        let net = IpNet::new(normalized, if normalized.is_ipv4() { 32 } else { 128 })
            .expect("valid prefix");
        return Ok(Rule::Cidr(net));
    }
    let (kind, value) = match s.split_once(':') {
        Some((k, v)) if !k.is_empty() && !k.contains('/') && !k.contains('.') => (Some(k), v),
        _ => (None, s),
    };
    match kind.map(|k| k.to_ascii_lowercase()).as_deref() {
        Some("full") => {
            let v = normalize_domain(value);
            if v.is_empty() {
                bail!("empty domain in '{raw}'");
            }
            Ok(Rule::Exact(v))
        }
        Some("domain") | Some("suffix") => {
            let v = normalize_domain(value).trim_start_matches('.').to_string();
            if v.is_empty() {
                bail!("empty domain in '{raw}'");
            }
            Ok(Rule::Suffix(v))
        }
        Some("keyword") => {
            if value.is_empty() {
                bail!("empty keyword in '{raw}'");
            }
            Ok(Rule::Keyword(value.to_ascii_lowercase()))
        }
        Some("regex") => {
            let re = Regex::new(value).with_context(|| format!("invalid regex '{raw}'"))?;
            Ok(Rule::Regex(re))
        }
        Some("cidr") => {
            let net: IpNet = value
                .parse()
                .with_context(|| format!("invalid CIDR in '{raw}'"))?;
            Ok(Rule::Cidr(net))
        }
        Some("geosite") | Some("geoip") => {
            bail!("'{raw}': geo databases are not supported; use domain:/cidr: rules")
        }
        Some(other) => bail!("'{raw}': unknown rule type '{other}'"),
        None => {
            let v = normalize_domain(s).trim_start_matches('.').to_string();
            if v.is_empty() {
                bail!("empty domain in '{raw}'");
            }
            Ok(Rule::Suffix(v))
        }
    }
}

impl Matcher {
    pub fn compile(rules: &[String]) -> Result<Self> {
        let mut out = Matcher::default();
        for raw in rules {
            if raw.trim() == "*" {
                out.all = true;
                continue;
            }
            out.rules.push(compile_rule(raw)?);
        }
        Ok(out)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && !self.all
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        if self.all {
            return true;
        }
        let d = normalize_domain(domain);
        if d.is_empty() {
            return false;
        }
        self.rules.iter().any(|r| match r {
            Rule::Exact(v) => d == *v,
            Rule::Suffix(v) => {
                d == *v
                    || (d.len() > v.len()
                        && d.ends_with(v)
                        && d.as_bytes()[d.len() - v.len() - 1] == b'.')
            }
            Rule::Keyword(v) => !v.is_empty() && d.contains(v),
            Rule::Regex(re) => re.is_match(&d),
            Rule::Cidr(_) => false,
        })
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        if self.all {
            return true;
        }
        let ip = norm_ip(ip);
        self.rules.iter().any(|r| match r {
            Rule::Cidr(net) => net.contains(&ip),
            _ => false,
        })
    }
}

/// One compiled rule/list: a matcher plus the route it selects.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub route: Route,
    pub backend: Option<String>,
    pub strategy: Option<String>,
    pub matcher: Matcher,
    /// Position after priority/declaration sorting (lower = stronger).
    pub rank: usize,
}

/// All rule lists, compiled once at startup.  The first matching rule wins.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn compile(cfg: &crate::config::Config) -> Result<Self> {
        let mut explicit: Vec<(i32, usize, &crate::config::RuleConfig)> = cfg
            .routing
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.priority, i, r))
            .collect();
        // Higher priority first; stable declaration order for ties.
        explicit.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

        let mut rules = Vec::new();
        for (rank, (_, _, rule)) in explicit.into_iter().enumerate() {
            let name = rule
                .name
                .clone()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("rule-{rank}"));
            rules.push(CompiledRule {
                name,
                route: rule.route,
                backend: rule.backend.clone(),
                strategy: rule.strategy.clone(),
                matcher: Matcher::compile(&rule.entries).with_context(|| {
                    format!("routing rule '{}'", rule.name.as_deref().unwrap_or("?"))
                })?,
                rank,
            });
        }

        // Legacy fixed lists: keep old configs working.  They are appended
        // after explicit rules, in the historical block > proxy > dpi > direct
        // order.
        for route in Route::PRECEDENCE {
            let entries = cfg.routing.lists.get(route);
            if entries.is_empty() {
                continue;
            }
            let rank = rules.len();
            rules.push(CompiledRule {
                name: format!("legacy-{}", route.as_str()),
                route,
                backend: None,
                strategy: None,
                matcher: Matcher::compile(entries)
                    .with_context(|| format!("routing.lists.{}", route.as_str()))?,
                rank,
            });
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    pub fn domain_match(&self, domain: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.matcher.matches_domain(domain))
    }

    pub fn ip_match(&self, ip: IpAddr) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.matcher.matches_ip(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Validates the tiny strategy grammar without pulling the DPI crate into the
/// config layer.
pub fn parse_strategy(s: &str) -> std::result::Result<(), String> {
    let mut parts = s.split(':');
    let kind = parts.next().unwrap_or("");
    match kind {
        "split" | "disorder" | "fake" | "overlap" | "oob" | "disoob" | "ipfrag" | "frag" => {}
        other => {
            return Err(format!(
            "unknown strategy '{other}' (expected split|disorder|fake|overlap|oob|disoob|ipfrag)"
        ))
        }
    }
    for p in parts {
        match p {
            "" | "sni" | "mid" => {}
            n if n
                .split(',')
                .all(|v| !v.is_empty() && v.parse::<usize>().is_ok()) => {}
            n => {
                return Err(format!(
                    "unknown strategy parameter '{n}' (expected sni|mid|BYTE[,BYTE...])"
                ))
            }
        }
    }
    Ok(())
}

/// Deduplicates hostnames and normalizes them for storage/logging.
pub fn normalize_hosts(hosts: impl IntoIterator<Item = String>) -> HashSet<String> {
    hosts
        .into_iter()
        .map(|h| normalize_domain(&h))
        .filter(|h| !h.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rules: &[&str]) -> Matcher {
        Matcher::compile(&rules.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn suffix_matches_domain_and_children_only() {
        let m = m(&["example.com"]);
        assert!(m.matches_domain("example.com"));
        assert!(m.matches_domain("www.example.com"));
        assert!(m.matches_domain("a.b.example.com"));
        assert!(m.matches_domain("WWW.Example.COM."));
        assert!(!m.matches_domain("notexample.com"));
        assert!(!m.matches_domain("example.com.evil"));
    }

    #[test]
    fn full_is_exact() {
        let m = m(&["full:example.com"]);
        assert!(m.matches_domain("example.com"));
        assert!(!m.matches_domain("www.example.com"));
    }

    #[test]
    fn keyword_regex_cidr() {
        assert!(m(&["keyword:tracker"]).matches_domain("ad-tracker-1.net"));
        assert!(m(&["regex:^ads?\\."]).matches_domain("ads.example.com"));
        assert!(!m(&["regex:^ads?\\."]).matches_domain("xads.example.com"));
        assert!(m(&["10.0.0.0/8"]).matches_ip("10.1.2.3".parse().unwrap()));
        assert!(m(&["::ffff:10.1.2.3"]).matches_ip("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn wildcard_and_compiled_rules() {
        let cfg = crate::config::Config::parse(
            r#"
[routing.lists]
proxy = ["example.com"]
dpi = ["example.com"]
[[proxy.backends]]
name = "x"
kind = "native"
url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=tcp"
"#,
        )
        .unwrap();
        let rs = RuleSet::compile(&cfg).unwrap();
        // Legacy block > proxy > dpi > direct order.
        assert_eq!(
            rs.domain_match("www.example.com").unwrap().route,
            Route::Proxy
        );
        assert!(m(&["*"]).matches_domain("anything"));
    }

    #[test]
    fn rejects_geo_and_bad_regex() {
        assert!(Matcher::compile(&["geosite:google".into()]).is_err());
        assert!(Matcher::compile(&["regex:(".into()]).is_err());
    }

    #[test]
    fn strategy_grammar() {
        assert!(parse_strategy("disorder:sni").is_ok());
        assert!(parse_strategy("fake:mid:3").is_ok());
        assert!(parse_strategy("nope").is_err());
        assert!(parse_strategy("split:sideways").is_err());
    }
}
