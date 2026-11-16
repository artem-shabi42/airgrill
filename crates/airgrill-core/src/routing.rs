//! The routing decision engine.
//!
//! Rules are checked in priority order (higher `priority` first, then
//! declaration order); the first matching domain/CIDR rule wins.  If no rule
//! matches, the DNS-observed IP map is consulted, then the mode default.
//!
//! A rule can override the proxy backend and the DPI strategy for its own
//! list, so an arbitrary number of independent lists can coexist.

use crate::config::{Config, Route};
use crate::ip_index::IpIndex;
use crate::rules::{CompiledRule, RuleSet};
use anyhow::{bail, Result};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Decision {
    pub route: Route,
    /// Set when `route == Proxy`.
    pub backend: Option<String>,
    /// Set when `route == Dpi`; falls back to `[dpi].strategy`.
    pub strategy: Option<String>,
    pub reason: String,
    /// Rule position (lower = stronger); `usize::MAX` for the mode default.
    pub rank: usize,
}

impl Decision {
    pub fn is_proxy(&self) -> bool {
        self.route == Route::Proxy
    }

    pub fn is_dpi(&self) -> bool {
        self.route == Route::Dpi
    }
}

#[derive(Debug)]
pub struct Router {
    rules: RuleSet,
    default: Route,
    default_backend: Option<String>,
    default_strategy: String,
    ip_index: Arc<IpIndex>,
}

impl Router {
    pub fn new(cfg: &Config) -> Result<Self> {
        let rules = RuleSet::compile(cfg)?;
        let default = cfg.routing.mode.default_route(cfg.routing.default_route);
        let default_backend = cfg
            .routing
            .proxy_backend
            .clone()
            .or_else(|| cfg.proxy.default_backend.clone())
            .or_else(|| {
                (cfg.proxy.backends.len() == 1).then(|| cfg.proxy.backends[0].name.clone())
            });
        if default == Route::Proxy && cfg.proxy.backends.is_empty() {
            bail!("routing default is proxy, but no [[proxy.backends]] are configured");
        }
        Ok(Self {
            rules,
            default,
            default_backend,
            default_strategy: cfg.dpi.strategy.clone(),
            ip_index: Arc::new(IpIndex::new()),
        })
    }

    pub fn ip_index(&self) -> Arc<IpIndex> {
        Arc::clone(&self.ip_index)
    }

    pub fn default_route(&self) -> Route {
        self.default
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    fn finish_rule(&self, rule: &CompiledRule, reason: impl Into<String>) -> Decision {
        Decision {
            route: rule.route,
            backend: if rule.route == Route::Proxy {
                rule.backend
                    .clone()
                    .or_else(|| self.default_backend.clone())
            } else {
                None
            },
            strategy: if rule.route == Route::Dpi {
                rule.strategy
                    .clone()
                    .or_else(|| Some(self.default_strategy.clone()))
            } else {
                None
            },
            reason: reason.into(),
            rank: rule.rank,
        }
    }

    fn finish_default(&self, reason: impl Into<String>) -> Decision {
        Decision {
            route: self.default,
            backend: if self.default == Route::Proxy {
                self.default_backend.clone()
            } else {
                None
            },
            strategy: if self.default == Route::Dpi {
                Some(self.default_strategy.clone())
            } else {
                None
            },
            reason: reason.into(),
            rank: usize::MAX,
        }
    }

    /// Classification by hostname only.
    pub fn decide_domain(&self, domain: &str) -> Decision {
        if let Some(rule) = self.rules.domain_match(domain) {
            return self.finish_rule(rule, format!("rule '{}':{}", rule.name, rule.route));
        }
        self.finish_default(format!("default:{}", self.default.as_str()))
    }

    /// Classification by destination address only.
    pub fn decide_ip(&self, ip: IpAddr) -> Decision {
        if let Some(rule) = self.rules.ip_match(ip) {
            return self.finish_rule(rule, format!("ip rule '{}':{}", rule.name, rule.route));
        }
        if let Some(decision) = self.ip_index.lookup(ip) {
            return decision;
        }
        self.finish_default(format!("default:{}", self.default.as_str()))
    }

    /// Classification with both pieces of evidence.  An explicit domain rule
    /// wins; otherwise a CIDR rule and then the DNS map can override the mode
    /// default.
    pub fn decide(&self, host: Option<&str>, ip: IpAddr) -> Decision {
        if let Some(host) = host {
            if let Some(rule) = self.rules.domain_match(host) {
                return self.finish_rule(rule, format!("rule '{}':{}", rule.name, rule.route));
            }
        }
        if let Some(rule) = self.rules.ip_match(ip) {
            return self.finish_rule(rule, format!("ip rule '{}':{}", rule.name, rule.route));
        }
        if let Some(decision) = self.ip_index.lookup(ip) {
            return decision;
        }
        self.finish_default(format!("default:{}", self.default.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Route};

    fn cfg(toml_text: &str) -> Config {
        Config::parse(toml_text).unwrap()
    }

    #[test]
    fn legacy_lists_still_work() {
        let cfg = cfg(r#"
[routing]
mode = "lists"
default_route = "direct"
[routing.lists]
proxy = ["proxy.example"]
dpi = ["dpi.example"]
block = ["blocked.example"]

[[proxy.backends]]
name = "x"
kind = "native"
url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=tcp"
"#);
        let r = Router::new(&cfg).unwrap();
        assert_eq!(r.decide_domain("proxy.example").route, Route::Proxy);
        assert_eq!(r.decide_domain("x.dpi.example").route, Route::Dpi);
        assert_eq!(r.decide_domain("blocked.example").route, Route::Block);
        assert_eq!(r.decide_domain("other.example").route, Route::Direct);
    }

    #[test]
    fn arbitrary_rules_first_match_and_overrides() {
        let cfg = cfg(r#"
[[proxy.backends]]
name = "vps"
kind = "native"
url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=tcp"

[routing]
mode = "lists"
default_route = "direct"

[[routing.rules]]
name = "youtube"
route = "dpi"
strategy = "fake:sni"
domains = ["domain:youtube.com"]

[[routing.rules]]
name = "telegram"
route = "proxy"
backend = "vps"
domains = ["cidr:149.154.160.0/20"]

[[routing.rules]]
name = "blocked"
route = "block"
priority = 10
match = ["domain:ads.youtube.com"]
"#);
        let r = Router::new(&cfg).unwrap();
        let yt = r.decide_domain("www.youtube.com");
        assert_eq!(yt.route, Route::Dpi);
        assert_eq!(yt.strategy.as_deref(), Some("fake:sni"));
        let tg = r.decide_ip("149.154.167.99".parse().unwrap());
        assert_eq!(tg.route, Route::Proxy);
        assert_eq!(tg.backend.as_deref(), Some("vps"));
        // The priority=10 block rule is checked before the youtube rule.
        assert_eq!(r.decide_domain("ads.youtube.com").route, Route::Block);
    }

    #[test]
    fn dns_map_keeps_full_decision() {
        let cfg = cfg(r#"
[routing]
mode = "proxy-default"
[[proxy.backends]]
name = "vps"
kind = "native"
url = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=tcp"
"#);
        let r = Router::new(&cfg).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut decision = r.decide_domain("direct.example");
        decision.route = Route::Direct;
        decision.rank = 2;
        r.ip_index()
            .insert(ip, decision, std::time::Duration::from_secs(60));
        assert_eq!(r.decide(None, ip).route, Route::Direct);
        assert_eq!(r.decide(Some("unknown.example"), ip).route, Route::Direct);
        assert_eq!(
            r.decide(Some("unknown.example"), "5.6.7.8".parse().unwrap())
                .route,
            Route::Proxy
        );
    }

    #[test]
    fn default_strategy_for_dpi_rule() {
        let cfg = cfg(r#"
[routing]
mode = "lists"
default_route = "direct"
[dpi]
strategy = "disorder:sni"
[[routing.rules]]
name = "yt"
route = "dpi"
domains = ["domain:youtube.com"]
"#);
        let r = Router::new(&cfg).unwrap();
        assert_eq!(
            r.decide_domain("youtube.com").strategy.as_deref(),
            Some("disorder:sni")
        );
    }
}
