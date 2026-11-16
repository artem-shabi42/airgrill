use airgrill_core::Config;
use airgrill_net::nft::{NftRules, PolicyRoutes, TPROXY_RULE_PRIORITY, TPROXY_TABLE};
use anyhow::{bail, Result};
use std::net::IpAddr;
use std::sync::Arc;

use crate::cli::{Cli, Cmd, RulesCmd};
use crate::daemon;

pub async fn dispatch(cli: Cli) -> Result<()> {
    let mut cfg = Config::load(&cli.config)?;
    init_logging(&cfg, cli.verbose);
    tracing::debug!(config = %cli.config.display(), "configuration loaded");

    match cli.cmd {
        Cmd::Run(args) => {
            if args.no_dpi {
                cfg.dpi.enabled = false;
            }
            if args.no_tun {
                cfg.tun.enabled = false;
            }
            if args.no_dns {
                cfg.dns.enabled = false;
            }
            cfg.validate()?;
            if args.dry_run {
                let rules = NftRules::from_config(&cfg)?;
                print!("{}", rules.script());
                return Ok(());
            }
            daemon::run(cfg, args).await
        }
        Cmd::Check => check(&cfg),
        Cmd::Route { target } => route(&cfg, &target),
        Cmd::Rules(args) => rules(&cfg, args.cmd).await,
    }
}

fn init_logging(cfg: &Config, verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbose {
        0 => cfg.log.level.clone(),
        1 => "debug".into(),
        _ => "trace".into(),
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("airgrill={default},airgrill_core={default},airgrill_dpi={default},airgrill_net={default},airgrill_proxy={default},airgrill_dns={default},warn")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn check(cfg: &Config) -> Result<()> {
    let router = airgrill_core::Router::new(cfg)?;
    println!("config:         ok");
    println!("mode:           {:?}", cfg.routing.mode);
    println!("default route:  {}", router.default_route());
    println!(
        "backends:       {}",
        cfg.proxy
            .backends
            .iter()
            .map(|b| format!("{} ({:?})", b.name, b.kind))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("rules:          {}", cfg.routing.rules.len());
    for (i, r) in cfg.routing.rules.iter().enumerate() {
        println!(
            "  {:>2}. {:<18} route={:<7} entries={:<4} backend={} strategy={} priority={}",
            i + 1,
            r.name.as_deref().unwrap_or("-"),
            r.route.as_str(),
            r.entries.len(),
            r.backend.as_deref().unwrap_or("-"),
            r.strategy.as_deref().unwrap_or("-"),
            r.priority
        );
    }
    if !cfg.routing.lists.proxy.is_empty()
        || !cfg.routing.lists.dpi.is_empty()
        || !cfg.routing.lists.direct.is_empty()
        || !cfg.routing.lists.block.is_empty()
    {
        println!(
            "legacy lists:   proxy={} dpi={} direct={} block={}",
            cfg.routing.lists.proxy.len(),
            cfg.routing.lists.dpi.len(),
            cfg.routing.lists.direct.len(),
            cfg.routing.lists.block.len()
        );
    }
    println!(
        "dpi:            {} (base queue {}, default strategy {})",
        if cfg.dpi.enabled { "on" } else { "off" },
        cfg.dpi.queue_num,
        cfg.dpi.strategy
    );
    if cfg.dpi.enabled {
        match airgrill_core::DpiPlan::build(cfg) {
            Ok(plan) => {
                for route in plan.routes() {
                    println!(
                        "  dpi queue {:<5} id={} mark=0x{:x} strategy={}",
                        route.queue,
                        route.id,
                        airgrill_core::marks::dpi_mark(route.id),
                        route.strategy
                    );
                }
            }
            Err(e) => println!("  dpi plan error: {e}"),
        }
    }
    println!(
        "dns:            {} ({}, {} upstreams)",
        if cfg.dns.enabled { "on" } else { "off" },
        cfg.dns.listen,
        cfg.dns.upstreams.len()
    );
    println!(
        "tun/udp:        {} ({})",
        if cfg.tun.enabled { "on" } else { "off" },
        cfg.tun.name
    );
    println!(
        "lan router:     {} (interfaces: {})",
        if cfg.router.enabled { "on" } else { "off" },
        if cfg.router.lan_interfaces.is_empty() {
            "-".into()
        } else {
            cfg.router.lan_interfaces.join(", ")
        }
    );
    Ok(())
}

fn route(cfg: &Config, target: &str) -> Result<()> {
    let router = airgrill_core::Router::new(cfg)?;
    let (decision, what) = if let Ok(ip) = target.parse::<IpAddr>() {
        (router.decide_ip(ip), format!("ip {ip}"))
    } else {
        let host = target.trim_end_matches('.').to_ascii_lowercase();
        (router.decide_domain(&host), format!("domain {host}"))
    };
    println!("{what}: {}", decision.route);
    println!("reason:  {}", decision.reason);
    if let Some(b) = decision.backend {
        println!("backend: {b}");
    } else if decision.route == airgrill_core::Route::Proxy {
        println!("backend: (default)");
    }
    Ok(())
}

async fn rules(cfg: &Config, cmd: RulesCmd) -> Result<()> {
    let rules = NftRules::from_config(cfg)?;
    match cmd {
        RulesCmd::Print => {
            print!("{}", rules.script());
            Ok(())
        }
        RulesCmd::Install { nft } => {
            require_root()?;
            rules.install(&nft)?;
            let tproxy = PolicyRoutes {
                tproxy_table: TPROXY_TABLE,
                tproxy_mark: airgrill_core::marks::MARK_TPROXY,
                tproxy_priority: TPROXY_RULE_PRIORITY,
                tun_table: cfg.tun.table,
                tun_mark: airgrill_core::marks::MARK_UDP,
                tun_priority: 0,
                tun_name: None,
            };
            tproxy.install()?;
            // `airgrill rules remove` cleans these up; do not drop the guard
            // (a Drop would remove them immediately).
            std::mem::forget(tproxy);
            println!("installed table inet {}", rules.table);
            if cfg.tun.enabled {
                println!(
                    "note: UDP TUN policy routes are installed by `airgrill run` (interface {})",
                    cfg.tun.name
                );
            }
            Ok(())
        }
        RulesCmd::Remove { nft } => {
            require_root()?;
            rules.remove(&nft)?;
            remove_policy_routes();
            remove_tun_routes(cfg);
            println!("removed table inet {}", rules.table);
            Ok(())
        }
    }
}

fn remove_tun_routes(cfg: &Config) {
    let mark = format!("0x{:x}", airgrill_core::marks::MARK_UDP);
    let table = cfg.tun.table.to_string();
    for args in [
        vec![
            "rule", "del", "fwmark", &mark, "lookup", &table, "priority", "1000",
        ],
        vec![
            "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", "1000",
        ],
        vec!["route", "flush", "table", &table],
        vec!["-6", "route", "flush", "table", &table],
        vec!["link", "del", &cfg.tun.name],
    ] {
        let _ = std::process::Command::new("ip").args(args).output();
    }
}

fn remove_policy_routes() {
    let mark = format!("0x{:x}", airgrill_core::marks::MARK_TPROXY);
    let table = TPROXY_TABLE.to_string();
    let prio = TPROXY_RULE_PRIORITY.to_string();
    for args in [
        vec![
            "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ],
        vec![
            "-6", "rule", "del", "fwmark", &mark, "lookup", &table, "priority", &prio,
        ],
        vec!["route", "flush", "table", &table],
        vec!["-6", "route", "flush", "table", &table],
    ] {
        let _ = std::process::Command::new("ip").args(args).output();
    }
}

pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("this command must run as root (CAP_NET_ADMIN / CAP_NET_RAW)");
    }
    Ok(())
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Arc<Config>>();
}
