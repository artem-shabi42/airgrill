//! Daemon orchestration: start listeners, install rules, wait for a signal,
//! tear everything down in reverse order.

use crate::cli::RunArgs;
use crate::state::AppState;
use crate::tcp;
use crate::udp;
use airgrill_core::marks::{MARK_SKIP, MARK_TPROXY, MARK_UDP};
use airgrill_core::{Config, DpiPlan, Router};
use airgrill_dpi::{run_queue, DpiSettings};
use airgrill_net::nft::{NftRules, PolicyRoutes, TPROXY_RULE_PRIORITY, TPROXY_TABLE};
use airgrill_net::tun::Tun;
use airgrill_proxy::Backends;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct NftGuard {
    rules: NftRules,
    nft_bin: String,
}

impl Drop for NftGuard {
    fn drop(&mut self) {
        if let Err(e) = self.rules.remove(&self.nft_bin) {
            tracing::warn!(error = %e, "could not remove nftables rules");
        } else {
            tracing::info!("nftables rules removed");
        }
    }
}

fn policy_routes(cfg: &Config) -> PolicyRoutes {
    PolicyRoutes {
        tproxy_table: TPROXY_TABLE,
        tproxy_mark: MARK_TPROXY,
        tproxy_priority: TPROXY_RULE_PRIORITY,
        tun_table: cfg.tun.table,
        tun_mark: MARK_UDP,
        tun_priority: 0,
        tun_name: None, // the TUN device installs its own rules
    }
}

pub async fn run(cfg: Config, args: RunArgs) -> Result<()> {
    crate::app::require_root()?;
    if !args.force {
        let foreign = airgrill_net::nft::foreign_policy_routes()
            .context("checking existing policy routing")?;
        if !foreign.is_empty() {
            let list = foreign
                .iter()
                .map(|(t, iface)| format!("table {t} ({iface})"))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "another policy-routing VPN/TUN is active: {list}.\n\
                 airgrill would intercept its outbound 443 and can break it.\n\
                 Stop that VPN first, or pass --force if you know what you are doing."
            );
        }
    }
    let cfg = Arc::new(cfg);

    // Remove leftovers from a crashed previous run *before* starting sockets:
    // otherwise the old redirect/tproxy rules can capture our own traffic.
    let rules = NftRules::from_config(&cfg)?;
    if !args.no_rules {
        let _ = rules.remove("nft");
        drop(policy_routes(&cfg));
    }

    let router = Arc::new(Router::new(&cfg)?);
    tracing::info!(
        mode = ?cfg.routing.mode,
        default = %router.default_route(),
        "routing table loaded"
    );

    // Expired DNS-derived addresses are only removed by a lookup otherwise;
    // prune in the background so the map stays bounded.
    {
        let index = router.ip_index();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                index.prune();
            }
        });
    }

    let dpi_plan = Arc::new(DpiPlan::build(&cfg)?);
    let backends = Arc::new(
        Backends::start(&cfg.proxy, MARK_SKIP)
            .await
            .context("starting proxy backends")?,
    );
    let state = Arc::new(AppState {
        cfg: Arc::clone(&cfg),
        router: Arc::clone(&router),
        backends,
        tcp_port: cfg.router.tcp_port,
        dpi_plan: Arc::clone(&dpi_plan),
        default_strategy: cfg.dpi.strategy.clone(),
    });

    if let Some(dns) = airgrill_dns::bind(&cfg, Arc::clone(&router))
        .await
        .context("starting DNS proxy")?
    {
        dns.spawn();
    }

    if cfg.router.enabled {
        // Forwarding is required for the LAN router role.  This is a system
        // setting; it is intentionally not reverted on exit (other tools may
        // depend on it).
        for (key, value) in [
            ("net.ipv4.ip_forward", "1"),
            ("net.ipv6.conf.all.forwarding", "1"),
        ] {
            if let Err(e) = std::process::Command::new("sysctl")
                .args(["-qw", &format!("{key}={value}")])
                .output()
            {
                tracing::warn!(key, error = %e, "could not enable forwarding");
            }
        }
    }

    let tun = if cfg.tun.enabled {
        let tun = Tun::create(
            &cfg.tun.name,
            cfg.tun.address_v4,
            cfg.tun.address_v6,
            cfg.tun.mtu,
            cfg.tun.table,
            MARK_UDP,
        )
        .context("creating UDP TUN")?;
        let tun = Arc::new(tun);
        udp::start(Arc::clone(&state), Arc::clone(&tun))?;
        Some(tun)
    } else {
        None
    };

    tcp::start(Arc::clone(&state))?;

    if cfg.proxy_inbound.enabled {
        crate::mixed::start(Arc::clone(&state)).context("starting local HTTP proxy")?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    if cfg.dpi.enabled {
        for route in dpi_plan.routes() {
            let settings = DpiSettings::parse(
                route.queue,
                MARK_SKIP,
                &route.strategy,
                &cfg.dpi.decoy,
                cfg.dpi.delay_ms,
                cfg.dpi.frag_first,
                cfg.dpi.frag_reverse,
            )?;
            let stop = Arc::clone(&stop);
            let strategy = route.strategy.clone();
            std::thread::Builder::new()
                .name(format!("airgrill-dpi-{}", route.id))
                .spawn(move || {
                    if let Err(e) = run_queue(settings, stop) {
                        tracing::error!(strategy = %strategy, error = %e, "DPI engine stopped");
                    }
                })
                .with_context(|| format!("spawning DPI thread for {}", route.strategy))?;
        }
        // Give the NFQUEUE binds a moment before the capturing rules exist.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let policy = policy_routes(&cfg);

    let _nft_guard = if args.no_rules {
        tracing::warn!("--no-rules: not installing nftables rules");
        None
    } else {
        // Policy routing first: the tproxy rule must never see a packet
        // before the local route table exists.
        policy
            .install()
            .context("installing TPROXY policy routing")?;
        rules.install("nft").context("installing nftables rules")?;
        Some(NftGuard {
            rules: rules.clone(),
            nft_bin: "nft".into(),
        })
    };

    tracing::info!("airgrill is running (Ctrl-C to stop)");
    wait_for_shutdown().await;
    tracing::info!("shutting down");
    stop.store(true, Ordering::Relaxed);

    // Dropping the guard removes nftables; PolicyRoutes removes ip rules.
    drop(_nft_guard);
    drop(policy);
    drop(tun);

    // Give the DPI thread a moment to observe the stop flag and release its
    // NFQUEUE binding before the process exits.
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(())
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
