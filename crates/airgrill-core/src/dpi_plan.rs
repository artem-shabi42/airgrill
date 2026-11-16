//! Assign a stable NFQUEUE and socket-mark id to every distinct DPI strategy.
//!
//! Different lists may use different strategies.  Each strategy gets its own
//! NFQUEUE so the worker can run the matching strategy without inspecting the
//! packet mark.

use crate::config::{Config, Route};
use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpiRoute {
    pub strategy: String,
    /// 8-bit id encoded in the socket mark.
    pub id: u8,
    pub queue: u16,
}

#[derive(Debug, Clone, Default)]
pub struct DpiPlan {
    routes: Vec<DpiRoute>,
}

impl DpiPlan {
    pub fn build(cfg: &Config) -> Result<Self> {
        if !cfg.dpi.enabled {
            return Ok(Self::default());
        }

        let mut strategies = Vec::<String>::new();
        let mut push = |s: &str| {
            if !s.is_empty() && !strategies.iter().any(|x| x == s) {
                strategies.push(s.to_string());
            }
        };
        push(&cfg.dpi.strategy);
        for rule in &cfg.routing.rules {
            if rule.route == Route::Dpi {
                if let Some(strategy) = &rule.strategy {
                    push(strategy);
                }
            }
        }
        // Legacy `routing.lists.dpi` uses the global strategy, already added.

        let mut routes = Vec::with_capacity(strategies.len());
        for (i, strategy) in strategies.into_iter().enumerate() {
            let id = u8::try_from(i)
                .map_err(|_| anyhow::anyhow!("too many distinct DPI strategies (max 255)"))?;
            let queue =
                cfg.dpi.queue_num.checked_add(i as u16).ok_or_else(|| {
                    anyhow::anyhow!("dpi.queue_num + strategy index overflows u16")
                })?;
            routes.push(DpiRoute {
                strategy,
                id,
                queue,
            });
        }
        Ok(Self { routes })
    }

    pub fn routes(&self) -> &[DpiRoute] {
        &self.routes
    }

    pub fn id(&self, strategy: &str) -> Option<u8> {
        self.routes
            .iter()
            .find(|r| r.strategy == strategy)
            .map(|r| r.id)
    }

    pub fn route(&self, id: u8) -> Option<&DpiRoute> {
        self.routes.iter().find(|r| r.id == id)
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Strategy used when a DPI rule does not specify one.
    pub fn default_strategy(&self) -> Option<&str> {
        self.routes.first().map(|r| r.strategy.as_str())
    }
}

/// Validate a plan (used by config checks).
pub fn ensure_queue_range(base: u16, count: usize) -> Result<()> {
    if count > u8::MAX as usize + 1 {
        bail!("too many DPI strategies");
    }
    base.checked_add(count.saturating_sub(1) as u16)
        .ok_or_else(|| anyhow::anyhow!("dpi.queue_num + strategy count overflows u16"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn deduplicates_and_assigns_queues() {
        let cfg = Config::parse(
            r#"
[routing]
mode = "lists"
[dpi]
enabled = true
strategy = "disorder:sni"
queue_num = 200
[[routing.rules]]
name = "a"
route = "dpi"
strategy = "fake:sni"
domains = ["domain:a.example"]
[[routing.rules]]
name = "b"
route = "dpi"
strategy = "disorder:sni"
domains = ["domain:b.example"]
"#,
        )
        .unwrap();
        let plan = DpiPlan::build(&cfg).unwrap();
        assert_eq!(plan.routes().len(), 2);
        assert_eq!(plan.id("disorder:sni"), Some(0));
        assert_eq!(plan.id("fake:sni"), Some(1));
        assert_eq!(plan.routes()[1].queue, 201);
    }
}
