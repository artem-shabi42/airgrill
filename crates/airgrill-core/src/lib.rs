//! Shared configuration, rule matching and routing for airgrill.

pub mod config;
pub mod dpi_plan;
pub mod ip_index;
pub mod marks;
pub mod routing;
pub mod rules;

pub use config::{Config, Mode, Route, RuleConfig};
pub use dpi_plan::{DpiPlan, DpiRoute};
pub use ip_index::IpIndex;
pub use routing::{Decision, Router};
pub use rules::{CompiledRule, Matcher, RuleSet};
