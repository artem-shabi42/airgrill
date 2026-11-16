use airgrill_core::{Config, DpiPlan, Router};
use airgrill_proxy::Backends;
use std::sync::Arc;

/// Shared state used by the TCP and UDP datapaths.
pub struct AppState {
    pub cfg: Arc<Config>,
    pub router: Arc<Router>,
    pub backends: Arc<Backends>,
    pub tcp_port: u16,
    pub dpi_plan: Arc<DpiPlan>,
    pub default_strategy: String,
}
