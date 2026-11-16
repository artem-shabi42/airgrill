//! Proxy backends.
//!
//! * `xray`   — spawn Xray-core and speak SOCKS5 to it (full protocol support).
//! * `native` — in-process VLESS over TCP/TLS/WS.

pub mod backend;
pub mod socks5;
pub mod target;
pub mod vless;
pub mod xray;

pub use backend::{Backends, ProxyBackend, UdpSession};
pub use target::Target;
pub use vless::{BoxStream, VlessBackend, VlessUrl};
pub use xray::XrayProcess;
