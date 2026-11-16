//! Userspace TCP desync (a Rust analogue of GoodbyeDPI/zapret).
//!
//! The kernel sends the first packets of marked TCP connections to an NFQUEUE.
//! We parse the TLS ClientHello / HTTP request, drop the original packet and
//! re-emit it as reordered or fake segments through a raw socket.  Sequence
//! numbers stay consistent, so the peer's TCP stack accepts the data.
//!
//! This crate contains no policy: the daemon only marks connections whose
//! route is `dpi`, everything else never reaches the queue.

pub mod dpi;
pub mod inject;
pub mod net;
pub mod nfq;
pub mod strategy;
pub mod worker;

pub use worker::{run_queue, DpiSettings};
