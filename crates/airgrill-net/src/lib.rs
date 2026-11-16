//! Linux networking primitives for airgrill: nftables rules, marked sockets,
//! transparent listeners and the UDP TUN datapath.

pub mod nft;
pub mod sock;
pub mod tun;

pub use nft::{NftRules, PolicyRoutes};
pub use sock::{connect_marked, original_dst, tcp_listener, udp_socket_marked};
pub use tun::{build_udp, parse_udp, Tun, UdpPacket};
