//! Socket marks shared by the nftables rules and the Rust datapath.
//!
//! All marks live in the low byte of `skb->mark`; the high bits are left alone
//! so that other tools (Docker, Hiddify, ...) can keep their own bits.

/// Traffic originated by airgrill itself (upstream relay sockets, DNS queries).
/// Such packets must never be redirected back into the transparent listener.
pub const MARK_SKIP: u32 = 0x40;

/// Bit that asks the DPI engine to desync the first packets of a socket.
/// Combined with `MARK_SKIP` so the same socket is not intercepted again.
pub const MARK_DPI: u32 = MARK_SKIP | 0x02;

/// Bit that sends UDP packets into the userspace TUN datapath.
pub const MARK_UDP: u32 = 0x10;

/// Mark used by the TPROXY policy routing rule.
pub const MARK_TPROXY: u32 = 0x01;

pub const SKIP_MASK: u32 = 0x40;

/// Mask covering the DPI flag and the 8-bit strategy id.
pub const DPI_MASK: u32 = 0xff02;

/// Socket mark for a strategy id: skip bit + DPI flag + `id << 8`.
pub fn dpi_mark(id: u8) -> u32 {
    MARK_SKIP | 0x02 | ((id as u32) << 8)
}

pub const TABLE: &str = "airgrill";

/// nftables set name for a route and address family.
pub fn set_name(route: crate::config::Route, v6: bool) -> String {
    format!("{}_{}", route.as_str(), if v6 { "v6" } else { "v4" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Route;

    #[test]
    fn dpi_ids() {
        assert_eq!(dpi_mark(0) & DPI_MASK, 0x02);
        assert_eq!(dpi_mark(1) & DPI_MASK, 0x102);
        assert_eq!(dpi_mark(1) & MARK_SKIP, MARK_SKIP);
        assert_eq!(dpi_mark(7) & MARK_UDP, 0);
    }

    #[test]
    fn flags_do_not_overlap() {
        assert_eq!(MARK_SKIP & MARK_UDP, 0);
        assert_eq!(MARK_SKIP & MARK_TPROXY, 0);
        assert_eq!(MARK_DPI & MARK_SKIP, MARK_SKIP);
        assert_eq!(MARK_DPI & MARK_UDP, 0);
    }

    #[test]
    fn set_names() {
        assert_eq!(set_name(Route::Proxy, false), "proxy_v4");
        assert_eq!(set_name(Route::Direct, true), "direct_v6");
    }
}
