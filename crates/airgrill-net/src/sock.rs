//! Socket helpers: marks, transparent listeners and original-destination
//! recovery.
//!
//! `SO_MARK` must be set *before* `connect()`: the very first SYN is what the
//! transparent rules see, and an unmarked SYN would be redirected back into
//! airgrill (a loop).

use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

pub const SOL_SOCKET: i32 = 1;
pub const SO_MARK: i32 = 36;
pub const SO_ORIGINAL_DST: i32 = 80;
pub const IP_TRANSPARENT: i32 = 19;
pub const IPV6_TRANSPARENT: i32 = 75;
pub const IP_RECVORIGDSTADDR: i32 = 20;
pub const IPV6_RECVORIGDSTADDR: i32 = 74;

pub fn set_mark_fd(fd: RawFd, mark: u32) -> io::Result<()> {
    let val = mark as libc::c_int;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_SOCKET,
            SO_MARK,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_opt(sock: &Socket, level: i32, opt: i32, val: libc::c_int) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socket_for(addr: SocketAddr, ty: Type, proto: Protocol) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    Socket::new(domain, ty, Some(proto))
}

/// Non-blocking TCP connect with `SO_MARK` applied before the SYN.
pub async fn connect_marked(addr: SocketAddr, mark: u32, timeout: Duration) -> Result<TcpStream> {
    let sock = socket_for(addr, Type::STREAM, Protocol::TCP)
        .with_context(|| format!("socket for {addr}"))?;
    sock.set_mark(mark)
        .with_context(|| format!("SO_MARK 0x{mark:x}"))?;
    sock.set_nonblocking(true)?;
    sock.set_tcp_nodelay(true)?;

    match sock.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e).with_context(|| format!("connect {addr}")),
    }

    let std_stream: std::net::TcpStream = sock.into();
    std_stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(std_stream)?;

    tokio::time::timeout(timeout, async {
        stream.writable().await?;
        if let Some(e) = stream.take_error()? {
            return Err(e);
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to {addr}"))?
    .with_context(|| format!("connect {addr}"))?;

    Ok(stream)
}

/// Bind a UDP socket and mark it.  The mark prevents our own upstream packets
/// from being routed back into the TUN capture rule.
pub fn udp_socket_marked(addr: SocketAddr, mark: u32) -> io::Result<UdpSocket> {
    let sock = socket_for(addr, Type::DGRAM, Protocol::UDP)?;
    sock.set_mark(mark)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// A listening TCP socket for REDIRECT (host) and TPROXY (LAN) traffic.
pub fn tcp_listener(addr: SocketAddr, transparent: bool) -> Result<std::net::TcpListener> {
    let sock = socket_for(addr, Type::STREAM, Protocol::TCP)
        .with_context(|| format!("listener socket {addr}"))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    if transparent {
        if addr.is_ipv4() {
            set_opt(&sock, libc::IPPROTO_IP, IP_TRANSPARENT, 1)
                .context("IP_TRANSPARENT (need CAP_NET_ADMIN)")?;
        } else {
            set_opt(&sock, libc::IPPROTO_IPV6, IPV6_TRANSPARENT, 1)
                .context("IPV6_TRANSPARENT (need CAP_NET_ADMIN)")?;
        }
    }
    sock.bind(&addr.into())
        .with_context(|| format!("bind {addr}"))?;
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be(sin6.sin6_port),
            ))
        }
        _ => None,
    }
}

/// Return the destination the client originally connected to.
///
/// * TPROXY: the accepted socket is bound to the original destination, so
///   `getsockname()` already returns it.
/// * REDIRECT (host): `getsockname()` is the local listener; the conntrack
///   lookup `SO_ORIGINAL_DST` recovers the real destination.
pub fn original_dst(fd: RawFd, listener_port: u16) -> Result<SocketAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc =
        unsafe { libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("getsockname");
    }
    let local = sockaddr_to_std(&storage).context("getsockname returned unknown family")?;
    if local.port() != listener_port && !local.ip().is_unspecified() {
        return Ok(local);
    }

    let level = if local.is_ipv4() {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    };
    let mut dst: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut dlen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            SO_ORIGINAL_DST,
            &mut dst as *mut _ as *mut libc::c_void,
            &mut dlen,
        )
    };
    if rc < 0 {
        bail!(
            "cannot recover original destination (getsockname={local}, SO_ORIGINAL_DST: {})",
            io::Error::last_os_error()
        );
    }
    sockaddr_to_std(&dst).context("SO_ORIGINAL_DST returned unknown family")
}

/// IPv4/IPv6 UDP socket that receives the original destination via ancillary
/// data (`IP_ORIGDSTADDR`).  Used only for diagnostics and future TPROXY UDP
/// experiments; the main UDP path is TUN-based.
pub fn udp_transparent(addr: SocketAddr) -> Result<Socket> {
    let sock = socket_for(addr, Type::DGRAM, Protocol::UDP)?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
        set_opt(&sock, libc::IPPROTO_IPV6, IPV6_TRANSPARENT, 1)?;
        set_opt(&sock, libc::IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, 1)?;
    } else {
        set_opt(&sock, libc::IPPROTO_IP, IP_TRANSPARENT, 1)?;
        set_opt(&sock, libc::IPPROTO_IP, IP_RECVORIGDSTADDR, 1)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}
