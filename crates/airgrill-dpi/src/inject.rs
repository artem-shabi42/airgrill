//! Raw-socket packet injection.
//!
//! Injected packets are tagged with a socket mark so the nftables rule that
//! sends traffic to NFQUEUE skips them (no feedback loop).

use anyhow::{bail, Context, Result};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;
const IPPROTO_IP: i32 = 0;
const IP_HDRINCL: i32 = 3;
const IPPROTO_IPV6: i32 = 41;
const IPV6_HDRINCL: i32 = 36;

pub struct Injector {
    v4: RawFd,
    v6: RawFd,
    mark: u32,
}

fn set_int(fd: RawFd, level: i32, opt: i32, val: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn raw_socket(domain: i32) -> io::Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

impl Injector {
    pub fn new(mark: u32) -> Result<Self> {
        let v4 =
            raw_socket(libc::AF_INET).context("raw IPv4 socket (need CAP_NET_RAW, i.e. root)")?;
        set_int(v4, IPPROTO_IP, IP_HDRINCL, 1).context("IP_HDRINCL")?;

        let v6 =
            raw_socket(libc::AF_INET6).context("raw IPv6 socket (need CAP_NET_RAW, i.e. root)")?;
        set_int(v6, IPPROTO_IPV6, IPV6_HDRINCL, 1).context("IPV6_HDRINCL")?;

        for fd in [v4, v6] {
            if let Err(e) = set_int(fd, SOL_SOCKET, SO_MARK, mark as i32) {
                // Marking is an optimisation; without it injected packets hit
                // the queue again. Fail loudly: a loop is worse than an error.
                bail!("SO_MARK (need CAP_NET_ADMIN): {e}");
            }
        }
        Ok(Injector { v4, v6, mark })
    }

    pub fn mark(&self) -> u32 {
        self.mark
    }

    /// Send a fully formed IP packet.
    pub fn send(&self, pkt: &[u8]) -> Result<()> {
        match pkt.first().map(|b| b >> 4) {
            Some(4) if pkt.len() >= 20 => {
                let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
                sin.sin_family = libc::AF_INET as u16;
                sin.sin_port = 0;
                let mut a = [0u8; 4];
                a.copy_from_slice(&pkt[16..20]);
                sin.sin_addr.s_addr = u32::from_ne_bytes(a);
                self.send_raw(
                    self.v4,
                    pkt,
                    &sin as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            Some(6) if pkt.len() >= 40 => {
                let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
                sin6.sin6_family = libc::AF_INET6 as u16;
                sin6.sin6_port = 0;
                sin6.sin6_addr.s6_addr.copy_from_slice(&pkt[24..40]);
                self.send_raw(
                    self.v6,
                    pkt,
                    &sin6 as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
            _ => bail!("refusing to send malformed packet ({} bytes)", pkt.len()),
        }
    }

    fn send_raw(
        &self,
        fd: RawFd,
        pkt: &[u8],
        addr: *const libc::sockaddr,
        alen: libc::socklen_t,
    ) -> Result<()> {
        let rc = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                addr,
                alen,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            bail!("raw send: {e}");
        }
        Ok(())
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.v4);
            libc::close(self.v6);
        }
    }
}
