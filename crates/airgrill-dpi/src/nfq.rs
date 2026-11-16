//! Minimal, dependency-free NFQUEUE client (nfnetlink_queue) over NETLINK.
//!
//! We speak the netlink protocol directly instead of linking
//! libnetfilter_queue: fewer moving parts, no C toolchain, and full control
//! over the verdict path.

use anyhow::{anyhow, bail, Context, Result};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

const NETLINK_NETFILTER: i32 = 12;
const NLM_F_REQUEST: u16 = 0x1;
const NLMSG_ERROR: u16 = 2;

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;

const NFQA_CFG_F_FAIL_OPEN: u32 = 1 << 0;

const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;

/// An outbound packet handed to us by the kernel.
pub struct Msg {
    pub id: u32,
    pub hook: u8,
    pub payload: Vec<u8>,
}

pub struct Queue {
    fd: RawFd,
    seq: u32,
    qnum: u16,
    closed: bool,
}

fn nlmsg(out: &mut Vec<u8>, typ: u16, flags: u16, seq: u32, body: &[u8]) {
    let len = 16 + body.len();
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&typ.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    out.extend_from_slice(body);
}

/// Patch nlmsg_len once all attributes have been appended.
fn patch_len(out: &mut [u8]) {
    let len = out.len() as u32;
    out[..4].copy_from_slice(&len.to_ne_bytes());
}

fn nfgenmsg(family: u8, res_id: u16) -> [u8; 4] {
    // struct nfgenmsg { u8 nfgen_family; u8 version; __be16 res_id; }
    [family, 0, (res_id >> 8) as u8, res_id as u8]
}

fn attr(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    let len = 4 + data.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&typ.to_ne_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn attr_be32(out: &mut Vec<u8>, typ: u16, v: u32) {
    attr(out, typ, &v.to_be_bytes());
}

impl Queue {
    /// Open and bind an NFQUEUE. `fail_open` makes the kernel accept packets
    /// when nobody is reading the queue (so a crash never bricks networking).
    pub fn open(qnum: u16, maxlen: u32, fail_open: bool) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            bail!("socket(NETLINK_NETFILTER): {}", io::Error::last_os_error());
        }
        let mut q = Queue {
            fd,
            seq: 1,
            qnum,
            closed: false,
        };

        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                q.fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            q.close_fd();
            return Err(anyhow!("bind(netlink): {e}"));
        }

        // Large receive buffer + never report ENOBUFS: dropped packets are
        // fine (fail-open), spurious errors are not.
        let rcvbuf: libc::c_int = 16 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                q.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let one: libc::c_int = 1;
            libc::setsockopt(
                q.fd,
                270, // SOL_NETLINK
                5,   // NETLINK_NO_ENOBUFS
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 200_000,
            };
            libc::setsockopt(
                q.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        // A previous instance may still be releasing the queue (restart,
        // signal handling). Retry briefly; a busy queue belongs to another
        // netlink portid and would otherwise fail with EPERM/E BUSY.
        let mut last = None;
        for attempt in 0..6 {
            match q.bind_queue(maxlen, fail_open) {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    if attempt < 5 {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
            }
        }
        if let Some(e) = last {
            return Err(e.context(format!(
                "binding nfqueue {} (busy? another gdpi instance or missing CAP_NET_ADMIN)",
                qnum
            )));
        }
        Ok(q)
    }

    pub fn queue_num(&self) -> u16 {
        self.qnum
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// BIND the queue and configure it in a single message.
    ///
    /// Note: `NFQA_CFG_CMD` must be exactly `struct nfqnl_msg_config_cmd`
    /// (4 bytes: command, pad, __be16 pf) and `NFQA_CFG_PARAMS` exactly
    /// `struct nfqnl_msg_config_params` (packed: __be32 copy_range, u8 mode).
    /// The kernel validates attribute lengths strictly (-ERANGE otherwise).
    fn bind_queue(&mut self, maxlen: u32, fail_open: bool) -> Result<()> {
        let seq = self.next_seq();
        let mut b = Vec::new();
        nlmsg(
            &mut b,
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            NLM_F_REQUEST | 0x4,
            seq,
            &nfgenmsg(0, self.qnum),
        );
        attr(&mut b, NFQA_CFG_CMD, &[NFQNL_CFG_CMD_BIND, 0, 0, 0]);
        let copy = 0xffffu32.to_be_bytes();
        attr(
            &mut b,
            NFQA_CFG_PARAMS,
            &[copy[0], copy[1], copy[2], copy[3], 2],
        ); // COPY_PACKET
        attr_be32(&mut b, NFQA_CFG_MASK, NFQA_CFG_F_FAIL_OPEN);
        let flags = if fail_open { NFQA_CFG_F_FAIL_OPEN } else { 0 };
        attr_be32(&mut b, NFQA_CFG_FLAGS, flags);
        attr_be32(&mut b, NFQA_CFG_QUEUE_MAXLEN, maxlen);
        patch_len(&mut b);
        if std::env::var_os("GDPI_NL_DEBUG").is_some() {
            eprintln!(
                "nl send ({} bytes): {}",
                b.len(),
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        self.send(&b)?;
        self.wait_ack(seq)
            .with_context(|| format!("binding nfqueue {}", self.qnum))
    }

    fn unbind(&mut self) {
        if self.closed {
            return;
        }
        let seq = self.next_seq();
        let mut b = Vec::new();
        nlmsg(
            &mut b,
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            NLM_F_REQUEST,
            seq,
            &nfgenmsg(0, self.qnum),
        );
        attr(&mut b, NFQA_CFG_CMD, &[NFQNL_CFG_CMD_UNBIND, 0, 0, 0]);
        patch_len(&mut b);
        let _ = self.send(&b);
        self.closed = true;
    }

    fn close_fd(&self) {
        unsafe {
            libc::close(self.fd);
        }
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
        let rc =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(rc as usize)
    }

    /// Wait for the NLMSG_ERROR ack of message `seq`. Packet messages that
    /// arrive in between are ignored (they stay queued in the kernel).
    fn wait_ack(&mut self, seq: u32) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        for _ in 0..64 {
            let n = match self.recv_raw(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    bail!("timed out waiting for netlink ack")
                }
                Err(e) => return Err(e.into()),
            };
            let mut off = 0usize;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                if len < 16 || off + len > n {
                    break;
                }
                let typ = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                let mseq = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
                if std::env::var_os("GDPI_NL_DEBUG").is_some() {
                    eprintln!("nl recv type={typ} seq={mseq} want={seq} len={len}");
                }
                if typ == NLMSG_ERROR && mseq == seq && len >= 20 {
                    let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                    if err != 0 {
                        return Err(anyhow!("{}", io::Error::from_raw_os_error(-err)));
                    }
                    return Ok(());
                }
                off += (len + 3) & !3;
            }
        }
        bail!("no netlink ack after 64 messages")
    }

    /// Receive one packet. Returns `Ok(None)` on receive timeout.
    pub fn recv(&mut self) -> Result<Option<Msg>> {
        let mut buf = vec![0u8; 65536];
        let n = match self.recv_raw(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(None)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let mut off = 0usize;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            if len < 16 || off + len > n {
                break;
            }
            let typ = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if typ == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET && len >= 20 {
                if let Some(msg) = parse_packet(&buf[off + 20..off + len]) {
                    return Ok(Some(msg));
                }
            }
            off += (len + 3) & !3;
        }
        Ok(None)
    }

    fn verdict(&self, id: u32, verdict: u32) -> io::Result<()> {
        let mut b = Vec::with_capacity(64);
        nlmsg(
            &mut b,
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
            NLM_F_REQUEST,
            0,
            &nfgenmsg(0, self.qnum),
        );
        let mut vh = Vec::with_capacity(8);
        vh.extend_from_slice(&verdict.to_be_bytes());
        vh.extend_from_slice(&id.to_be_bytes());
        attr(&mut b, NFQA_VERDICT_HDR, &vh);
        patch_len(&mut b);
        self.send(&b)
    }

    pub fn accept(&self, id: u32) -> io::Result<()> {
        self.verdict(id, NF_ACCEPT)
    }

    pub fn drop(&self, id: u32) -> io::Result<()> {
        self.verdict(id, NF_DROP)
    }
}

fn parse_packet(body: &[u8]) -> Option<Msg> {
    let mut id = 0u32;
    let mut hook = 0u8;
    let mut payload = Vec::new();
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let alen = u16::from_ne_bytes(body[off..off + 2].try_into().ok()?) as usize;
        let atyp = u16::from_ne_bytes(body[off + 2..off + 4].try_into().ok()?);
        if alen < 4 || off + alen > body.len() {
            break;
        }
        let data = &body[off + 4..off + alen];
        match atyp {
            NFQA_PACKET_HDR if data.len() >= 7 => {
                id = u32::from_be_bytes(data[0..4].try_into().ok()?);
                hook = data[6];
            }
            NFQA_PAYLOAD => payload = data.to_vec(),
            _ => {}
        }
        off += (alen + 3) & !3;
    }
    Some(Msg { id, hook, payload })
}

impl Drop for Queue {
    fn drop(&mut self) {
        self.unbind();
        self.close_fd();
    }
}
