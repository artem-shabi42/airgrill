# Integration tests (Linux netns)

The unit tests do not touch the network.  The scenarios below exercise the real
datapath and require root (or a user namespace).  They were used while building
airgrill and are kept here so regressions are reproducible.

> Everything runs in throw-away network namespaces.  Do not run these scripts
> against your real interfaces.

## 0. Build

```bash
cargo build
BIN=$PWD/target/debug/airgrill
```

## 1. Host TCP + host UDP (one namespace)

A transparent server binds a non-local address (`IP_TRANSPARENT`) and a route
for it goes through `lo`.  nft redirects the client's TCP connection and marks
its UDP; airgrill relays both.

```bash
unshare -rn sh -c '
  ip link set lo up
  ip route add 203.0.113.1/32 dev lo
  python3 server.py &        # TCP/UDP echo on 203.0.113.1, IP_TRANSPARENT
  /path/to/airgrill -c host.toml run &
  sleep 1
  python3 client.py          # TCP 8443 + UDP 9999
  kill %2 %1
'
```

`host.toml` needs `router.enabled = false`, `host_all_tcp = true`, `tun.enabled = true`,
`dns.enabled = false`.

## 2. LAN TCP TPROXY (three namespaces)

Three netns: client, router, server.  Two veth pairs:

* `lan0` (router, 10.10.10.1/24) ↔ `lanC` (client, 10.10.10.2/24)
* `wan0` (router, 203.0.113.2/24) ↔ `wanS` (server, 203.0.113.1/24)

Start `airgrill` in the router namespace with:

```toml
[router]
enabled = true
lan_interfaces = ["lan0"]
lan_cidrs = ["10.10.10.0/24"]
lan_all_tcp = true
[tun]
enabled = false
```

The client connects to `203.0.113.1:8443`; the server echoes.  A successful
round-trip proves TPROXY, original-destination recovery and the reply path.

## 3. LAN UDP over TUN (three namespaces)

Same topology, plus `[tun] enabled = true`.  The client sends UDP to
`203.0.113.1:9999`; airgrill reads the packet from the TUN, sends it direct and
injects the reply.  Repeat with `mode = "proxy-default"` and a SOCKS5 UDP
backend to test the proxy path.

## 4. DNS

Run a tiny UDP DNS responder in the server namespace on `203.0.113.1:53` and set
`dns.upstreams = ["203.0.113.1:53"]`.  Query from the client namespace to any
resolver address (`203.0.113.1:53` works).  The reply must contain the A record;
airgrill's log should show `DNS classified ... route=...`.

## 5. DPI desync

Route a domain to `dpi`, point a fake TLS ClientHello at an echo server:

```toml
[routing.lists]
dpi = ["domain:blocked.example"]
[dpi]
enabled = true
strategy = "disorder:sni"
```

airgrill logs `desync ... actions=...`; the echo server must receive the exact
same bytes after TCP reassembly.  This validates the mark (0x42), NFQUEUE,
raw injection and sequence numbers.

## 6. Real Xray backend

Run a real Xray server in the server namespace (VLESS + TLS, self-signed cert)
and configure a `kind = "xray"` backend.  With modern Xray, pin the cert:

```
vless://UUID@203.0.113.1:443?security=tls&type=tcp&sni=test.local&pcs=<sha256>
```

If the target address is blocked by Xray's freedom outbound, bind a transparent
echo socket on a globally-routable-looking IP and add a `/32` route via `lo`
inside the server namespace.

## 7. Cleanup checks

After SIGTERM the following must be empty:

```bash
nft list table inet airgrill       # no such table
ip rule show | grep -E 'fwmark 0x(1|10)'
ip route show table 100
ip route show table 101
ip link show airgrill0
```
