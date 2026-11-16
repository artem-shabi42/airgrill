#!/usr/bin/env bash
# airgrill: подготовка и переключение с Hiddify.
#
#   sudo /tmp/airgrill-switch.sh                 # build + switch + stop Hiddify + start airgrill
#   sudo /tmp/airgrill-switch.sh --no-switch     # не делать nixos-rebuild (сервис уже установлен)
#   sudo /tmp/airgrill-switch.sh --prepare-only  # только извлечь VLESS в /etc/airgrill/vless_uri
#   sudo /tmp/airgrill-switch.sh --rollback      # остановить airgrill и убрать его правила
#
# Скрипт идемпотентный. Секрет (VLESS UUID/путь) не печатается.
set -Eeuo pipefail
export PATH=/run/current-system/sw/bin:/run/wrappers/bin:/nix/var/nix/profiles/default/bin:$PATH

MODE=switch
case "${1:-}" in
  ""|--switch) MODE=switch ;;
  --no-switch) MODE=no-switch ;;
  --prepare-only) MODE=prepare-only ;;
  --rollback) MODE=rollback ;;
  -h|--help)
    sed -n '2,14p' "$0"; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Запусти через sudo: sudo $0 ${1:-}" >&2
  exit 1
fi

HERE=/home/artem/Utils/hiddify
AIRGRILL_CONFIG=/etc/airgrill/config.toml
SECRET=/etc/airgrill/vless_uri
HIDDIFY_STOPPED=0

log()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

on_error() {
  local rc=$?
  echo
  echo "!!! Ошибка (код $rc)."
  if [[ $HIDDIFY_STOPPED -eq 1 ]]; then
    echo "Hiddify был остановлен. Проверь: journalctl -u airgrill -n 100"
    echo "Вернуть Hiddify вручную: sudo -E $HERE/run-tun.sh"
    echo "Откатить правила airgrill: sudo $0 --rollback"
  fi
  exit $rc
}
trap on_error ERR

prepare_secret() {
  log "извлекаю VLESS-конфиг из текущего Hiddify"
  install -d -m 0755 /etc/airgrill
  python3 - <<'PY'
import json, os, socket, sys, urllib.parse
src = "/home/artem/.local/share/app.hiddify.com/data/current-config.json"
try:
    data = json.load(open(src))
except Exception as exc:
    sys.exit(f"не читается {src}: {exc}")

outs = data.get("outbounds", [])
def tag(name):
    for o in outs:
        if o.get("tag") == name:
            return o
    return None

sel = next((o for o in outs if o.get("type") == "selector"), None)
out = tag(sel.get("default")) if sel else None
if not out or out.get("type") != "vless":
    out = next((o for o in outs if o.get("type") == "vless"), None)
if not out:
    sys.exit("в active Hiddify config нет VLESS outbound")

tls = out.get("tls") or {}
tr = out.get("transport") or {}
reality = tls.get("reality") or {}
utls = tls.get("utls") or {}
server = str(out["server"])
port = int(out.get("server_port") or 443)
q = {"encryption": "none"}

if reality.get("enabled"):
    q["security"] = "reality"
    if tls.get("server_name"): q["sni"] = tls["server_name"]
    if reality.get("public_key"): q["pbk"] = reality["public_key"]
    if reality.get("short_id"): q["sid"] = reality["short_id"]
    if utls.get("fingerprint"): q["fp"] = utls["fingerprint"]
elif tls.get("enabled"):
    q["security"] = "tls"
    if tls.get("server_name"): q["sni"] = tls["server_name"]
    if utls.get("fingerprint"): q["fp"] = utls["fingerprint"]
else:
    q["security"] = "none"

alpn = tls.get("alpn")
if isinstance(alpn, list) and alpn:
    q["alpn"] = ",".join(alpn)
elif isinstance(alpn, str) and alpn:
    q["alpn"] = alpn

network = tr.get("type") or "tcp"
q["type"] = network
if network == "ws":
    # Xray+sabi.ru требует ALPN http/1.1; с h2 WebSocket не поднимается.
    q["alpn"] = "http/1.1"
    q["path"] = tr.get("path") or "/"
    q["host"] = tr.get("headers", {}).get("Host") or server
    if tr.get("early_data_header_name"):
        q["eh"] = tr["early_data_header_name"]
elif network in ("grpc",):
    if tr.get("service_name"): q["serviceName"] = tr["service_name"]
elif network in ("http", "httpupgrade"):
    q["path"] = tr.get("path") or "/"

# Use the literal IPv4 address: direct DNS can be poisoned, while TLS SNI and
# the WS Host header stay the real hostname.
try:
    infos = socket.getaddrinfo(server, port, socket.AF_INET, socket.SOCK_STREAM)
    ip = infos[0][4][0] if infos else server
except Exception:
    ip = server

url = "vless://" + out["uuid"] + "@" + ip + ":" + str(port) + "?" + urllib.parse.urlencode(q)
dst = "/etc/airgrill/vless_uri"
with open(dst, "w", encoding="utf-8") as f:
    f.write(url + "\n")
os.chmod(dst, 0o600)
print(f"  server={server} ip={ip} security={q['security']} transport={network} (секрет не печатается)")
PY
}

stop_runtime_dnsmasq() {
  if [[ -f /run/dnsmasq-eno2.pid ]]; then
    kill "$(cat /run/dnsmasq-eno2.pid)" 2>/dev/null || true
    rm -f /run/dnsmasq-eno2.pid
  fi
  pkill -f 'dnsmasq.*--interface=eno2' 2>/dev/null || true
}

stop_hiddify() {
  log "останавливаю Hiddify"
  pkill -TERM -f 'Hiddify.AppImage' 2>/dev/null || true
  pkill -TERM -x hiddify 2>/dev/null || true
  for _ in $(seq 1 20); do
    pgrep -f 'Hiddify.AppImage|^\./hiddify$' >/dev/null 2>&1 || break
    sleep 0.25
  done
  pkill -KILL -f 'Hiddify.AppImage' 2>/dev/null || true
  pkill -KILL -x hiddify 2>/dev/null || true
  pkill -KILL -f 'HiddifyCli' 2>/dev/null || true
  HIDDIFY_STOPPED=1
  sleep 0.5
}

cleanup_hiddify_net() {
  log "убираю TUN/policy-routing/nat от Hiddify и старого lan-share"
  ip link del tun0 2>/dev/null || true
  ip -6 link del tun0 2>/dev/null || true

  # At priorities 9002/9003 Hiddify installs several rules; delete until none.
  while true; do
    prio=$(ip rule show 2>/dev/null | awk '$1 ~ /^(900[0-9]|9010):/ {gsub(":", "", $1); print $1; exit}')
    [[ -z "$prio" ]] && break
    ip rule del priority "$prio" 2>/dev/null || break
  done
  ip route flush table 2022 2>/dev/null || true
  ip -6 route flush table 2022 2>/dev/null || true

  iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o tun0 -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i eno2 -o tun0 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i tun0 -o eno2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i eno2 -p udp --dport 67 -j ACCEPT 2>/dev/null || true

  # Старые правила airgrill от предыдущего запуска (сервис всё равно перезапустится).
  systemctl stop airgrill 2>/dev/null || true
}

ensure_lan() {
  log "проверяю eno2 / 10.10.10.1"
  if ! ip link show eno2 >/dev/null 2>&1; then
    echo "Нет интерфейса eno2" >&2
    exit 1
  fi
  ip link set eno2 up
  if ! ip -4 addr show dev eno2 | grep -q '10\.10\.10\.1/24'; then
    ip addr replace 10.10.10.1/24 dev eno2
  fi
  sysctl -qw net.ipv4.ip_forward=1
  sysctl -qw net.ipv6.conf.all.forwarding=1
}

start_service() {
  log "запускаю airgrill"
  systemctl daemon-reload
  systemctl enable airgrill >/dev/null 2>&1 || true
  systemctl restart dnsmasq
  systemctl restart airgrill
  # systemd-resolved иногда залипает после смены firewall/NAT.
  systemctl restart systemd-resolved 2>/dev/null || true
  for _ in $(seq 1 40); do
    if systemctl is-active --quiet airgrill; then break; fi
    sleep 0.5
  done
  if ! systemctl is-active --quiet airgrill; then
    systemctl --no-pager --full status airgrill || true
    journalctl -u airgrill -n 80 --no-pager || true
    return 1
  fi
  sleep 1
}

verify() {
  log "проверка"
  airgrill -c "$AIRGRILL_CONFIG" check | sed -n '1,18p' || true
  echo
  nft list table inet airgrill 2>/dev/null | sed -n '1,25p' || true
  echo
  ip rule show | grep -E 'fwmark 0x(1|10)' || true
  echo
  ss -lunp 2>/dev/null | grep -E ':67\b|:15353\b' || true
  echo
  local code
  code=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
    curl --noproxy '*' -sS -m 20 -o /dev/null -w '%{http_code}' https://www.youtube.com/ || true)
  echo "YouTube (DPI): $code"
  code=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
    curl --noproxy '*' -sS -m 20 -o /dev/null -w '%{http_code}' https://discord.com/ || true)
  echo "Discord (proxy): $code"
  echo
  echo "DHCP-лизы: $(wc -l < /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null || echo 0) шт."
  echo
  cat <<'TXT'
Готово. В текущей оболочке старые proxy-переменные могут указывать на Hiddify:
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
Или просто перелогинься. Discord после перезапуска клиента будет без старого
socks5://127.0.0.1:12334.
TXT
}

rollback() {
  log "останавливаю airgrill и убираю его правила"
  systemctl stop airgrill 2>/dev/null || true
  airgrill -c "$AIRGRILL_CONFIG" rules remove 2>/dev/null || true
  echo "airgrill остановлен. Hiddify запускается вручную:"
  echo "  sudo -E $HERE/run-tun.sh"
  echo "Затем (для второго ПК) можно вернуть старый lan-share, если нужен: /tmp/lan-share.sh"
}

prepare_secret

if [[ $MODE == prepare-only ]]; then
  log "готово: секрет в $SECRET (0600)"
  exit 0
fi

if [[ $MODE == rollback ]]; then
  rollback
  exit 0
fi

stop_runtime_dnsmasq

if [[ $MODE == switch ]]; then
  log "обновляю flake input airgrill и собираю систему (Hiddify ещё работает)"
  GIT=/etc/profiles/per-user/artem/bin/git
  [[ -x "$GIT" ]] || GIT=$(command -v git)
  runuser -u artem -- "$GIT" -C /home/artem/airgrill add -A
  # /etc/nixos is a git repo owned by artem; root hits libgit2's safe.directory.
  runuser -u artem -- /run/current-system/sw/bin/bash -c 'cd /etc/nixos && /run/current-system/sw/bin/nix flake update airgrill'
  nixos-rebuild build --flake path:/etc/nixos#nixos
fi

# Hiddify нужно остановить ДО switch: иначе airgrill.service увидит чужой
# policy-routing VPN и упадёт, а switch-to-configuration посчитает это ошибкой.
stop_hiddify
cleanup_hiddify_net
ensure_lan

if [[ $MODE == switch ]]; then
  log "активирую NixOS (airgrill стартует уже без Hiddify)"
  nixos-rebuild switch --flake path:/etc/nixos#nixos
fi

start_service
verify
