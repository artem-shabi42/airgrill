# airgrill

Прокси-клиент с маршрутизацией **по доменам**: один список идёт напрямую,
второй — напрямую, но с обходом DPI (GoodbyeDPI-подобный desync), третий —
через VLESS/Xray на VPS. Плюс режим роутера: трафик второго ПК, подключённого
по Ethernet, заворачивается в те же правила.

Всё написано на Rust, разбито на маленькие crate'ы, чтобы код можно было читать
по частям.

```
                    ┌──────────────────────────────────────────────┐
  приложения ──────►│ TCP: nft REDIRECT (host) / TPROXY (LAN)      │
                    │      └─ sniff TLS SNI / HTTP Host            │
  второй ПК ───────►│         └─ router.decide(domain, ip)         │
  (eno2, 10.10.10)  │             ├─ direct  → connect_marked()    │
                    │             ├─ dpi     → connect_marked(DPI) │
                    │             │            → NFQUEUE → raw     │
                    │             └─ proxy   → SOCKS5 / VLESS      │
                    │                                              │
  DNS :53 ─────────►│ DNS proxy (UDP/TCP) → upstream               │
                    │      └─ A/AAAA → IP index (для UDP)          │
                    │                                              │
  UDP ─────────────►│ nft mark 0x10 → policy route → TUN           │
                    │      └─ userspace UDP router                 │
                    │             ├─ direct → обычный UDP socket    │
                    │             └─ proxy  → SOCKS5 UDP / VLESS   │
                    └──────────────────────────────────────────────┘
```

## Что уже работает

* TCP 80/443 (host) и весь TCP с LAN: прозрачный перехват, SNI/Host sniffing,
  маршрутизация direct / DPI / proxy / block.
* DPI-desync: `disorder`, `split`, `fake`, `overlap`, `ipfrag` (движок перенесён
  из проверенного `gdpi`: `split`, `disorder`, `fake`, `overlap`, `oob`,
  `disoob`, `ipfrag` и несколько точек разреза; стратегии покрыты тестами).
* UDP: QUIC, игры, голос Discord/Telegram через userspace TUN. Для
  проксируемых — SOCKS5 UDP ASSOCIATE (Xray) или VLESS UDP (native).
* DNS-прокси: перехват `:53` для хоста и LAN, кэш, классификация ответов
  A/AAAA → IP → маршрут (нужно для UDP без SNI).
* Xray-бэкенд: `vless://` со всеми транспортами/Reality/Vision, процессом
  управляет airgrill, наружу он ходит под uid `65534` и не попадает в
  прозрачные правила.
* Native-бэкенд: VLESS over TCP / TLS / WebSocket, включая UDP-framing. Без
  Reality/Vision/gRPC — для них есть Xray.
* Любое количество именованных списков; у каждого свой route, backend и DPI-стратегия.
* Режимы «по спискам» и «всё, кроме списков» (`proxy-default` и т.п.).
* IPv4 и IPv6.

Проверено в изолированных netns (rootless user namespace):

* host TCP REDIRECT → direct relay;
* LAN TCP TPROXY (три namespace: клиент → роутер → сервер);
* UDP через TUN для host и LAN;
* DNS redirect + классификация;
* DPI `disorder:sni` с реальным NFQUEUE и raw-инъекцией;
* SOCKS5 TCP и UDP ASSOCIATE;
* native VLESS TCP и UDP;
* настоящий Xray 26.x (VLESS + TLS + pinning) как backend.

## Workspace

```
crates/
  airgrill-core    конфиг, парсинг списков, matcher, Router, IpIndex
  airgrill-dpi     NFQUEUE + raw-socket desync (net/dpi/strategy/inject/nfq)
  airgrill-net     nftables, policy routing, SO_MARK, TPROXY, TUN, IP/UDP
  airgrill-proxy   backend trait, SOCKS5, native VLESS, управление Xray
  airgrill-dns     DNS proxy + извлечение A/AAAA
  airgrill         демон, CLI, TCP/UDP datapath
```

## Сборка

Нужны Rust (edition 2021), `nftables`, `iproute2`, `/dev/net/tun`, root
(`CAP_NET_ADMIN`, `CAP_NET_RAW`).

```bash
cargo build --release
cargo test
```

Для Reality/Vision/gRPC нужен бинарник `xray` (в NixOS: `nix shell nixpkgs#xray`
или добавить в `environment.systemPackages`). Путь можно указать явно:
`xray_binary = "/run/current-system/sw/bin/xray"`.

## Быстрый старт

```bash
cp examples/airgrill.toml /etc/airgrill/config.toml
$EDITOR /etc/airgrill/config.toml          # списки, VLESS-ссылка, eno2

airgrill -c /etc/airgrill/config.toml check
airgrill -c /etc/airgrill/config.toml route www.youtube.com
airgrill -c /etc/airgrill/config.toml route 8.8.8.8
airgrill -c /etc/airgrill/config.toml run --dry-run   # только показать nft
sudo airgrill -c /etc/airgrill/config.toml run
```

`run` сам создаёт TUN, слушатели, правила nftables и policy routing, а на
SIGTERM/Ctrl-C удаляет их. Если что-то осталось после падения:

```bash
sudo airgrill -c /etc/airgrill/config.toml rules remove
```

Отдельно:

```bash
airgrill rules print          # nftables-скрипт, без root
sudo airgrill rules install   # nft + TPROXY policy routing (TUN routes — в run)
sudo airgrill rules remove
```

## Правила маршрутизации: сколько угодно списков

Списков может быть любое количество.  Каждый список — это `[[routing.rules]]`
со своим `route` (`direct`, `dpi`, `proxy` или `block`), набором правил и
опциональными `backend` / `strategy` / `priority`.

```toml
[routing]
mode = "lists"
default_route = "direct"

[[routing.rules]]
name = "youtube"
route = "dpi"
strategy = "disorder:sni"          # своя стратегия только для этого списка
domains = ["domain:youtube.com", "domain:googlevideo.com"]

[[routing.rules]]
name = "telegram"
route = "proxy"
backend = "vps"                    # можно выбрать конкретный backend
domains = [
  "domain:telegram.org",
  "cidr:149.154.160.0/20",         # MTProto ходит по IP, без SNI
]

[[routing.rules]]
name = "ads"
route = "block"
priority = 10                      # проверяется раньше остальных
domains = ["domain:ads.example"]
```

Порядок:

1. `priority` больше — раньше; при равном `priority` — порядок в файле;
2. первое совпавшее правило выигрывает;
3. если ничего не совпало — IP-карта из DNS;
4. затем `mode`/`default_route`.

`domains`, `entries`, `match` и `list` — синонимы поля со списком правил.
Старый формат `[routing.lists]` продолжает работать: его списки импортируются
после явных правил в историческом порядке `block > proxy > dpi > direct`.

`routing.mode`:

| mode             | что делает                                                    |
|------------------|---------------------------------------------------------------|
| `lists`          | каждый список авторитетен, остальное → `default_route`        |
| `proxy-default`  | всё, чего нет в правилах, идёт в proxy                        |
| `dpi-default`    | всё остальное идёт напрямую с DPI-desync                      |
| `direct-default` | всё остальное напрямую                                        |
| `block-default`  | всё остальное блокируется                                     |

Пример «всё через VPS, кроме YouTube (DPI) и локальных сетей (direct)»:

```toml
[routing]
mode = "proxy-default"

[[routing.rules]]
name = "youtube"
route = "dpi"
strategy = "fake:sni"
domains = ["domain:youtube.com", "domain:googlevideo.com"]

[[routing.rules]]
name = "lan"
route = "direct"
domains = ["cidr:192.168.0.0/16", "domain:example.ru"]
```

Для UDP `route = "dpi"` ведёт себя как `direct`: десинк UDP не даёт надёжного
эффекта. QUIC управляется отдельно: `tun.quic = "block" | "direct" | "proxy"`.

### Синтаксис правил

| правило                | смысл                                      |
|------------------------|--------------------------------------------|
| `example.com`          | домен и все поддомены                      |
| `domain:example.com`   | то же                                      |
| `suffix:example.com`   | то же                                      |
| `full:example.com`     | только точное совпадение                   |
| `keyword:tracker`      | подстрока в имени                          |
| `regex:^ads?\.`        | регулярное выражение                       |
| `cidr:10.0.0.0/8`      | сеть                                       |
| `10.0.0.0/8`, `1.2.3.4`| сеть / одиночный IP                        |
| `*`                    | всё                                        |

`geosite:` / `geoip:` намеренно не поддерживаются — клиент не тащит geo-базы.
Используйте `domain:` / `cidr:`.

### Стратегии DPI

`[dpi].strategy` — стратегия по умолчанию; у каждого `route = "dpi"` списка
можно указать свою `strategy`.  Каждая уникальная стратегия получает
отдельный NFQUEUE (номера начинаются с `dpi.queue_num`) и отдельный 8-битный
id в socket mark, поэтому списков со своими стратегиями может быть много.

| стратегия | что делает |
|-----------|------------|
| `split:sni` | разрезать ClientHello в середине SNI, отправить по порядку |
| `disorder:sni` | то же, но хвост первым (ломает in-order DPI) |
| `fake:sni` | decoy-пакет с другим SNI/TTL, затем disorder |
| `overlap:sni` | хвост, decoy-голова, настоящая голова |
| `oob:sni` | первый кусок с TCP URG, затем остаток (экспериментально) |
| `disoob:sni` | хвост, затем кусок с URG (экспериментально) |
| `ipfrag:sni` | фрагментация на IP-уровне |
| `split:50,100,150` | несколько точек разреза |
| `disorder:50,100` | несколько точек, куски в обратном порядке |

Позиция: `sni`, `mid`, `BYTE`, `BYTE[,BYTE...]`.  Для `fake` число после
позиции задаёт TTL decoy: `fake:mid:7`.  Флаги ByeDPI вида `+s/+e` пока не
поддерживаются; для них есть внешний `ciadpi` (roadmap).

## Прокси-бэкенды

```toml
[[proxy.backends]]
name = "vps"
kind = "xray"                 # полный набор протоколов
url = "vless://UUID@host:443?security=reality&sni=...&pbk=...&sid=...&flow=xtls-rprx-vision&type=tcp"
xray_binary = "/run/current-system/sw/bin/xray"
socks_addr = "127.0.0.1:10808"
run_as_uid = 65534            # обязательно не 0, иначе возможен цикл
```

Xray запускается на `socks_addr`, airgrill общается с ним по SOCKS5. Конфиг
генерируется из `vless://`; если нужен свой — укажите `xray_config = "/path.json"`
(из него берутся `outbounds`, `inbounds` заменяются на SOCKS). Ссылку можно
хранить вне Nix store и читать из файла:

```toml
url_file = "/etc/airgrill/vless_uri"   # 0600
```

Современный Xray (26.x) **удалил** `allowInsecure`. Для самоподписанных
сертификатов используйте pinning в ссылке:

```
...&pcs=<sha256-сертификата-hex>
```

(или `verifyPeerCertByName` / `vcn`, либо свой `xray_config`).

Native:

```toml
[[proxy.backends]]
name = "native"
kind = "native"
url = "vless://UUID@host:443?security=tls&type=ws&path=%2Fws&sni=host"
insecure = false
```

Native поддерживает `tcp`, `tls`, `ws` и UDP. `security=reality`, `flow=...` и
`type=grpc` он отвергает с понятной ошибкой — это работа для Xray.

Если backend один, `default_backend` можно не указывать.

## DNS

DNS-прокси слушает `dns.listen` (по умолчанию `0.0.0.0:15353`, не требует
root). nftables перенаправляет на него `:53` хоста и LAN. Ответы A/AAAA
запоминаются с TTL и используются для маршрутизации UDP.

* Кэш хранит сырые ответы (EDNS/DNSSEC/неизвестные типы не ломаются).
* Для доменов из `block` отдаётся NXDOMAIN.
* Upstream'ы — обычные UDP/TCP DNS. DoH пока нет.
* Если клиенты ходят через DoH/DoT, классификация по IP для UDP не сработает;
  останется маршрут по умолчанию.

Для LAN `dns.listen` не должен быть loopback.

## NixOS, systemd и замена Hiddify

В `/etc/nixos` добавлены:

* `flake.nix` — input `airgrill` (`path:/home/artem/airgrill`);
* `modules/airgrill.nix` — пакет, systemd-сервис, dnsmasq-DHCP для `eno2`,
  firewall и sysctl;
* `modules/airgrill-config.toml` — конфиг без секретов; VLESS-ссылка читается
  из `/etc/airgrill/vless_uri` (0600).

Одноразовый переключатель (создан в `/tmp`, запускать под root):

```bash
sudo /tmp/airgrill-switch.sh
```

Что делает скрипт:

1. извлекает активный VLESS из Hiddify в `/etc/airgrill/vless_uri` (0600),
   подставляет IPv4 VPS и **ALPN `http/1.1`** (для этого WS-сервера `h2`
   ломает handshake);
2. собирает NixOS с airgrill и делает `nixos-rebuild switch` (пока Hiddify
   ещё работает, чтобы не потерять сеть);
3. останавливает Hiddify, убирает `tun0`/правила `9000–9010`/старый NAT;
4. запускает `airgrill` + `dnsmasq` и проверяет YouTube/Discord.

Режим `proxy-default`: **всё, что не попало в direct/dpi-правила, идёт через
VPS**, включая трафик второго ПК. `eno2` — 10.10.10.1/24, DHCP 10.10.10.100–200,
шлюз и DNS для второго ПК — 10.10.10.1. Локальные сети и `.ru` идут напрямую,
YouTube — через DPI, Telegram/Discord — через proxy.

Hiddify не имеет autostart; после переключения его не нужно запускать.

* **`nixos-fw-rpfilter` и TPROXY**: strict/loose rpfilter на этой конфигурации
  дропает TPROXY-пакеты с mark 0x1. Модуль ставит
  `networking.firewall.checkReversePath = false`; это обязательно для LAN.
* **Самозащита агента**: airgrill поднимает локальный HTTP CONNECT-прокси на
  `127.0.0.1:12334` (`[proxy_inbound]`), поэтому процессы с
  `http_proxy=http://127.0.0.1:12334` (pi, codex, старые env) не умирают
  после остановки Hiddify.
* **DNS**: слушатель на `15353`, потому что `5353` занимает mDNS
  (`systemd-resolved`/KDE Connect). Скрипт после switch перезапускает
  `systemd-resolved` — иначе host-DNS иногда залипает.
Если текущая оболочка унаследовала `http_proxy`/`https_proxy` от Hiddify:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
```

Discord-модуль больше не оборачивается в `socks5://127.0.0.1:12334`
(`discord.proxy = null`) — Discord идёт прозрачно через airgrill.

Откат:

```bash
sudo /tmp/airgrill-switch.sh --rollback
# затем вручную:
sudo -E /home/artem/Utils/hiddify/run-tun.sh
```

Скрипт можно запускать повторно. `--prepare-only` только обновляет секрет,
`--no-switch` пропускает `nixos-rebuild` (сервис уже установлен).

## Режим роутера (второй ПК)

Сейчас в этот ПК воткнут второй по `eno2` (`10.10.10.1/24`). Конфиг:

```toml
[router]
enabled = true
lan_interfaces = ["eno2"]
lan_cidrs = ["10.10.10.0/24"]
tcp_port = 16000
lan_all_tcp = true
host_tcp_ports = [80, 443]
bypass_private = true
masquerade = false

[tun]
enabled = true
name = "airgrill0"
table = 100
```

Что делает демон:

* `ip_forward=1`, `ipv6.conf.all.forwarding=1`;
* TPROXY для TCP, приходящего с `eno2` (все порты или `host_tcp_ports`);
* TUN + policy routing для UDP (`fwmark 0x10`, table 100);
* при `masquerade = true` — NAT для не перехваченного forward-трафика.

Второму ПК достаточно иметь шлюз `10.10.10.1`. DNS можно отдавать любой —
запросы на `:53` всё равно перехватываются; лучше выдать `10.10.10.1`.

### Firewall

NixOS по умолчанию дропает forward. Добавьте:

```nix
networking.firewall.extraForwardRules = ''
  iifname "eno2" accept
  oifname "eno2" ct state established,related accept
  iifname "airgrill0" accept
  oifname "airgrill0" accept
'';
```

`airgrill` создаёт свою таблицу `inet airgrill` и не трогает чужие. Если у вас
уже есть другой firewall с политикой DROP в forward, разрешите эти интерфейсы.

### Hiddify и прочий policy routing

**Важно:** если на хосте уже есть policy-routing VPN/TUN (Hiddify, sing-box,
WireGuard с отдельной таблицей), `airgrill run` по умолчанию **откажется
стартовать**. Иначе airgrill перехватит собственный исходящий 443 этого VPN и
сломает его — именно так пропадает интернет при попытке запустить два
клиента одновременно. Обойти проверку можно только явным `--force`, если вы
действительно хотите, чтобы airgrill перехватывал и трафик VPN.

Сейчас на хосте Hiddify держит `tun0` и правила `9000–9010`. airgrill ставит
свои правила с приоритетами **1000/1001**, то есть его mark'и разбираются
раньше. Но:

* полностью переключиться на airgrill = выключить auto-route/forwarding у
  Hiddify (иначе его `tun0` продолжит забирать не перехваченный трафик);
* нельзя держать одновременно два TUN-клиента, которые претендуют на весь
  трафик;
* `airgrill` не меняет ваши правила и таблицы, только добавляет свои.

Поэтому сейчас ничего не коммутируется автоматически: сначала остановите
Hiddify (или отключите его auto-route/forwarding), затем `run --dry-run` и
ручное переключение. Флаг `--force` позволяет запуститься рядом с Hiddify, но
это осознанно опасный режим.

Результаты живого теста на Ростелекоме (YouTube / Telegram / Discord) —
в `docs/real-isp-tests.md`.

## Как это устроено внутри

Mark'и (low byte):

| mark | смысл                                         |
|------|-----------------------------------------------|
| 0x40 | трафик самого airgrill — не перехватывать     |
| 0x42 | direct-соединение, которое надо десинкать     |
| 0x10 | UDP → TUN                                     |
| 0x01 | TPROXY policy routing                         |

* `SO_MARK` ставится **до** `connect()`, иначе первый SYN попадёт в
  перехват и получится цикл.
* Host TCP: `nft ... redirect to :16000` в `output`; original destination
  восстанавливается через `SO_ORIGINAL_DST`.
* LAN TCP: `tproxy to :16000` в `prerouting`; accepted socket уже привязан к
  исходному адресу, ответы уходят клиенту с правильным source.
* DPI: сокет помечен `0x42`, nft отправляет его первые пакеты в NFQUEUE,
  движок дропает оригинал и шлёт сегменты через raw socket с тем же seq.
  Инъекция помечена `0x40`, поэтому не зацикливается.
* DNS-сокеты тоже помечены `0x40`, иначе их ответы ушли бы в UDP TUN.
* Xray работает под uid `65534`, nft пропускает его по `meta skuid`.

Policy routing:

```
ip rule fwmark 0x1  lookup 101 priority 1001   # TPROXY → local
ip route local 0.0.0.0/0 dev lo table 101
ip rule fwmark 0x10 lookup 100 priority 1000   # UDP → TUN
ip route default dev airgrill0 table 100
```

## Ограничения и заметки

* UDP-фрагменты (IP fragmentation) не собираются в TUN — датаграммы больше MTU
  отбрасываются. MTU 1500 покрывает QUIC, игры и голос.
* Native VLESS не умеет Reality/Vision/gRPC — используйте Xray.
* DoH/DoT-клиенты обходят DNS-классификацию; для них работает маршрут по IP
  по умолчанию.
* `quic = "block"` ломает QUIC, браузер откатывается на TCP; для игр/голоса,
  которым нужен UDP/443, поставьте `direct` или `proxy`.
* На проверенном ISP YouTube обходится DPI (`disorder:sni` / `fake:sni` /
  `overlap:sni`), а Telegram и Discord — нет: Telegram блокируется по IP,
  Discord — по SNI, но агрессивнее, чем YouTube. Их нужно держать в `proxy`.
* Telegram-приложение ходит по MTProto **на IP без SNI**, поэтому в `proxy`
  нужны не только домены, но и CIDR (готовый список — в
  `examples/airgrill.toml` и `docs/real-isp-tests.md`).
* Игры и голос с жёстко прописанными IP не видны DNS;они идут по маршруту по
  умолчанию (для `proxy-default` — через прокси, для `lists` — напрямую).
* `airgrill` требует root; Xray — нет.
* `bypass_private=true` исключает RFC1918/loopback/link-local из перехвата.

## Тесты

```bash
cargo test
```

Юнит-тесты покрывают matcher, режимы, precedence, TTL IP-индекса, NFQUEUE
парсер, desync-стратегии, nft-скрипт, VLESS URL/заголовок, SOCKS5 UDP и
DNS-парсер.

Интеграционные сценарии (netns) описаны в `docs/integration-tests.md` — их
нужно запускать вручную под root/user namespace.

## Roadmap

* `geosite`/`geoip` или загрузка списков сообществ (сейчас только свои).
* DoH/DoT upstream.
* UDP full-cone / XUDP для native VLESS.
* Перезагрузка конфига по SIGHUP.
* Web UI / метрики.
