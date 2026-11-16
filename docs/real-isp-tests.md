# Реальный тест на живом ISP (2026-11-16)

Условия:

* Ростелеком, прямой выход `77.37.209.149` (без VPN);
* тестовый клиент — отдельный netns на macvlan-интерфейсе `eno1`
  (`192.168.1.51`), поэтому правила и трафик не затрагивали хостовую сеть;
* airgrill 0.1.0, `dpi.enabled=true`, `host_tcp_ports=[443]`, DNS/TUN/роутер
  выключены;
* SNI-проверки — `curl` с `--resolve`, без HTTP-прокси Hiddify;
* стратегии: `disorder:sni`, `fake:sni`, `overlap:sni`, `split:sni`, а также
  фиксированные позиции `split:50/100/150`, `fake:50/100`, `disorder:50`.

## Адреса

| сервис | IP | TCP:443 напрямую |
|--------|----|------------------|
| YouTube | `142.251.153.4` | открыт, но TLS с SNI `www.youtube.com` виснет |
| Discord | `162.159.136.232`, `162.159.135.232` | открыт |
| Telegram | `149.154.167.99`, `149.154.166.110`, `149.154.167.50`, `91.108.56.130` | **SYN timeout** |

## Результаты

| цель | disorder:sni | fake:sni | overlap:sni | split:sni | fixed split/fake |
|------|--------------|----------|-------------|-----------|------------------|
| `www.youtube.com/` | **200** | **200** | **200** | 000 | 000 |
| `www.youtube.com/watch?v=...` | **200** | — | — | — | — |
| `i.ytimg.com/...` | **200** | — | — | — | — |
| `discord.com/api/v9/gateway` | 000 | 000 | 000 | 000 | 000 |
| `discord.com/` | 000 | 000 | 000 | 000 | 000 |
| `gateway.discord.gg/` | 000 | — | — | — | 000 |
| `web.telegram.org/` | 000 | 000 | 000 | 000 | 000 |
| `example.com/` (direct) | 200 | 200 | 200 | 200 | 200 |

Диагностика Discord: тот же IP с SNI `example.com` отдаёт **200** за 0.1 с,
а с SNI `discord.com` — 000. То есть IP доступен, блокировка именно по
`discord.com`, но текущие desync-стратегии её не обходят: похоже, DPI
пересобирает ClientHello агрессивнее, чем для YouTube.

Диагностика Telegram: TCP-соединение на все проверенные IP:443 не
устанавливается вообще (SYN timeout). Это блокировка по IP/маршруту, а не по
SNI; GoodbyeDPI-подход здесь принципиально не поможет.

## Почему на телефоне Telegram работает

В `/tmp/gdpi-android` лежит **ByeByeDPI Android** — это не чистый GoodbyeDPI,
а форк с дополнительным sing-box/VLESS-слоем:

* `app/src/main/java/io/github/romanvht/byedpi/core/SingBox.kt`:
  * `TELEGRAM_DOMAINS` и `TELEGRAM_CIDRS` направляются в outbound `vpn`
    (VLESS), а не в byedpi;
  * в коде есть комментарий: `Telegram is blocked by IP on this ISP, so it
    cannot be desynced.`;
  * в настройках приложения есть пункт **«VLESS-конфиг (ИИ и Telegram)»**.
* `NativeSession.kt` вставляет sing-box между TUN и ciadpi: Telegram и
  «санкционные» сервисы идут через VLESS, остальное — через byedpi.

Поэтому работающий Telegram на телефоне подтверждает наш вывод: он идёт через
VLESS, а не через DPI. Чтобы так же работало в airgrill, Telegram-домены **и
CIDR** нужно положить в правило с `route = "proxy"` (см. `examples/airgrill.toml`).

Для Discord телефон использует byedpi, у которого есть стратегии, которых нет
во встроенном движке airgrill (OOB, TLS-record split, multi-split, auto).
Встроенный `disorder:sni` Discord на этом ISP не пробивает; надёжный путь —
Discord в `proxy` или отдельный внешний `ciadpi`-бэкенд.

## Вывод

* **YouTube — работает через DPI**, лучшие стратегии: `disorder:sni`,
  `fake:sni`, `overlap:sni`; `split` не работает.
* **Telegram и Discord на этом ISP нужно отправлять в proxy**, а не в `dpi`.
  Пример:

  ```toml
  [[routing.rules]]
  name = "telegram"
  route = "proxy"
  domains = [
    "domain:telegram.org", "domain:t.me",
    "cidr:91.108.0.0/16", "cidr:149.154.160.0/20",
  ]

  [[routing.rules]]
  name = "discord"
  route = "proxy"
  domains = ["domain:discord.com", "domain:discord.gg"]

  [[routing.rules]]
  name = "youtube"
  route = "dpi"
  strategy = "disorder:sni"
  domains = ["domain:youtube.com", "domain:googlevideo.com", "domain:ytimg.com"]
  ```

* При запуске на хосте, где уже работает Hiddify, airgrill перехватывал
  исходящий 443 самого Hiddify и ломал VPN. В текущей версии добавлена
  проверка: при наличии чужого policy-routing VPN/TUN `run` отказывается
  стартовать (обойти можно только явным `--force`).
