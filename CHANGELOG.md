<a id="top"></a>

# Changelog

<p align="center">
  <a href="#english"><b>English</b></a> &nbsp;|&nbsp;
  <a href="#persian"><b>فارسی</b></a> &nbsp;|&nbsp;
  <a href="#chinese"><b>简体中文</b></a>
</p>

---

<a id="english"></a>

# 🇬🇧 English

All notable changes are documented in this file, in two parts: Part 1 covers this fork, Part 2 is the changelog of the upstream project.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Part 1 — This fork: localization and install wizard

### [Unreleased] — Persian & English localization and install wizard

Base project: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 2.1
Localization maintained by: [@soroushse7o](https://github.com/soroushse7o) (original author: [@cmliu](https://github.com/cmliu))

#### Summary

This PR adds Persian (فارسی) and English localization to edgetunnel, plus a standalone
one-click install wizard, without touching any proxy, subscription, or transport logic:

1. Full English and Persian READMEs (plus the Chinese one as its own file) and a short trilingual landing `README.md` that links to them.
2. A client-side translation layer for the admin panel (Chinese → Persian / English).
3. English names for the generated CF nodes and for subscription-generator error nodes.
4. A one-click install wizard (a separate Cloudflare Worker) for users without technical knowledge.

#### Added

##### Documentation
- Three full, standalone READMEs: `README_en.md` (English), `README_fa.md` (Persian, right-to-left,
  wrapped in `<div dir="rtl">`) and `README_zh.md` (Chinese). The English and Persian files are full
  translations of the original Chinese README. Each file starts with a language switcher:
  `English | فارسی | 简体中文`.
- `README.md` is now a short trilingual landing page (English, Persian, Chinese): a summary of the
  project in each language that links to the full README of that language. The original Chinese README
  moved to `README_zh.md`.
- New **One-Click Install Wizard** section in all three full READMEs (before *Quick Deployment*): link to
  the live wizard, 5-step usage, what it configures automatically, a short privacy note and a link to the
  wizard's full documentation. The landing page carries a short version of it.

##### Admin panel localization (`_worker.js`)
- New block at lines 5–737, placed after the version header:
  - `面板本地化脚本` — a browser-side translation script with **480 dictionary
    entries** (Chinese → Persian / English).
  - `本地化页面响应()` — a small helper that injects the script with
    `HTMLRewriter` (`prepend` into `<html>`).
- The helper only touches responses whose `content-type` is `text/html`; any
  other response, or any error, falls back to the untouched original response.
- **English is the default language**; **Persian (فارسی) is the second
  language**. The original Chinese interface is available **only manually**
  via the `?lang=zh` URL parameter (no button for it).
- Language toggle button **«EN | فارسی»** fixed at the bottom-left of the page.
  The selection is stored in `localStorage` (key `edt_ui_lang`).
- `?lang=en|fa|zh` URL parameter. The value is saved to `localStorage` as well,
  so `?lang=zh` keeps the Chinese interface until another language is selected.
- Dynamic text is translated too: `alert`, `confirm` and `prompt` dialogs are
  wrapped, and a `MutationObserver` translates nodes, text and attributes added
  after page load.

##### One-click install wizard (`wizard-panel/`)
A separate single-file Cloudflare Worker that installs edgetunnel on the user's own Cloudflare
account. Live at [edge-panel-wizard.soroush.my.id](https://edge-panel-wizard.soroush.my.id); full documentation:
[wizard-panel/README.md](https://github.com/soroushse7o/edgetunnel/blob/feat/i18n-en-fa/wizard-panel/README.md).
- Four-step guided page, bilingual with RTL support (**English** by default, **Persian** as the second language).
- Installs as **Cloudflare Workers** or **Cloudflare Pages**.
- Automatic setup: verifies the API token and uses the first accessible account, downloads the
  edgetunnel script, creates a KV namespace named `<project-name>-kv` and binds it as `KV`,
  sets the `ADMIN` and `KEY` variables, and deploys.
  - `ADMIN`: 16 random characters, or the user's own (6 to 64 visible characters, no spaces).
  - `KEY`: 16 random characters, used as the quick-subscription path (`/<KEY>`).
  - `UUID` is intentionally not set, so the admin panel can still manage its own UUID.
- Workers mode enables the `workers.dev` route (creating the account's subdomain if missing);
  Pages mode creates the project with the variables and the KV binding (production and preview)
  and uploads the script as `_worker.js`.
- **Placement Hint** selector with 11 Europe-focused regions (Italy, Netherlands, Germany,
  Finland, Sweden, France, Ireland, United Kingdom). If Cloudflare rejects the hint, Workers
  retries once without it and Pages still succeeds.
- Clean rollback: if the install fails after the KV namespace was created, the namespace (and a
  half-created Pages project) is deleted again.
- Status bar (Standby, Deploying, Success, Error) with clear error messages (invalid token,
  missing permissions, network error, rate limit, and more).
- Shows the admin panel link, the admin password and the quick-subscription link.
- No dependencies, no build step and no database. The wizard stores nothing; the token is used
  only for the install requests made directly against the Cloudflare API and is never returned to the page.

#### Changed

##### Panel pages passed through the injector
Exactly four `fetch(Pages静态页面 + …)` call sites were modified:

| Page | Change |
|---|---|
| `/login` | `.then(本地化页面响应)` appended |
| `/admin` | `.then(本地化页面响应)` appended |
| `/noADMIN` | existing response handler now returns the localized response |
| `/noKV` | existing response handler now returns the localized response |

##### Node naming (`生成随机IP`)
Generated node names are now ASCII/English instead of Chinese:

| Before | After |
|---|---|
| `CF官方优选N` | `CF-Official-N` |
| `CF移动优选N` | `CF-Mobile-N` |
| `CF联通优选N` | `CF-Unicom-N` |
| `CF电信优选N` | `CF-Telecom-N` |
| `CF优选 …ms …MB/s` (API result) | `CF-Preferred …ms …MB/s` |

##### Subscription generator error messages
Three error entries that are emitted as a placeholder node
(`127.0.0.1:1234#…`) with a Chinese name are now in English:

| Before | After |
|---|---|
| `…优选订阅生成器格式化异常:…` | `… generator format error: …` |
| `…优选订阅生成器异常:<statusText>` | `… generator error: <statusText>` |
| `…优选订阅生成器异常:<message>` | `… generator error: <message>` |

> Only name/message strings were replaced. No logic was changed.

##### Housekeeping
- Removed the UTF-8 BOM at the start of line 1.

#### Not changed

- Proxy logic
- Subscription generation logic
- WebSocket / gRPC / XHTTP transports
- Configuration handling

#### Verification

- `node --check` passes on `_worker.js`.
- `node --check` passes on the injected translation script itself.

#### Known limitations

- ISP names shown in the **Network Information** cards (for example `科赋锐科技`)
  come from an external API and are therefore **not translated**.
- The on-page toggle offers English and Persian only; Chinese is available
  only manually via `?lang=zh`.

- The wizard uses the first account when the API token can access several accounts.
- The `DNS (edit)` permission is pre-selected on the token page for convenience but is not used yet.
- The wizard stores `ADMIN` and `KEY` as plain-text variables in the created Worker/Pages project,
  so they stay readable in the Cloudflare dashboard.

#### Compatibility notes

- No new environment variables, dependencies or deployment steps.
- **Default panel language is now English (`en`)** for visitors who have not
  chosen a language yet (previously Chinese). Persian is the second language.
  Chinese-speaking users can restore the original interface manually with
  `?lang=zh`; the choice is remembered in their browser.
- Node names changed (see above). Client-side rules, filters or routing that
  match the old Chinese names (for example `CF官方优选`) must be updated.

- The wizard is optional and separate from edgetunnel's runtime: existing deployments are unaffected.

#### Files changed

| File | Change |
|---|---|
| `_worker.js` | Translation layer (lines 5–737), 4 `fetch` call sites, node and error-message names, BOM removed |
| `README.md` | Short trilingual landing page that links to the full per-language READMEs |
| `README_en.md`, `README_fa.md`, `README_zh.md` | Full per-language READMEs (English and Persian are new; Chinese moved here), each with the install wizard section |
| `wizard-panel/` | New: one-click install wizard (Worker and its README) |
| `CHANGELOG.md` | Merged trilingual changelog: this fork (Part 1) and the upstream project (Part 2) |

#### Credits

- Original project: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) by cmliu
- Localization, install wizard and updates: [soroushse7o](https://github.com/soroushse7o)

---

## Part 2 — Upstream project ([cmliu/edgetunnel](https://github.com/cmliu/edgetunnel))

> Changelog of the original project by [@cmliu](https://github.com/cmliu). This English version is a translation of the Chinese original (see the Chinese section).

### [2.1.20260922200117] - 2026-09-22 20:01:17

#### Fixed

- Fixed the **aggregated subscription** (汇聚订阅): the User-Agent is now set uniformly, making request behavior more consistent.

### [2.1.20260907040834] - 2026-09-07 04:08:34

#### Added

- Added the **Expand full rule text** option to the **subscription conversion config**.

### [2.1.20260904162413] - 2026-09-04 16:24:13

#### Added

- Added support for the **ALPN** field: node links now carry the ALPN parameter automatically, fitting more client scenarios.

#### Fixed

- Fixed **HTTPS proxy**: the handshake failed when the upstream server requested a client certificate (CertificateRequest). An empty certificate is now sent back so the handshake completes normally. [Commit](https://github.com/cmliu/CF-Workers-CheckSocks5/commit/ae93bc28462a6df03795143a5caa85f717ba231a)

### [2.1.20260811144522] - 2026-08-11 14:45:22

#### Changed

- Optimized **XHTTP** upload transport: added a data coalescing mechanism. Small chunks are merged and then sent together, reducing frequent small writes and resource overhead, so large file uploads are smoother.

### [2.1.20260810030901] - 2026-08-10 03:09:01

#### Added

- Added receiver-side support for **XHTTP obfs padding**: recognizes the `xPaddingObfsMode` (tokenish / queryInHeader) obfuscation headers.

### [2.1.20260809231057] - 2026-08-09 23:10:57

#### Fixed

- Fixed parameter parsing for **XHTTP chained proxy**: a trailing `/` at the end of the path made the reverse-proxy configuration ineffective. Trailing slashes are now handled.

### [2.1.20260809201158] - 2026-08-09 20:11:58

#### Changed

- Optimized the **XHTTP** transport path: TCP data now flows through direct bidirectional pipes, `request.body.pipeTo(socket.writable)` and `socket.readable.pipeTo(IdentityTransformStream)`, and no longer goes through ReadableStream + upload write queue + BYOB/Grain chunk-by-chunk relaying, which significantly reduces CPU usage.
- Optimized **XHTTP** connection management: `forwardataTCP` gains a "connect only" mode. After connecting and writing the first packet it returns the socket directly for the pipe to take over, while keeping the fallback of automatically switching to a reverse proxy when the direct connection fails (gRPC/WS callers are unaffected).
- Optimized **XHTTP UDP** handling: the UDP branch is split into a dedicated handler function, keeping the Trojan UDP reverse-proxy and DNS forwarding logic.

### [2.1.20260729235734] - 2026-07-29 23:57:34

#### Changed

- Corrected the **PRELOAD_RACE_DIAL** environment variable logic: the default changed from `true` to `false` (preload race dialing is **off** by default), and setting `1` or `true` turns it **on**. The README description of this variable was fixed accordingly. [Commit](https://github.com/cmliu/edgetunnel/commit/aea8b85688ef6066116af551cfd5e6fd2ce77567)

### [2.1.20260724150359] - 2026-07-24 15:03:59

#### Changed

- Synced the latest **GrainTCP** transport optimizations: the upload Grain coalescing target was raised from `16KB` to `20KB`, reusing the unified collect/coalesce core. Consecutive small chunks are opportunistically merged during the drain phase, reducing high-frequency `writer.write()` calls. [Upstream commit](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- Optimized downstream **GrainTCP** aggregation: keeps the `32KB` aggregation cap, uses a `tail × 12` low watermark and up to `4` rounds of growth observation at `1ms` each. A flush can send several aggregated packets in a row and sends promptly when near the cap, reducing the number of small-packet WebSocket frames. [Upstream commit](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- Optimized downstream packet handling: large chunks are sent directly when the Grain is empty, and small chunks are detached from the reusable read buffer first on the BYOB/default reader path. Aggregated results are copied before sending, preventing data overwrite caused by scratch buffer reuse. [Upstream commit](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- Strengthened TCP connection management based on the upstream transport model: added connection generation, socket identity and an old-downstream drain barrier. During redialing, upload data keeps being collected and waits for the new writer, and the asynchronous cleanup of an old reader, timer or connection can no longer pollute the new connection. [Upstream idea](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- Based on the upstream Grain send model, unified direct send, segmented send and timed flush into one serial send chain, and persisted asynchronous send errors. The response header is consumed only on the first real send, so redialing or a dead connection cannot consume the protocol response header early. [Upstream idea](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- Kept the existing multi-protocol compatibility: WS upload uses non-waiting enqueue to reduce message-handling blocking, while XHTTP/gRPC keep waiting for the remote write to complete. A local upload high-water protection of `16MiB / 4096` entries is kept to prevent unbounded Worker queue growth. [Upstream change](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- Optimized: the local speed-test response is now enabled only in **reverse-proxy mode**. When using **SOCKS5/HTTP/HTTPS/TURN/SSTP** proxies, speed-test requests are forwarded normally.

### [2.1.20260722191426] - 2026-07-22 19:14:26

#### Changed

- Added support for the `http://cp.cloudflare.com/generate_204` real-connection test address.

### [2.1.20260711190235] - 2026-07-11 19:02:35

#### Added

- Added the **TCP_CONCURRENT_DIAL** environment variable to customize the **TCP concurrent dial count**. Once set, it no longer drops to a single path automatically on China Mobile networks.
- Added the **PROXY_CONCURRENT_DIAL** environment variable to customize the **reverse-proxy concurrent dial count**.

### [2.1.20260711022318] - 2026-07-11 02:23:18

#### Changed

- Optimized **reverse-proxy logic**: fixed multi-reverse-proxy node parameters not taking effect because a global variable was accidentally overwritten.
- Optimized the **DoH cache**: recent domain resolution results are cached to reduce duplicate requests, speed up resolution and lower resource usage. Domains with no result are also cached briefly to avoid repeated queries.

#### Added

- Added the **reverse-proxy concurrent dial count**: you can adjust the number of concurrent reverse-proxy connections. The higher the concurrency, the faster the connection but the more frequent the IP switching; the lower the concurrency, the more stable the connection process.
- Added more options to the **subscription conversion config**, including **UDP**, **XUDP**, **TLS 1.3**, **insert node type** and **base node sorting**, all passed through to the subscription conversion backend.
- Added **Trojan fallback proxy (Fallback)**: the Trojan protocol now supports a backup proxy address. When the main connection fails, it can switch automatically to the backup proxy and keep working, making connections more stable and reliable. [PR #1359](https://github.com/cmliu/edgetunnel/pull/1359)

### [2.1.20260617014121] - 2026-06-17 01:41:21

#### Added

- Added an **output node info only** option to the subscription conversion config.

### [2.1.20260611041617] - 2026-06-11 04:16:17

#### Changed

- Optimized the UUID validation logic of the **version info endpoint**, improving validation security.

### [2.1.20260609132903] - 2026-06-09 13:29:03

#### Fixed

- Fixed the **Error 1101** signature.

#### Changed

- Optimized the **PROXYIP resolution cache**: reverse-proxy addresses are lowercased before the cache comparison, so the same address with different letter case is no longer resolved twice.

### [2.1.20260601154939] - 2026-06-01 15:49:39

#### Changed

- Adapted to **Xray-core v26.2.6**: TLS has removed the `allowInsecure` option, so Base64 subscriptions no longer output the **skip certificate verification** setting. Clash and Sing-box subscriptions are unaffected. [Release](https://github.com/XTLS/Xray-core/releases/tag/v26.2.6)

### [2.1.20260529014818] - 2026-05-29 01:48:18

#### Changed

- Optimized **China Mobile** direct access: TCP concurrent dialing is downgraded to a single path to mitigate CPU timeouts.

### [2.1.20260526210857] - 2026-05-26 21:08:57

#### Fixed

- Fixed **TURN authentication**: an empty `REALM` in the STUN auth challenge is now allowed, so an empty realm is no longer misjudged as missing and no longer causes connection failure.

### [2.1.20260518183745] - 2026-05-18 18:37:45

#### Added

- Added the **PRELOAD_RACE_DIAL** environment variable to customize **TCP preload race dialing**: on the first direct connection to a domain, A/AAAA records can first be queried concurrently via DoH, preferring IPv4 and filling up with IPv6 to the `TCP concurrent dial count` limit when there are not enough. The reverse-proxy failure fallback logic is separated from the ordinary first direct connection to avoid triggering the preload by mistake.

### [2.1.20260517185203] - 2026-05-17 18:52:03

#### Fixed

- Fixed **WS/XHTTP/gRPC upload**: upload writes now wait for the remote write to complete before processing the next chunk, avoiding a fast pile-up inside the Worker during upload bursts and the resulting `upload queue overflow`.
- Optimized the **WS explicit transfer queue**: the upload queue protection was adjusted from 256KB to 16MB / 4096 entries, and waiting write tasks are now released correctly when the queue is cleaned up, reducing occasional overflow during large file uploads.

### [2.1.20260515185129] - 2026-05-15 18:51:29

#### Changed

- Optimized the **Shadowsocks subscription**: when TLS is turned off, preferred ports are automatically rewritten to noTLS ports. (This does not apply to reverse-proxy IPs.)
- Optimized the **GO2SOCKS5** variable: changed from override mode to append mode. [PR #1202](https://github.com/cmliu/edgetunnel/pull/1202)

### [2.1.20260513042803] - 2026-05-13 04:28:03

#### Changed

- Optimized the **VLESS** hot path: the UUID is pre-decoded to 16 bytes for direct comparison, and first-packet parsing uses offsets and `subarray()` to copy less. [Open-source reference](https://github.com/ToiCF/GrainTCP)
- Optimized **WS Early Data**: added an 8KB cap, and avoided injecting ordinary WebSocket subprotocols into the first packet as if they were early data. [Open-source reference](https://github.com/ToiCF/GrainTCP)
- Optimized the **WS/XHTTP/gRPC** upload path: added a bounded queue, small-packet coalescing and 256KB backpressure protection, reducing high-frequency small writes and preventing unbounded queue growth. [Open-source reference](https://github.com/ToiCF/GrainTCP)
- Optimized the downstream **GrainTCP** send flow: small packets are aggregated with a microtask and a short quiet window, and large packets on the BYOB path flush the aggregator first and are then sent directly, reducing copies and WebSocket frames. [Open-source reference](https://github.com/ToiCF/GrainTCP)
- Optimized TCP connection setup: direct and proxyip reverse-proxy candidates use 4-way concurrent dialing to grab the first successful connection, while SOCKS/HTTP/HTTPS/TURN/SSTP proxy chains keep their original handshake logic. [Open-source reference](https://github.com/ToiCF/GrainTCP)
- Optimized the WebSocket handshake and WS main-path transport: added an exception fallback for `allowHalfOpen`, the 101 response clears `Sec-WebSocket-Extensions`, and the WS main path now uses an explicit sequential queue. [Open-source reference](https://github.com/ToiCF/GrainTCP)

### [2.1.20260511041705] - 2026-05-11 04:17:05

#### Changed

- Optimized the password validation logic of the **login settings page**, so that beginners who set the `ADMIN` password with a stray line break no longer find that the password never matches and lose their patience!

#### Removed

- Removed the request-count refresh countdown from the subscription response headers, so beginners don't lose their patience when they see it!

### [2.1.20260508190728] - 2026-05-08 19:07:28

#### Fixed

- Fixed an issue with **random preferred selection**: the carrier information was lost after subscription conversion, so the preferred IPs for the matching carrier could not be generated.

#### Changed

- Optimized subscription conversion: a temporary `TOKEN` is now submitted for conversion, to avoid leaking the real subscription URL.

### [2.1.20260508041513] - 2026-05-08 04:15:13

#### Changed

- Optimized the **PROXYIP** domain resolution flow: a domain first reads the reverse-proxy address from its **TXT** record, and the **A** record result is used only if no TXT result is found.
- When neither TXT nor A records return a result, the **AAAA** record is requested, reducing unnecessary IPv6 queries.

#### Removed

- Removed the `.william` domain special case and the Google DoH backup retry logic. Ordinary domains can now also configure reverse-proxy addresses through TXT records.

### [2.1.20260506175102] - 2026-05-06 17:51:02

#### Added

- Added **TURN protocol** proxy support in reverse-proxy mode. [Open-source reference](https://github.com/ToiCF/CF-Workers-TURN)
- Added **SSTP (SoftEther) protocol** proxy support in reverse-proxy mode. [Open-source reference](https://github.com/ToiCF/CF-Workers-SoftEther)
- Added the ability to add **chained proxy** nodes in custom subscriptions.

### [2.1.20260503011925] - 2026-05-03 01:19:25

#### Changed

- Adapted to **Sing-box**'s custom ECH **EchConfig resolution domain** feature.
- **Custom subscriptions** now support wildcard preferred domains.

#### Removed

- Removed the backup DoH for the ECH **EchConfig DNS service** in **Clash**.

### [2.1.20260417015756] - 2026-04-17 01:57:56

#### Fixed

- Synced upstream project updates, fixing known **HTTPS proxy** issues. [Reference](https://t.me/Enkelte_notif/824)
- Fixed known issues [#1117](https://github.com/cmliu/edgetunnel/issues/1117) [#1119](https://github.com/cmliu/edgetunnel/issues/1119) [#1120](https://github.com/cmliu/edgetunnel/issues/1120)

### [2.1.20260416044724] - 2026-04-16 04:47:24

#### Added

- The Trojan protocol now supports DNS queries over UDP-over-TCP.
- Added **HTTPS proxy** support in reverse-proxy mode. [Open-source reference](https://github.com/ToiCF/CF-Workers-HTTPS)

### [2.1.20260413174651] - 2026-04-13 17:46:51

#### Changed

- Optimized the WebSocket data transfer logic, supporting BYOB mode for better performance and flexibility.

### [2.1.20260410060317] - 2026-04-10 06:03:17

#### Added

- Added **AEAD encrypted transport** for the Shadowsocks protocol, providing content encryption for non-TLS transport modes.

### [2.1.0]

#### Added

- The VLESS/Trojan protocols now support the XHTTP and gRPC transports.

### [2.0.0]

#### Added

- The project architecture has been completely rewritten, with a new front-end web page. [Front-end source](https://github.com/EDT-Pages/EDT-Pages.github.io)

<p align="right"><a href="#top">⬆ Back to top</a></p>

---

<a id="persian"></a>

<div dir="rtl">

# 🇮🇷 فارسی

تمام تغییرات قابل‌توجه در همین فایل و در دو بخش ثبت شده است: بخش ۱ مربوط به این فورک و بخش ۲ چینج‌لاگ پروژه‌ی اصلی است.
قالب فایل از [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) پیروی می‌کند.

## بخش ۱ — این فورک: بومی‌سازی و ویزارد نصب

### [Unreleased] — بومی‌سازی فارسی و انگلیسی و ویزارد نصب

پروژه‌ی پایه: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) نسخه‌ی 2.1
بومی‌سازی توسط: [@soroushse7o](https://github.com/soroushse7o) (نویسنده‌ی اصلی: [@cmliu](https://github.com/cmliu))

#### خلاصه

این PR بومی‌سازی فارسی و انگلیسی و همچنین یک ویزارد نصب یک‌کلیکیِ مستقل را به edgetunnel اضافه می‌کند، بدون این‌که به منطق پروکسی، اشتراک یا انتقال دست بزند:

1. README کامل انگلیسی و فارسی (به‌علاوه‌ی README چینی در فایل جدا) و یک `README.md` اصلیِ خلاصه‌ی سه‌زبانه که به آن‌ها لینک می‌دهد.
2. یک لایه‌ی ترجمه در سمت کلاینت برای پنل مدیریت (چینی ← فارسی / انگلیسی).
3. نام انگلیسی برای نودهای CF تولیدشده و برای نودهای خطای مولد اشتراک.
4. یک ویزارد نصب یک‌کلیکی (یک Worker جداگانه) برای کاربرانی که دانش فنی ندارند.

#### افزوده‌شده

##### مستندات
- سه README کامل و مستقل: `README_en.md` (انگلیسی)، `README_fa.md` (فارسی، راست‌به‌چپ، داخل `<div dir="rtl">`) و `README_zh.md` (چینی). فایل‌های انگلیسی و فارسی ترجمه‌ی کامل README چینیِ اصلی هستند. بالای هر فایل یک خط تعویض زبان هست: `English | فارسی | 简体中文`.
- `README.md` اکنون یک صفحه‌ی خلاصه‌ی سه‌زبانه است (انگلیسی، فارسی، چینی): معرفی پروژه به هر زبان، با لینک به README کامل همان زبان. README چینیِ اصلی به `README_zh.md` منتقل شد.
- بخش جدید **ویزارد نصب یک‌کلیکی** در هر سه README کامل (قبل از «استقرار سریع») با لینک ویزارد آنلاین، ۵ مرحله‌ی استفاده، کارهایی که خودکار انجام می‌شود، نکته‌ی حریم خصوصی و لینک مستندات کامل ویزارد؛ صفحه‌ی خلاصه نسخه‌ی کوتاهی از آن دارد.

##### بومی‌سازی پنل مدیریت (`_worker.js`)
- بلوک جدید در خطوط 5 تا 737، بعد از هدر نسخه:
  - `面板本地化脚本` — اسکریپت ترجمه‌ی سمت مرورگر با **480 مدخل واژه‌نامه**
    (چینی ← فارسی / انگلیسی).
  - `本地化页面响应()` — یک تابع کمکی کوچک که اسکریپت را با
    `HTMLRewriter` تزریق می‌کند (`prepend` داخل `<html>`).
- این تابع فقط به پاسخ‌هایی دست می‌زند که `content-type` آن‌ها `text/html` است؛ هر پاسخ دیگر،
  یا هر خطا، به پاسخ اصلیِ دست‌نخورده برمی‌گردد.
- **زبان پیش‌فرض انگلیسی است** و **فارسی زبان دوم** است. رابط چینی اصلی
  **فقط به‌صورت دستی** با پارامتر آدرس `?lang=zh` در دسترس است (دکمه‌ای برای آن وجود ندارد).
- دکمه‌ی تعویض زبان **«EN | فارسی»** پایین‌چپ صفحه ثابت است.
  انتخاب در `localStorage` ذخیره می‌شود (کلید `edt_ui_lang`).
- پارامتر آدرس `?lang=en|fa|zh`. مقدار آن هم در `localStorage` ذخیره می‌شود،
  بنابراین `?lang=zh` رابط چینی را نگه می‌دارد تا زبان دیگری انتخاب شود.
- متن‌های پویا هم ترجمه می‌شوند: پنجره‌های `alert`، `confirm` و `prompt` بسته‌بندی شده‌اند و
  یک `MutationObserver` گره‌ها، متن‌ها و ویژگی‌هایی را که بعد از بارگذاری صفحه اضافه می‌شوند ترجمه می‌کند.

##### ویزارد نصب یک‌کلیکی (`wizard-panel/`)
یک Worker تک‌فایل و جداگانه برای کلادفلر که edgetunnel را روی حساب کلادفلر خودِ کاربر نصب می‌کند. نسخه‌ی آنلاین: [edge-panel-wizard.soroush.my.id](https://edge-panel-wizard.soroush.my.id)؛ مستندات کامل: [wizard-panel/README.md](https://github.com/soroushse7o/edgetunnel/blob/feat/i18n-en-fa/wizard-panel/README.md).
- صفحه‌ی راهنمای چهار مرحله‌ای، دوزبانه با پشتیبانی از راست‌به‌چپ (**انگلیسی** پیش‌فرض و **فارسی** زبان دوم).
- نصب به‌صورت **Cloudflare Workers** یا **Cloudflare Pages**.
- راه‌اندازی خودکار: توکن API را بررسی می‌کند و اولین حساب در دسترس را برمی‌دارد، اسکریپت edgetunnel را دانلود می‌کند، یک KV namespace با نام `<project-name>-kv` می‌سازد و با نام `KV` بایند می‌کند، متغیرهای `ADMIN` و `KEY` را تنظیم می‌کند و دپلوی می‌کند.
  - `ADMIN`: ۱۶ کاراکتر تصادفی، یا رمز دلخواه کاربر (۶ تا ۶۴ کاراکتر قابل‌نمایش بدون فاصله).
  - `KEY`: ۱۶ کاراکتر تصادفی که مسیر اشتراک سریع (`/<KEY>`) است.
  - `UUID` عمداً تنظیم نمی‌شود تا پنل مدیریت همچنان بتواند UUID خودش را مدیریت کند.
- حالت Workers مسیر `workers.dev` را فعال می‌کند (و اگر subdomain حساب وجود نداشته باشد، آن را می‌سازد)؛ حالت Pages پروژه را همراه با متغیرها و بایند KV (production و preview) می‌سازد و اسکریپت را به‌عنوان `_worker.js` آپلود می‌کند.
- انتخاب‌گر **Placement Hint** با ۱۱ ریجن عمدتاً اروپایی (ایتالیا، هلند، آلمان، فنلاند، سوئد، فرانسه، ایرلند، بریتانیا). اگر کلادفلر Hint را رد کند، Workers یک بار بدون آن تلاش می‌کند و Pages همچنان موفق می‌شود.
- بازگشت تمیز: اگر نصب بعد از ساخت KV شکست بخورد، namespace (و پروژه‌ی نیمه‌کاره‌ی Pages) دوباره حذف می‌شود.
- نوار وضعیت (آماده‌باش، در حال نصب، موفق، خطا) با پیام‌های خطای روشن (توکن نامعتبر، دسترسی ناکافی، خطای شبکه، محدودیت نرخ و غیره).
- لینک پنل مدیریت، رمز مدیریت و لینک اشتراک سریع را نشان می‌دهد.
- بدون وابستگی، بدون مرحله‌ی build و بدون دیتابیس. ویزارد چیزی ذخیره نمی‌کند؛ توکن فقط برای درخواست‌های نصب و مستقیماً با API کلادفلر استفاده می‌شود و هرگز به صفحه برنمی‌گردد.

#### تغییرکرده

##### صفحه‌های پنل که از تزریق‌کننده عبور می‌کنند
دقیقاً چهار محل فراخوانی `fetch(Pages静态页面 + …)` تغییر کرد:

| صفحه | تغییر |
|---|---|
| `/login` | `.then(本地化页面响应)` اضافه شد |
| `/admin` | `.then(本地化页面响应)` اضافه شد |
| `/noADMIN` | مدیریت‌کننده‌ی پاسخ موجود اکنون پاسخ بومی‌سازی‌شده را برمی‌گرداند |
| `/noKV` | مدیریت‌کننده‌ی پاسخ موجود اکنون پاسخ بومی‌سازی‌شده را برمی‌گرداند |

##### نام‌گذاری نودها (`生成随机IP`)
نام نودهای تولیدشده اکنون به‌جای چینی، ASCII/انگلیسی است:

| قبل | بعد |
|---|---|
| `CF官方优选N` | `CF-Official-N` |
| `CF移动优选N` | `CF-Mobile-N` |
| `CF联通优选N` | `CF-Unicom-N` |
| `CF电信优选N` | `CF-Telecom-N` |
| `CF优选 …ms …MB/s` (نتیجه‌ی API) | `CF-Preferred …ms …MB/s` |

##### پیام‌های خطای مولد اشتراک
سه پیام خطا که به‌صورت یک نود جایگزین (`127.0.0.1:1234#…`) با نام چینی ارسال می‌شدند، اکنون انگلیسی هستند:

| قبل | بعد |
|---|---|
| `…优选订阅生成器格式化异常:…` | `… generator format error: …` |
| `…优选订阅生成器异常:<statusText>` | `… generator error: <statusText>` |
| `…优选订阅生成器异常:<message>` | `… generator error: <message>` |

> فقط رشته‌های نام/پیام جایگزین شدند. هیچ منطقی تغییر نکرد.

##### نظافت کد
- حذف UTF-8 BOM از ابتدای خط 1.

#### بدون تغییر

- منطق پروکسی
- منطق تولید اشتراک
- انتقال‌های WebSocket / gRPC / XHTTP
- مدیریت پیکربندی

#### راستی‌آزمایی

- `node --check` روی `_worker.js` بدون خطا اجرا می‌شود.
- `node --check` روی خودِ اسکریپت ترجمه‌ی تزریق‌شده هم بدون خطا اجرا می‌شود.

#### محدودیت‌های شناخته‌شده

- نام اپراتورها (ISP) در کارت‌های **Network Information** (مثلاً `科赋锐科技`)
  از یک API خارجی می‌آیند و بنابراین **ترجمه نمی‌شوند**.
- دکمه‌ی روی صفحه فقط انگلیسی و فارسی را ارائه می‌دهد؛ چینی فقط
  به‌صورت دستی با `?lang=zh` در دسترس است.

- اگر توکن API به چند حساب دسترسی داشته باشد، ویزارد اولین حساب را استفاده می‌کند.
- دسترسی `DNS (edit)` برای راحتی در صفحه‌ی ساخت توکن از قبل انتخاب شده، ولی فعلاً استفاده نمی‌شود.
- ویزارد `ADMIN` و `KEY` را به‌صورت متغیر متن ساده در Worker/Pages ساخته‌شده ذخیره می‌کند، بنابراین در داشبورد کلادفلر قابل‌مشاهده می‌مانند.

#### نکات سازگاری

- بدون متغیر محیطی، وابستگی یا مرحله‌ی استقرار جدید.
- **زبان پیش‌فرض پنل اکنون انگلیسی (`en`) است** برای بازدیدکنندگانی که هنوز
  زبانی انتخاب نکرده‌اند (قبلاً چینی بود). فارسی زبان دوم است.
  کاربران چینی‌زبان می‌توانند رابط اصلی را به‌صورت دستی با
  `?lang=zh` بازگردانند؛ انتخاب آن‌ها در مرورگرشان به یاد سپرده می‌شود.
- نام نودها تغییر کرده است (بالا را ببینید). قواعد، فیلترها یا مسیریابی سمت کلاینت
  که با نام‌های چینی قبلی (مثلاً `CF官方优选`) تطبیق می‌دهند باید به‌روز شوند.

- ویزارد اختیاری است و از زمان اجرای edgetunnel جداست: استقرارهای موجود تحت تأثیر قرار نمی‌گیرند.

#### فایل‌های تغییریافته

| فایل | تغییر |
|---|---|
| `_worker.js` | لایه‌ی ترجمه (خطوط 5 تا 737)، ۴ محل فراخوانی `fetch`، نام نودها و پیام‌های خطا، حذف BOM |
| `README.md` | صفحه‌ی خلاصه‌ی سه‌زبانه که به README کامل هر زبان لینک می‌دهد |
| `README_en.md`، `README_fa.md`، `README_zh.md` | README کامل هر زبان (انگلیسی و فارسی جدید؛ چینی به اینجا منتقل شد)، هرکدام با بخش ویزارد نصب |
| `wizard-panel/` | جدید: ویزارد نصب یک‌کلیکی (Worker و README آن) |
| `CHANGELOG.md` | چینج‌لاگ سه‌زبانه‌ی ادغام‌شده: این فورک (بخش ۱) و پروژه‌ی اصلی (بخش ۲) |

#### تشکر

- پروژه‌ی اصلی: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) از cmliu
- بومی‌سازی، ویزارد نصب و به‌روزرسانی‌ها: [soroushse7o](https://github.com/soroushse7o)

---

## بخش ۲ — پروژه‌ی اصلی ([cmliu/edgetunnel](https://github.com/cmliu/edgetunnel))

> چینج‌لاگ پروژه‌ی اصلی از [@cmliu](https://github.com/cmliu). این نسخه‌ی فارسی ترجمه‌ی متن چینی اصلی است (بخش چینی را ببینید).

### [2.1.20260922200117] - 2026-09-22 20:01:17

#### رفع‌شده

- رفع مشکل **اشتراک تجمیعی (汇聚订阅)**: User-Agent اکنون به‌صورت یکپارچه تنظیم می‌شود تا رفتار درخواست‌ها هماهنگ‌تر باشد.

### [2.1.20260907040834] - 2026-09-07 04:08:34

#### افزوده‌شده

- افزودن گزینه‌ی **نمایش کامل متن قوانین** به **پیکربندی تبدیل اشتراک**.

### [2.1.20260904162413] - 2026-09-04 16:24:13

#### افزوده‌شده

- پشتیبانی از فیلد **ALPN**: لینک نودها اکنون به‌طور خودکار پارامتر ALPN را همراه دارند و با کلاینت‌های بیشتری سازگار است.

#### رفع‌شده

- رفع مشکل **پروکسی HTTPS**: وقتی سرور بالادستی گواهی کلاینت را درخواست می‌کرد (CertificateRequest)، handshake شکست می‌خورد. اکنون یک گواهی خالی برگردانده می‌شود و handshake به‌طور عادی کامل می‌شود. [کامیت](https://github.com/cmliu/CF-Workers-CheckSocks5/commit/ae93bc28462a6df03795143a5caa85f717ba231a)

### [2.1.20260811144522] - 2026-08-11 14:45:22

#### تغییرکرده

- بهینه‌سازی انتقال آپلود **XHTTP**: سازوکار ادغام داده اضافه شد. قطعه‌های کوچک ابتدا ادغام و سپس یک‌جا ارسال می‌شوند؛ این کار نوشتن‌های مکرر بسته‌های کوچک و سربار منابع را کم می‌کند و آپلود فایل‌های بزرگ روان‌تر می‌شود.

### [2.1.20260810030901] - 2026-08-10 03:09:01

#### افزوده‌شده

- پشتیبانی سمت گیرنده از **XHTTP obfs padding**: هدرهای مبهم‌سازی `xPaddingObfsMode` (حالت‌های tokenish / queryInHeader) شناسایی می‌شوند.

### [2.1.20260809231057] - 2026-08-09 23:10:57

#### رفع‌شده

- رفع مشکل تجزیه‌ی پارامتر **پروکسی زنجیره‌ای XHTTP**: وجود `/` اضافه در انتهای مسیر باعث از کار افتادن پیکربندی پروکسی معکوس می‌شد. اکنون اسلش انتهایی هم پشتیبانی می‌شود.

### [2.1.20260809201158] - 2026-08-09 20:11:58

#### تغییرکرده

- بهینه‌سازی مسیر انتقال **XHTTP**: داده‌های TCP اکنون با اتصال مستقیم دوطرفه‌ی `request.body.pipeTo(socket.writable)` و `socket.readable.pipeTo(IdentityTransformStream)` منتقل می‌شوند و دیگر از مسیر ReadableStream + صف نوشتن آپلود + انتقال تکه‌به‌تکه‌ی BYOB/Grain عبور نمی‌کنند؛ نتیجه کاهش چشمگیر مصرف CPU است.
- بهینه‌سازی مدیریت اتصال **XHTTP**: تابع `forwardataTCP` یک حالت «فقط برقراری اتصال» گرفته است. پس از اتصال و نوشتن بسته‌ی اول، socket مستقیماً برگردانده می‌شود تا pipe آن را به دست بگیرد، و سازوکار پشتیبان تعویض خودکار به پروکسی معکوس در صورت شکست اتصال مستقیم حفظ شده است (فراخوان‌های gRPC/WS تأثیری نمی‌بینند).
- بهینه‌سازی پردازش **XHTTP UDP**: شاخه‌ی UDP به یک تابع پردازشی اختصاصی منتقل شد و منطق پروکسی معکوس UDP در Trojan و هدایت DNS حفظ شده است.

### [2.1.20260729235734] - 2026-07-29 23:57:34

#### تغییرکرده

- اصلاح منطق متغیر محیطی **PRELOAD_RACE_DIAL**: مقدار پیش‌فرض از `true` به `false` تغییر کرد (شماره‌گیری رقابتیِ پیش‌بارگذاری‌شده به‌طور پیش‌فرض **خاموش** است) و با مقدار `1` یا `true` **روشن** می‌شود. توضیح این متغیر در README هم متناسب با آن اصلاح شد. [کامیت](https://github.com/cmliu/edgetunnel/commit/aea8b85688ef6066116af551cfd5e6fd2ce77567)

### [2.1.20260724150359] - 2026-07-24 15:03:59

#### تغییرکرده

- همگام‌سازی با آخرین بهینه‌سازی‌های انتقال **GrainTCP**: هدف ادغام Grain در مسیر آپلود از `16KB` به `20KB` افزایش یافت و هسته‌ی یکپارچه‌ی جمع‌آوری/ادغام دوباره استفاده می‌شود. قطعه‌های کوچک پیاپی در مرحله‌ی drain در صورت امکان ادغام می‌شوند و تعداد فراخوانی‌های پرتکرار `writer.write()` کم می‌شود. [کامیت بالادستی](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- بهینه‌سازی تجمیع **GrainTCP** در مسیر دانلود: سقف تجمیع `32KB` حفظ شده، از آستانه‌ی پایین `tail × 12` و حداکثر `4` دور بررسی رشد (هر دور `1ms`) استفاده می‌شود. flush می‌تواند چند بسته‌ی تجمیع‌شده را پشت‌سرهم بفرستد و نزدیک سقف فوراً ارسال می‌کند؛ نتیجه کاهش تعداد فریم‌های WebSocket برای بسته‌های کوچک است. [کامیت بالادستی](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- بهینه‌سازی پردازش بسته‌های دانلود: وقتی Grain خالی است، قطعه‌های بزرگ مستقیماً ارسال می‌شوند، و قطعه‌های کوچک در مسیر BYOB/default reader ابتدا از بافر خواندنِ قابل‌استفاده‌ی مجدد جدا می‌شوند. نتیجه‌ی تجمیع پیش از ارسال کپی می‌شود تا استفاده‌ی مجدد از scratch buffer باعث بازنویسی داده نشود. [کامیت بالادستی](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- تقویت مدیریت اتصال TCP بر پایه‌ی مدل انتقال بالادستی: connection generation، socket identity و یک مانع drain برای دانلود قدیمی اضافه شد. هنگام شماره‌گیری مجدد، داده‌های آپلود همچنان جمع می‌شوند و منتظر writer جدید می‌مانند، و پایان‌دادن ناهمگامِ reader، تایمر یا اتصال قدیمی دیگر اتصال جدید را خراب نمی‌کند. [ایده‌ی بالادستی](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- بر پایه‌ی مدل ارسال Grain بالادستی، ارسال مستقیم، ارسال قطعه‌قطعه و flush زمان‌بندی‌شده در یک زنجیره‌ی ارسال ترتیبی یکپارچه شدند و خطاهای ناهمگام ارسال ماندگار می‌شوند. هدر پاسخ فقط در اولین ارسال واقعی مصرف می‌شود، بنابراین شماره‌گیری مجدد یا اتصال از کار افتاده نمی‌تواند هدر پاسخ پروتکل را زودتر مصرف کند. [ایده‌ی بالادستی](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- سازگاری چندپروتکلی فعلی حفظ شد: آپلود WS با صف‌گذاری بدون انتظار انجام می‌شود تا انسداد پردازش پیام کم شود، در حالی که XHTTP/gRPC همچنان منتظر پایان نوشتن در مقصد می‌مانند. محافظ محلی سقف آپلود به اندازه‌ی `16MiB / 4096` مورد نگه داشته شده تا صف Worker بی‌نهایت رشد نکند. [تغییر بالادستی](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- بهینه‌سازی: پاسخ محلی تست سرعت فقط در **حالت پروکسی معکوس** فعال می‌شود. هنگام استفاده از پروکسی‌های **SOCKS5/HTTP/HTTPS/TURN/SSTP**، درخواست‌های تست سرعت به‌طور عادی هدایت می‌شوند.

### [2.1.20260722191426] - 2026-07-22 19:14:26

#### تغییرکرده

- پشتیبانی از آدرس تست اتصال واقعی `http://cp.cloudflare.com/generate_204` اضافه شد.

### [2.1.20260711190235] - 2026-07-11 19:02:35

#### افزوده‌شده

- افزودن متغیر محیطی **TCP_CONCURRENT_DIAL** برای تنظیم **تعداد اتصال هم‌زمان TCP**. با تنظیم آن، دیگر روی شبکه‌ی China Mobile به‌طور خودکار به یک مسیر کاهش نمی‌یابد.
- افزودن متغیر محیطی **PROXY_CONCURRENT_DIAL** برای تنظیم **تعداد اتصال هم‌زمان پروکسی معکوس**.

### [2.1.20260711022318] - 2026-07-11 02:23:18

#### تغییرکرده

- بهینه‌سازی **منطق پروکسی معکوس**: رفع مشکلی که در آن پارامترهای نودهای چندپروکسی معکوس به‌دلیل بازنویسی ناخواسته‌ی یک متغیر سراسری اثر نمی‌کردند.
- بهینه‌سازی **کش DoH**: نتایج اخیر تحلیل دامنه کش می‌شوند تا درخواست‌های تکراری کم شود، سرعت تحلیل بالا برود و مصرف منابع کاهش یابد. دامنه‌هایی که نتیجه‌ای ندارند نیز موقتاً کش می‌شوند تا پرس‌وجوی مکرر انجام نشود.

#### افزوده‌شده

- افزودن **تعداد اتصال هم‌زمان پروکسی معکوس**: می‌توانید تعداد اتصال‌های هم‌زمان پروکسی معکوس را تنظیم کنید. هرچه هم‌زمانی بیشتر باشد اتصال سریع‌تر برقرار می‌شود اما تعویض IP هم بیشتر رخ می‌دهد؛ هرچه کمتر باشد روند اتصال پایدارتر است.
- افزودن گزینه‌های بیشتر به **پیکربندی تبدیل اشتراک**، از جمله **UDP**، **XUDP**، **TLS 1.3**، **درج نوع نود** و **مرتب‌سازی پایه‌ی نودها**، که همگی به بک‌اند تبدیل اشتراک منتقل می‌شوند.
- افزودن **پروکسی پشتیبان Trojan (Fallback)**: پروتکل Trojan اکنون از تعیین آدرس پروکسی پشتیبان پشتیبانی می‌کند. وقتی اتصال اصلی برقرار نشود، می‌تواند خودکار به پروکسی پشتیبان سوئیچ کند و کار را ادامه دهد تا اتصال پایدارتر و مطمئن‌تر باشد. [PR #1359](https://github.com/cmliu/edgetunnel/pull/1359)

### [2.1.20260617014121] - 2026-06-17 01:41:21

#### افزوده‌شده

- افزودن گزینه‌ی **فقط خروجی اطلاعات نود** به پیکربندی تبدیل اشتراک.

### [2.1.20260611041617] - 2026-06-11 04:16:17

#### تغییرکرده

- بهینه‌سازی منطق اعتبارسنجی UUID در **رابط اطلاعات نسخه** و افزایش امنیت اعتبارسنجی.

### [2.1.20260609132903] - 2026-06-09 13:29:03

#### رفع‌شده

- اصلاح امضای (کد شناسایی) **خطای 1101**.

#### تغییرکرده

- بهینه‌سازی **کش تحلیل PROXYIP**: آدرس‌های پروکسی معکوس پیش از مقایسه با کش به حروف کوچک تبدیل می‌شوند تا یک آدرس یکسان با اختلاف حروف بزرگ و کوچک دو بار تحلیل نشود.

### [2.1.20260601154939] - 2026-06-01 15:49:39

#### تغییرکرده

- سازگارسازی با **Xray-core v26.2.6**: گزینه‌ی `allowInsecure` از TLS حذف شده است، بنابراین اشتراک Base64 دیگر تنظیم **نادیده‌گرفتن اعتبارسنجی گواهی** را خروجی نمی‌دهد. اشتراک‌های Clash و Sing-box تحت تأثیر نیستند. [Release](https://github.com/XTLS/Xray-core/releases/tag/v26.2.6)

### [2.1.20260529014818] - 2026-05-29 01:48:18

#### تغییرکرده

- بهینه‌سازی دسترسی مستقیم روی **China Mobile**: اتصال هم‌زمان TCP به یک مسیر کاهش می‌یابد تا مشکل تایم‌اوت CPU کم شود.

### [2.1.20260526210857] - 2026-05-26 21:08:57

#### رفع‌شده

- رفع مشکل **احراز هویت TURN**: وجود `REALM` خالی در challenge احراز هویت STUN اکنون مجاز است، تا realm خالی به اشتباه «ناموجود» تشخیص داده نشود و اتصال شکست نخورد.

### [2.1.20260518183745] - 2026-05-18 18:37:45

#### افزوده‌شده

- افزودن متغیر محیطی **PRELOAD_RACE_DIAL** برای تنظیم **شماره‌گیری رقابتیِ پیش‌بارگذاریِ TCP**: در اولین اتصال مستقیم به یک دامنه، می‌توان ابتدا رکوردهای A/AAAA را هم‌زمان از طریق DoH پرس‌وجو کرد؛ IPv4 اولویت دارد و در صورت کمبود، با IPv6 تا سقف `تعداد اتصال هم‌زمان TCP` تکمیل می‌شود. منطق پشتیبان شکست پروکسی معکوس از اولین اتصال مستقیم معمولی جدا شده تا پیش‌بارگذاری به اشتباه فعال نشود.

### [2.1.20260517185203] - 2026-05-17 18:52:03

#### رفع‌شده

- رفع مشکل **آپلود WS/XHTTP/gRPC**: نوشتن در مسیر آپلود اکنون پیش از پردازش قطعه‌ی بعدی منتظر پایان نوشتن در مقصد می‌ماند، تا هنگام انفجار آپلود داده به‌سرعت داخل Worker انباشته نشود و خطای `upload queue overflow` رخ ندهد.
- بهینه‌سازی **صف انتقال صریح WS**: محافظ صف آپلود از 256KB به 16MB / 4096 مورد تغییر کرد و هنگام پاک‌سازی صف، وظایف نوشتنِ در حال انتظار به‌درستی آزاد می‌شوند؛ این کار سرریز گاه‌به‌گاه هنگام آپلود فایل‌های بزرگ را کم می‌کند.

### [2.1.20260515185129] - 2026-05-15 18:51:29

#### تغییرکرده

- بهینه‌سازی **اشتراک Shadowsocks**: هنگام خاموش‌بودن TLS، پورت‌های برگزیده به‌طور خودکار به پورت‌های noTLS بازنویسی می‌شوند. (این قابلیت برای IP پروکسی معکوس کاربرد ندارد.)
- بهینه‌سازی متغیر **GO2SOCKS5**: حالت آن از «جایگزینی» به «افزودن» تغییر کرد. [PR #1202](https://github.com/cmliu/edgetunnel/pull/1202)

### [2.1.20260513042803] - 2026-05-13 04:28:03

#### تغییرکرده

- بهینه‌سازی مسیر داغ **VLESS**: UUID از پیش به ۱۶ بایت رمزگشایی می‌شود تا مقایسه مستقیم انجام شود، و تجزیه‌ی بسته‌ی اول با offset و `subarray()` و کپی کمتر انجام می‌شود. [منبع متن‌باز](https://github.com/ToiCF/GrainTCP)
- بهینه‌سازی **WS Early Data**: سقف 8KB اضافه شد و از تزریق زیرپروتکل‌های معمولی WebSocket به بسته‌ی اول، به‌جای early data، جلوگیری می‌شود. [منبع متن‌باز](https://github.com/ToiCF/GrainTCP)
- بهینه‌سازی مسیر آپلود **WS/XHTTP/gRPC**: صف محدود، ادغام بسته‌های کوچک و محافظ backpressure برابر 256KB اضافه شد تا نوشتن‌های پرتکرار بسته‌های کوچک کم شود و صف بی‌نهایت رشد نکند. [منبع متن‌باز](https://github.com/ToiCF/GrainTCP)
- بهینه‌سازی روند ارسال **GrainTCP** در مسیر دانلود: بسته‌های کوچک با microtask و یک پنجره‌ی سکوت کوتاه تجمیع می‌شوند، و بسته‌های بزرگ در مسیر BYOB ابتدا تجمیع‌کننده را flush می‌کنند و سپس مستقیم ارسال می‌شوند؛ این کار کپی‌ها و تعداد فریم‌های WebSocket را کم می‌کند. [منبع متن‌باز](https://github.com/ToiCF/GrainTCP)
- بهینه‌سازی برقراری اتصال TCP: برای کاندیداهای مستقیم و پروکسی معکوس proxyip از اتصال هم‌زمان ۴ مسیره استفاده می‌شود تا اولین اتصال موفق انتخاب شود، در حالی که زنجیره‌های پروکسی SOCKS/HTTP/HTTPS/TURN/SSTP منطق handshake قبلی خود را حفظ می‌کنند. [منبع متن‌باز](https://github.com/ToiCF/GrainTCP)
- بهینه‌سازی handshake در WebSocket و انتقال مسیر اصلی WS: برای `allowHalfOpen` بازگشت امن در صورت استثنا اضافه شد، پاسخ 101 مقدار `Sec-WebSocket-Extensions` را پاک می‌کند، و مسیر اصلی WS اکنون از یک صف ترتیبی صریح استفاده می‌کند. [منبع متن‌باز](https://github.com/ToiCF/GrainTCP)

### [2.1.20260511041705] - 2026-05-11 04:17:05

#### تغییرکرده

- بهینه‌سازی منطق اعتبارسنجی رمز در **صفحه‌ی تنظیمات ورود**، تا کاربران تازه‌کاری که هنگام تنظیم رمز `ADMIN` ناخواسته یک خط‌شکن وارد می‌کنند، دیگر با رمزی که هرگز درست وارد نمی‌شود حوصله‌شان سر نرود!

#### حذف‌شده

- حذف شمارش معکوس تازه‌سازی تعداد درخواست‌ها از هدرهای پاسخ اشتراک، تا کاربران تازه‌کار با دیدن آن کلافه نشوند!

### [2.1.20260508190728] - 2026-05-08 19:07:28

#### رفع‌شده

- رفع مشکل **انتخاب تصادفی برگزیده**: اطلاعات اپراتور پس از تبدیل اشتراک از بین می‌رفت و در نتیجه IPهای برگزیده‌ی اپراتور مربوطه ساخته نمی‌شدند.

#### تغییرکرده

- بهینه‌سازی تبدیل اشتراک: اکنون یک `TOKEN` موقت برای تبدیل ارسال می‌شود تا آدرس واقعی اشتراک نشت نکند.

### [2.1.20260508041513] - 2026-05-08 04:15:13

#### تغییرکرده

- بهینه‌سازی روند تحلیل دامنه‌ی **PROXYIP**: دامنه ابتدا آدرس پروکسی معکوس را از رکورد **TXT** می‌خواند و فقط در صورت نبودن نتیجه‌ی TXT از نتیجه‌ی رکورد **A** استفاده می‌شود.
- وقتی هیچ‌یک از رکوردهای TXT و A نتیجه‌ای ندارند، رکورد **AAAA** درخواست می‌شود تا پرس‌وجوهای غیرضروری IPv6 کم شود.

#### حذف‌شده

- حذف استثنای دامنه‌ی `.william` و منطق تلاش مجدد با Google DoH پشتیبان. اکنون دامنه‌های معمولی هم می‌توانند آدرس پروکسی معکوس را از طریق رکورد TXT تنظیم کنند.

### [2.1.20260506175102] - 2026-05-06 17:51:02

#### افزوده‌شده

- افزودن پروکسی پروتکل **TURN** در حالت پروکسی معکوس. [منبع متن‌باز](https://github.com/ToiCF/CF-Workers-TURN)
- افزودن پروکسی پروتکل **SSTP (SoftEther)** در حالت پروکسی معکوس. [منبع متن‌باز](https://github.com/ToiCF/CF-Workers-SoftEther)
- افزودن قابلیت اضافه‌کردن نودهای **پروکسی زنجیره‌ای** در اشتراک سفارشی.

### [2.1.20260503011925] - 2026-05-03 01:19:25

#### تغییرکرده

- سازگارسازی با قابلیت **دامنه‌ی تحلیل EchConfig** سفارشی در **Sing-box** برای ECH.
- **اشتراک‌های سفارشی** اکنون از دامنه‌های برگزیده‌ی wildcard پشتیبانی می‌کنند.

#### حذف‌شده

- حذف DoH پشتیبانِ **سرویس DNS مربوط به EchConfig** برای ECH در **Clash**.

### [2.1.20260417015756] - 2026-04-17 01:57:56

#### رفع‌شده

- همگام‌سازی با به‌روزرسانی‌های پروژه‌ی بالادستی و رفع مشکلات شناخته‌شده‌ی **پروکسی HTTPS**. [مرجع](https://t.me/Enkelte_notif/824)
- رفع مشکلات شناخته‌شده [#1117](https://github.com/cmliu/edgetunnel/issues/1117) [#1119](https://github.com/cmliu/edgetunnel/issues/1119) [#1120](https://github.com/cmliu/edgetunnel/issues/1120)

### [2.1.20260416044724] - 2026-04-16 04:47:24

#### افزوده‌شده

- پروتکل Trojan اکنون از پرس‌وجوی DNS به‌روش UDP over TCP پشتیبانی می‌کند.
- افزودن **پروکسی HTTPS** در حالت پروکسی معکوس. [منبع متن‌باز](https://github.com/ToiCF/CF-Workers-HTTPS)

### [2.1.20260413174651] - 2026-04-13 17:46:51

#### تغییرکرده

- بهینه‌سازی منطق انتقال داده‌ی WebSocket و پشتیبانی از حالت BYOB برای کارایی و انعطاف بیشتر.

### [2.1.20260410060317] - 2026-04-10 06:03:17

#### افزوده‌شده

- افزودن **انتقال رمزنگاری‌شده‌ی AEAD** برای پروتکل Shadowsocks تا در حالت‌های انتقال بدون TLS هم محتوا رمزنگاری شود.

### [2.1.0]

#### افزوده‌شده

- پروتکل‌های VLESS/Trojan اکنون از روش‌های انتقال XHTTP و gRPC پشتیبانی می‌کنند.

### [2.0.0]

#### افزوده‌شده

- معماری پروژه به‌طور کامل بازنویسی شد و یک صفحه‌ی وب فرانت‌اند جدید اضافه شد. [سورس فرانت‌اند](https://github.com/EDT-Pages/EDT-Pages.github.io)

<p align="left"><a href="#top">⬆ بازگشت به بالا</a></p>

</div>

---

<a id="chinese"></a>

# 🇨🇳 简体中文

所有值得注意的变更均记录在此文件中，分为两部分：第一部分为本分支，第二部分为上游项目的更新日志。
格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)。

## 第一部分 — 本分支：本地化与安装向导

### [Unreleased] — 波斯语与英语本地化及安装向导

基础项目：[cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 2.1
本地化维护者：[@soroushse7o](https://github.com/soroushse7o)（原作者：[@cmliu](https://github.com/cmliu)）

#### 概述

本 PR 为 edgetunnel 添加波斯语（فارسی）和英语本地化，以及一个独立的一键安装向导，且不触碰任何代理、订阅或传输逻辑：

1. 完整的英语和波斯语 README（中文版作为独立文件），以及一个链接到它们的简短三语落地页 `README.md`。
2. 管理面板的客户端翻译层（中文 → 波斯语 / 英语）。
3. 生成的 CF 节点以及订阅生成器错误节点的英文名称。
4. 面向无技术基础用户的一键安装向导（独立的 Cloudflare Worker）。

#### 新增

##### 文档
- 三份完整、独立的 README：`README_en.md`（英语）、`README_fa.md`（波斯语，从右到左，包裹在 `<div dir="rtl">` 中）和 `README_zh.md`（中文）。英语和波斯语文件是原中文 README 的完整翻译。每个文件顶部都有语言切换行：`English | فارسی | 简体中文`。
- `README.md` 现在是一个简短的三语落地页（英语、波斯语、中文）：每种语言各有一段项目简介，并链接到该语言的完整 README。原中文 README 已移至 `README_zh.md`。
- 三份完整 README 中均新增**一键安装向导**章节（位于「快速部署」之前）：在线向导链接、5 步使用说明、自动完成的配置、简短的隐私说明以及向导完整文档链接；落地页中有其精简版。

##### 管理面板本地化（`_worker.js`）
- 位于版本头之后的第 5–737 行新增代码块：
  - `面板本地化脚本` — 浏览器端翻译脚本，包含 **480 条词典条目**
    （中文 → 波斯语 / 英语）。
  - `本地化页面响应()` — 一个小型辅助函数，通过
    `HTMLRewriter` 注入该脚本（`prepend` 到 `<html>` 中）。
- 该函数只处理 `content-type` 为 `text/html` 的响应；任何其他响应，
  或任何错误，都会回退到未经修改的原始响应。
- **默认语言为英语**；**波斯语（فارسی）为第二语言**。原中文界面
  **只能手动**通过 URL 参数 `?lang=zh` 启用（没有对应按钮）。
- 页面左下角固定显示语言切换按钮 **「EN | فارسی」**。
  所选语言保存在 `localStorage` 中（键名 `edt_ui_lang`）。
- 支持 URL 参数 `?lang=en|fa|zh`。该值同样会保存到 `localStorage`，
  因此 `?lang=zh` 会一直保持中文界面，直到选择其他语言。
- 动态文本同样会被翻译：`alert`、`confirm` 和 `prompt` 对话框已被包装，
  并且 `MutationObserver` 会翻译页面加载后新增的节点、文本和属性。

##### 一键安装向导（`wizard-panel/`）
一个独立的单文件 Cloudflare Worker，可把 edgetunnel 安装到用户自己的 Cloudflare 账户。在线地址：[edge-panel-wizard.soroush.my.id](https://edge-panel-wizard.soroush.my.id)；完整文档：[wizard-panel/README.md](https://github.com/soroushse7o/edgetunnel/blob/feat/i18n-en-fa/wizard-panel/README.md)。
- 四步引导页面，支持英语和波斯语双语及从右到左排版（默认**英语**，**波斯语**为第二语言）。
- 可安装为 **Cloudflare Workers** 或 **Cloudflare Pages**。
- 自动配置：验证 API 令牌并使用第一个可访问的账户，下载 edgetunnel 脚本，创建名为 `<project-name>-kv` 的 KV 命名空间并以 `KV` 绑定，设置 `ADMIN` 和 `KEY` 变量并部署。
  - `ADMIN`：随机 16 个字符，或用户自定义（6 到 64 个可见字符，不含空格）。
  - `KEY`：随机 16 个字符，用作快速订阅路径（`/<KEY>`）。
  - 有意**不**设置 `UUID`，这样管理面板仍可管理自己的 UUID。
- Workers 模式会启用 `workers.dev` 路由（账户没有子域名时自动创建）；Pages 模式会创建带有变量和 KV 绑定（生产和预览环境）的项目，并将脚本作为 `_worker.js` 上传。
- **Placement Hint** 选择器，提供 11 个以欧洲为主的区域（意大利、荷兰、德国、芬兰、瑞典、法国、爱尔兰、英国）。如果 Cloudflare 拒绝该提示，Workers 会去掉提示重试一次，Pages 仍然安装成功。
- 干净回滚：如果在创建 KV 命名空间之后安装失败，会删除该命名空间（以及创建到一半的 Pages 项目）。
- 状态栏（待机、部署中、成功、错误），带有清晰的错误信息（令牌无效、权限不足、网络错误、速率限制等）。
- 显示管理面板链接、管理员密码和快速订阅链接。
- 无依赖、无构建步骤、无数据库。向导不存储任何数据；令牌仅用于安装过程中直接请求 Cloudflare API，且不会返回给页面。

#### 变更

##### 经过注入器的面板页面
恰好修改了四处 `fetch(Pages静态页面 + …)` 调用：

| 页面 | 变更 |
|---|---|
| `/login` | 追加 `.then(本地化页面响应)` |
| `/admin` | 追加 `.then(本地化页面响应)` |
| `/noADMIN` | 现有响应处理器现在返回本地化后的响应 |
| `/noKV` | 现有响应处理器现在返回本地化后的响应 |

##### 节点命名（`生成随机IP`）
生成的节点名称现在是 ASCII/英文，而不是中文：

| 变更前 | 变更后 |
|---|---|
| `CF官方优选N` | `CF-Official-N` |
| `CF移动优选N` | `CF-Mobile-N` |
| `CF联通优选N` | `CF-Unicom-N` |
| `CF电信优选N` | `CF-Telecom-N` |
| `CF优选 …ms …MB/s`（API 结果） | `CF-Preferred …ms …MB/s` |

##### 订阅生成器错误信息
三条以占位节点（`127.0.0.1:1234#…`）形式输出、原本使用中文名称的错误信息，现在改为英文：

| 变更前 | 变更后 |
|---|---|
| `…优选订阅生成器格式化异常:…` | `… generator format error: …` |
| `…优选订阅生成器异常:<statusText>` | `… generator error: <statusText>` |
| `…优选订阅生成器异常:<message>` | `… generator error: <message>` |

> 仅替换了名称/信息字符串，未改动任何逻辑。

##### 代码整理
- 移除第 1 行开头的 UTF-8 BOM。

#### 未改动

- 代理逻辑
- 订阅生成逻辑
- WebSocket / gRPC / XHTTP 传输
- 配置处理

#### 验证

- `_worker.js` 通过 `node --check`。
- 注入的翻译脚本本身也通过 `node --check`。

#### 已知限制

- **Network Information** 卡片中显示的运营商（ISP）名称（例如 `科赋锐科技`）
  来自外部 API，因此**不会被翻译**。
- 页面上的切换按钮仅提供英语和波斯语；中文只能
  通过 `?lang=zh` 手动启用。

- 如果 API 令牌可访问多个账户，向导会使用第一个账户。
- `DNS (edit)` 权限为方便起见在令牌页面中被预先勾选，但目前尚未使用。
- 向导将 `ADMIN` 和 `KEY` 以明文变量保存在创建的 Worker/Pages 项目中，因此在 Cloudflare 控制台中仍可查看。

#### 兼容性说明

- 没有新增环境变量、依赖或部署步骤。
- 对于尚未选择语言的访客，**面板默认语言现在是英语（`en`）**
  （此前为中文）。波斯语为第二语言。
  中文用户可以通过
  `?lang=zh` 手动恢复原界面；该选择会保存在其浏览器中。
- 节点名称已变更（见上文）。客户端中匹配旧中文名称
  （例如 `CF官方优选`）的规则、过滤器或路由必须同步更新。

- 向导是可选的，与 edgetunnel 的运行时相互独立：现有部署不受影响。

#### 变更文件

| 文件 | 变更 |
|---|---|
| `_worker.js` | 翻译层（第 5–737 行）、4 处 `fetch` 调用、节点与错误信息名称、移除 BOM |
| `README.md` | 简短的三语落地页，链接到各语言的完整 README |
| `README_en.md`、`README_fa.md`、`README_zh.md` | 各语言完整 README（英语和波斯语为新增，中文版移至此处），均含安装向导章节 |
| `wizard-panel/` | 新增：一键安装向导（Worker 及其 README） |
| `CHANGELOG.md` | 合并后的三语更新日志：本分支（第一部分）与上游项目（第二部分） |

#### 致谢

- 原项目：[cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)，作者 cmliu
- 本地化、安装向导与更新：[soroushse7o](https://github.com/soroushse7o)

---

## 第二部分 — 上游项目（[cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)）

> 原项目更新日志，作者 [@cmliu](https://github.com/cmliu)。以下为中文原文。

### [2.1.20260922200117] - 2026-09-22 20:01:17

#### Debug

- 修复 **汇聚订阅**：统一设置 User-Agent，提升请求行为的一致性。

### [2.1.20260907040834] - 2026-09-07 04:08:34

#### ADD

- 新增 **订阅转换配置**：**展开规则全文**选项。

### [2.1.20260904162413] - 2026-09-04 16:24:13

#### ADD

- 新增 **ALPN** 字段支持：节点链接现已自动携带 ALPN 参数，适配更多客户端场景。

#### Debug

- 修复 **HTTPS 代理**：上游服务器请求客户端证书（CertificateRequest）时握手失败的问题，现已回送空证书正常完成握手。[提交](https://github.com/cmliu/CF-Workers-CheckSocks5/commit/ae93bc28462a6df03795143a5caa85f717ba231a)

### [2.1.20260811144522] - 2026-08-11 14:45:22

#### Change

- 优化 **XHTTP** 上行传输：新增数据合包机制，小块数据合并后再统一发送，减少小包频繁写入，降低资源开销，大文件上传更流畅。

### [2.1.20260810030901] - 2026-08-10 03:09:01

#### ADD

- 新增 **XHTTP obfs padding** 接收端支持：识别 `xPaddingObfsMode`（tokenish / queryInHeader）混淆头。

### [2.1.20260809231057] - 2026-08-09 23:10:57

#### Debug

- 修复 **XHTTP链式代理** 参数解析：路径末尾多余的 `/` 会导致反代配置失效，现已兼容末尾斜杠。

### [2.1.20260809201158] - 2026-08-09 20:11:58

#### Change

- 优化 **XHTTP** 传输链路：TCP 数据改由 `request.body.pipeTo(socket.writable)` 与 `socket.readable.pipeTo(IdentityTransformStream)` 双向直通，不再经过 ReadableStream + 上行写入队列 + BYOB/Grain 逐块搬运，显著降低 CPU 占用。
- 优化 **XHTTP** 连接管理：`forwardataTCP` 新增"仅建立连接"模式，建连并写入首包后直接返回 socket 交由 pipe 直通，同时保留直连失败后自动切换反代的兜底逻辑（gRPC/WS 调用方不受影响）。
- 优化 **XHTTP UDP** 处理：UDP 分支独立拆出为专用处理函数，保留 Trojan UDP 反代与 DNS 转发逻辑。

### [2.1.20260729235734] - 2026-07-29 23:57:34

#### Change

- 修正 **PRELOAD_RACE_DIAL** 环境变量逻辑：默认值由 `true` 改为 `false`（默认**关闭**预加载竞速拨号），设置 `1` 或 `true` 则**开启**；同步修正 README 中该变量的说明。[提交](https://github.com/cmliu/edgetunnel/commit/aea8b85688ef6066116af551cfd5e6fd2ce77567)

### [2.1.20260724150359] - 2026-07-24 15:03:59

#### Change

- 同步 **GrainTCP** 最新传输优化：上行 Grain 合包目标由 `16KB` 调整为 `20KB`，并复用统一的收纳/合包核心；连续小块会在 drain 阶段机会性合并，减少高频 `writer.write()` 调用。[上游提交](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- 优化下行 **GrainTCP** 聚合：保留 `32KB` 聚合上限，使用 `tail × 12` 低水位和最多 `4` 轮、每轮 `1ms` 的增长观察；flush 可连续发送多个聚合包，接近上限时及时发送，降低小包 WebSocket frame 数量。[上游提交](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- 优化下行数据包处理：大块数据在 Grain 为空时直接发送，小块数据在 BYOB/default reader 路径中先脱离可复用读取缓冲；聚合结果复制后再发送，避免 scratch buffer 复用造成数据覆盖。[上游提交](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- 基于上游传输模型增强 TCP 连接管理：加入 connection generation、socket identity 和旧下行 drain 屏障；重拨期间上行数据继续收纳并等待新 writer，旧 reader、定时器或连接的异步收尾不会污染新连接。[上游思路](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- 基于上游 Grain 发送模型统一直发、分段发送、定时 flush 的串行发送链，并持久化异步发送错误；响应头仅在首次真实发送时消费，避免重拨或失效连接提前消耗协议响应头。[上游思路](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- 保持现有多协议兼容性：WS 上行采用非等待入队以降低消息处理阻塞，XHTTP/gRPC 继续等待远端写入完成；本地保留 `16MiB / 4096` 条目的上传高水位保护，避免 Worker 队列无界增长。[上游变更](https://github.com/ToiCF/GrainTCP/commit/1d22628f4d1413989f521f1d41591b0c72e658eb)
- 优化 仅在 **反代模式** 下启用本地测速响应，使用 **SOCKS5/HTTP/HTTPS/TURN/SSTP** 代理时改为正常转发测速请求。

### [2.1.20260722191426] - 2026-07-22 19:14:26

#### Change

- 适配 `http://cp.cloudflare.com/generate_204` 真连接测试地址。

### [2.1.20260711190235] - 2026-07-11 19:02:35

#### ADD

- 新增 **TCP_CONCURRENT_DIAL** 环境变量，可自定义 **TCP 并发拨号数**；设置后不再根据中国移动网络自动降为单路。
- 新增 **PROXY_CONCURRENT_DIAL** 环境变量，可自定义 **反代并发拨号数**。

### [2.1.20260711022318] - 2026-07-11 02:23:18

#### Change

- 优化 **反代相关逻辑**：解决多反代节点参数因全局变量被意外覆盖导致不生效的问题。
- 优化 **DoH 缓存**：缓存近期的域名解析结果，减少重复请求，提升解析速度并降低资源占用；对于没有解析结果的域名也会暂时缓存，避免反复查询。

#### ADD

- 新增 **反代并发拨号数**：可自行调整反代连接的并发数量。并发数越高，连接速度越快，但 IP 切换也越频繁；并发数越低，连接过程则更加稳定。
- 新增 **订阅转换配置**：更多功能选项，包括 **UDP**、**XUDP**、**TLS 1.3**、**插入节点类型** 和 **基础节点排序**，并同步透传到订阅转换后端。
- 新增 **Trojan 回退代理（Fallback）**：Trojan 协议现在支持设置备用代理地址。当主连接不通时，可以自动切换到备用代理继续工作，让连接更稳定可靠。[PR #1359](https://github.com/cmliu/edgetunnel/pull/1359)

### [2.1.20260617014121] - 2026-06-17 01:41:21

#### ADD

- 订阅转换配置 增加 **仅输出节点信息** 的选项。

### [2.1.20260611041617] - 2026-06-11 04:16:17

#### Change

- 优化 **版本信息接口** 的 UUID 校验逻辑，提高校验安全性。

### [2.1.20260609132903] - 2026-06-09 13:29:03

#### Debug

- 修复 **报错1101** 特征码。

#### Change

- 优化 **PROXYIP 解析缓存**：在缓存比较前统一将反代地址转为小写，避免同一反代地址因大小写不同重复解析。

### [2.1.20260601154939] - 2026-06-01 15:49:39

#### Change

- 适配 **Xray-core v26.2.6**：TLS 已移除 `allowInsecure` 配置项，Base64 订阅不再输出 **跳过证书验证** 功能；Clash 与 Sing-box 订阅不受影响。[Release](https://github.com/XTLS/Xray-core/releases/tag/v26.2.6)

### [2.1.20260529014818] - 2026-05-29 01:48:18

#### Change

- 优化 **中国移动** 直连访问时 TCP 并发拨号降级为单路，缓解CPU超时情况。

### [2.1.20260526210857] - 2026-05-26 21:08:57

#### Debug

- 修复 **TURN 认证**：允许 STUN 鉴权 challenge 中存在空 `REALM`，避免空 realm 被误判为缺失导致连接失败。

### [2.1.20260518183745] - 2026-05-18 18:37:45

#### ADD

- 新增 **PRELOAD_RACE_DIAL** 环境变量，可自定义 **TCP 预加载竞速拨号**：首次直连域名时可先通过 DoH 并发查询 A/AAAA 记录，优先使用 IPv4，数量不足时用 IPv6 补齐到 `TCP并发拨号数` 上限；反代失败兜底逻辑与普通首次直连拆分，避免误触发预加载。

### [2.1.20260517185203] - 2026-05-17 18:52:03

#### Debug

- 修复 **WS/XHTTP/gRPC 上传**：上行写入改为等待远端写入完成后再继续处理下一块，避免上传突发时在 Worker 内部快速堆积并触发 `upload queue overflow`。
- 优化 **WS 显式传输队列**：上行队列保护从 256KB 调整为 16MB / 4096 条，并在队列清理时正确释放等待中的写入任务，减少大文件上传时的偶发溢出。

### [2.1.20260515185129] - 2026-05-15 18:51:29

#### Change

- 优化 **Shadowsocks 订阅**：关闭 TLS 时会自动将优选端口重写为 noTLS 端口。（但是该功能不适用于反代IP）
- 优化 **GO2SOCKS5** 变量：从覆盖模式改为追加模式。[PR #1202](https://github.com/cmliu/edgetunnel/pull/1202)

### [2.1.20260513042803] - 2026-05-13 04:28:03

#### Change

- 优化 **VLESS** 热路径：UUID 预解码为 16 字节直接比较，首包解析改为偏移和 `subarray()` 少拷贝处理。[开源引用](https://github.com/ToiCF/GrainTCP)
- 优化 **WS Early Data**：增加 8KB 上限保护，并避免普通 WebSocket 子协议被误当作 early data 注入首包。[开源引用](https://github.com/ToiCF/GrainTCP)
- 优化 **WS/XHTTP/gRPC** 上行链路：新增有界队列、小包合并和 256KB 背压保护，减少高频小包写入次数并防止队列无限增长。[开源引用](https://github.com/ToiCF/GrainTCP)
- 优化 下行 **GrainTCP** 发送流程：小包使用 microtask 和短静默窗口聚合，大包在 BYOB 路径中先刷新聚合器后直接发送，减少复制和 WebSocket frame 数量。[开源引用](https://github.com/ToiCF/GrainTCP)
- 优化 TCP 建连流程：直连和 proxyip 反代候选启用 4 路并发拨号抢首个成功连接，SOCKS/HTTP/HTTPS/TURN/SSTP 代理链路保持原握手逻辑。[开源引用](https://github.com/ToiCF/GrainTCP)
- 优化 WebSocket 握手和 WS 主链路传输：`allowHalfOpen` 增加异常回退，101 响应清空 `Sec-WebSocket-Extensions`，WS 主链路改用显式顺序队列处理。[开源引用](https://github.com/ToiCF/GrainTCP)

### [2.1.20260511041705] - 2026-05-11 04:17:05

#### Change

- 优化 **登录设置页面** 密码验证逻辑，避免小白设置 `ADMIN` 密码的时候存在换行符，导致密码怎么都输不对然后心态爆炸！

#### Delete

- 移除 订阅响应头中的请求数刷新倒计时，避免小白看到后心态爆炸！

### [2.1.20260508190728] - 2026-05-08 19:07:28

#### Debug

- 修复 **随机优选** 时，订阅转换后遗漏运营商信息，导致无法生成对应运营商优选IP的问题。

#### Change

- 优化 订阅转换时将提交临时 `TOKEN` 用于转换，避免真实订阅地址泄露。

### [2.1.20260508041513] - 2026-05-08 04:15:13

#### Change

- 优化 **PROXYIP** 域名解析流程：域名会优先读取 **TXT** 记录中的反代地址，未获取到 TXT 结果时再使用 **A** 记录解析结果。
- 当 TXT 和 A 记录均无结果时，再请求 **AAAA** 记录，减少不必要的 IPv6 查询。

#### Delete

- 移除 `.william` 域名特判和 Google DoH 备用重试逻辑，普通域名也可通过 TXT 记录配置反代地址。

### [2.1.20260506175102] - 2026-05-06 17:51:02

#### New

- 反代模式 中新增 **TURN 协议** 代理的功能。[开源引用](https://github.com/ToiCF/CF-Workers-TURN)
- 反代模式 中新增 **SSTP(SoftEther) 协议** 代理的功能。[开源引用](https://github.com/ToiCF/CF-Workers-SoftEther)
- 自定义订阅 中新增添加 **链式代理** 节点的功能。

### [2.1.20260503011925] - 2026-05-03 01:19:25

#### Change

- 适配 **Sing-box** 关于 ECH 自定义 **EchConfig 解析域名** 功能。
- **自定义订阅** 适配 通配符优选域名。

#### Delete

- 删除 **Clash** 关于 ECH 的 **EchConfig DNS服务** 备用DoH。

### [2.1.20260417015756] - 2026-04-17 01:57:56

#### Debug

- 同步上游项目更新，修复 **HTTPS 代理** 已知问题。[参考链接](https://t.me/Enkelte_notif/824)
- 修复已知问题 [#1117](https://github.com/cmliu/edgetunnel/issues/1117) [#1119](https://github.com/cmliu/edgetunnel/issues/1119) [#1120](https://github.com/cmliu/edgetunnel/issues/1120)

### [2.1.20260416044724] - 2026-04-16 04:47:24

#### New

- Trojan 协议现已支持通过 UDP Over TCP 方式进行 DNS 查询。
- 反向代理模式中新增 **HTTPS 代理** 功能。[开源引用](https://github.com/ToiCF/CF-Workers-HTTPS)

### [2.1.20260413174651] - 2026-04-13 17:46:51

#### Change

- 优化WebSocket数据传输逻辑，支持BYOB模式以提高性能和灵活性。

### [2.1.20260410060317] - 2026-04-10 06:03:17

#### New

- 新增 Shadowsocks 协议 **AEAD 加密传输**，为非 TLS 传输模式提供内容加密。

### [2.1.0]

#### New
- VLESS/Trojan 协议现已支持 XHTTP 和 gRPC 传输方式。

### [2.0.0]

#### New

- 项目架构已完全重写，新增前端 Web 页面。[前端源码](https://github.com/EDT-Pages/EDT-Pages.github.io)

<p align="right"><a href="#top">⬆ 返回顶部</a></p>
