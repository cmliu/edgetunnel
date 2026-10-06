# Changelog

All notable changes in this pull request are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — Persian & English localization

Base project: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 2.1
Localization maintained by: [@soroushse7o](https://github.com/soroushse7o) (original author: [@cmliu](https://github.com/cmliu))

### Summary

This PR adds Persian (فارسی) and English localization to edgetunnel without
touching any proxy, subscription, or transport logic:

1. Full Persian and English translations of the project README.
2. A client-side translation layer for the admin panel (Chinese → Persian / English).
3. English names for the generated CF nodes and for subscription-generator error nodes.

### Added

#### Documentation
- `README_en.md` — full English translation of `README.md`.
- `README_fa.md` — full Persian translation of `README.md`, rendered right-to-left
  (wrapped in `<div dir="rtl">`).
- Language switcher line in the translated READMEs:
  `English | فارسی | 简体中文`.

#### Admin panel localization (`_worker.js`)
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

### Changed

#### Panel pages passed through the injector
Exactly four `fetch(Pages静态页面 + …)` call sites were modified:

| Page | Change |
|---|---|
| `/login` | `.then(本地化页面响应)` appended |
| `/admin` | `.then(本地化页面响应)` appended |
| `/noADMIN` | existing response handler now returns the localized response |
| `/noKV` | existing response handler now returns the localized response |

#### Node naming (`生成随机IP`)
Generated node names are now ASCII/English instead of Chinese:

| Before | After |
|---|---|
| `CF官方优选N` | `CF-Official-N` |
| `CF移动优选N` | `CF-Mobile-N` |
| `CF联通优选N` | `CF-Unicom-N` |
| `CF电信优选N` | `CF-Telecom-N` |
| `CF优选 …ms …MB/s` (API result) | `CF-Preferred …ms …MB/s` |

#### Subscription generator error messages
Three error entries that are emitted as a placeholder node
(`127.0.0.1:1234#…`) with a Chinese name are now in English:

| Before | After |
|---|---|
| `…优选订阅生成器格式化异常:…` | `… generator format error: …` |
| `…优选订阅生成器异常:<statusText>` | `… generator error: <statusText>` |
| `…优选订阅生成器异常:<message>` | `… generator error: <message>` |

> Only name/message strings were replaced. No logic was changed.

#### Housekeeping
- Removed the UTF-8 BOM at the start of line 1.

### Not changed

- Proxy logic
- Subscription generation logic
- WebSocket / gRPC / XHTTP transports
- Configuration handling

### Verification

- `node --check` passes on `_worker.js`.
- `node --check` passes on the injected translation script itself.

### Known limitations

- ISP names shown in the **Network Information** cards (for example `科赋锐科技`)
  come from an external API and are therefore **not translated**.
- The on-page toggle offers English and Persian only; Chinese is available
  only manually via `?lang=zh`.

### Compatibility notes

- No new environment variables, dependencies or deployment steps.
- **Default panel language is now English (`en`)** for visitors who have not
  chosen a language yet (previously Chinese). Persian is the second language.
  Chinese-speaking users can restore the original interface manually with
  `?lang=zh`; the choice is remembered in their browser.
- Node names changed (see above). Client-side rules, filters or routing that
  match the old Chinese names (for example `CF官方优选`) must be updated.

### Files changed

| File | Change |
|---|---|
| `_worker.js` | Translation layer (lines 5–737), 4 `fetch` call sites, node and error-message names, BOM removed |
| `README_en.md` | New |
| `README_fa.md` | New |

### Credits

- Original project: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) by cmliu
- Localization and updates: [soroushse7o](https://github.com/soroushse7o)
