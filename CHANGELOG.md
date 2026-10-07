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

<p align="right"><a href="#top">⬆ Back to top</a></p>

---

<a id="persian"></a>

<div dir="rtl">

# 🇮🇷 فارسی

تمام تغییرات قابل‌توجه این Pull Request در همین فایل ثبت شده است.
قالب فایل از [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) پیروی می‌کند.

## [Unreleased] — بومی‌سازی فارسی و انگلیسی

پروژه‌ی پایه: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) نسخه‌ی 2.1
بومی‌سازی توسط: [@soroushse7o](https://github.com/soroushse7o) (نویسنده‌ی اصلی: [@cmliu](https://github.com/cmliu))

### خلاصه

این PR بومی‌سازی فارسی و انگلیسی را به edgetunnel اضافه می‌کند، بدون این‌که به منطق پروکسی، اشتراک یا انتقال دست بزند:

1. ترجمه‌ی کامل فارسی و انگلیسی README پروژه.
2. یک لایه‌ی ترجمه در سمت کلاینت برای پنل مدیریت (چینی ← فارسی / انگلیسی).
3. نام انگلیسی برای نودهای CF تولیدشده و برای نودهای خطای مولد اشتراک.

### افزوده‌شده

#### مستندات
- `README_en.md` — ترجمه‌ی کامل انگلیسی `README.md`.
- `README_fa.md` — ترجمه‌ی کامل فارسی `README.md` به‌صورت راست‌به‌چپ
  (داخل `<div dir="rtl">`).
- خط تعویض زبان در READMEهای ترجمه‌شده:
  `English | فارسی | 简体中文`.

#### بومی‌سازی پنل مدیریت (`_worker.js`)
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

### تغییرکرده

#### صفحه‌های پنل که از تزریق‌کننده عبور می‌کنند
دقیقاً چهار محل فراخوانی `fetch(Pages静态页面 + …)` تغییر کرد:

| صفحه | تغییر |
|---|---|
| `/login` | `.then(本地化页面响应)` اضافه شد |
| `/admin` | `.then(本地化页面响应)` اضافه شد |
| `/noADMIN` | مدیریت‌کننده‌ی پاسخ موجود اکنون پاسخ بومی‌سازی‌شده را برمی‌گرداند |
| `/noKV` | مدیریت‌کننده‌ی پاسخ موجود اکنون پاسخ بومی‌سازی‌شده را برمی‌گرداند |

#### نام‌گذاری نودها (`生成随机IP`)
نام نودهای تولیدشده اکنون به‌جای چینی، ASCII/انگلیسی است:

| قبل | بعد |
|---|---|
| `CF官方优选N` | `CF-Official-N` |
| `CF移动优选N` | `CF-Mobile-N` |
| `CF联通优选N` | `CF-Unicom-N` |
| `CF电信优选N` | `CF-Telecom-N` |
| `CF优选 …ms …MB/s` (نتیجه‌ی API) | `CF-Preferred …ms …MB/s` |

#### پیام‌های خطای مولد اشتراک
سه پیام خطا که به‌صورت یک نود جایگزین (`127.0.0.1:1234#…`) با نام چینی ارسال می‌شدند، اکنون انگلیسی هستند:

| قبل | بعد |
|---|---|
| `…优选订阅生成器格式化异常:…` | `… generator format error: …` |
| `…优选订阅生成器异常:<statusText>` | `… generator error: <statusText>` |
| `…优选订阅生成器异常:<message>` | `… generator error: <message>` |

> فقط رشته‌های نام/پیام جایگزین شدند. هیچ منطقی تغییر نکرد.

#### نظافت کد
- حذف UTF-8 BOM از ابتدای خط 1.

### بدون تغییر

- منطق پروکسی
- منطق تولید اشتراک
- انتقال‌های WebSocket / gRPC / XHTTP
- مدیریت پیکربندی

### راستی‌آزمایی

- `node --check` روی `_worker.js` بدون خطا اجرا می‌شود.
- `node --check` روی خودِ اسکریپت ترجمه‌ی تزریق‌شده هم بدون خطا اجرا می‌شود.

### محدودیت‌های شناخته‌شده

- نام اپراتورها (ISP) در کارت‌های **Network Information** (مثلاً `科赋锐科技`)
  از یک API خارجی می‌آیند و بنابراین **ترجمه نمی‌شوند**.
- دکمه‌ی روی صفحه فقط انگلیسی و فارسی را ارائه می‌دهد؛ چینی فقط
  به‌صورت دستی با `?lang=zh` در دسترس است.

### نکات سازگاری

- بدون متغیر محیطی، وابستگی یا مرحله‌ی استقرار جدید.
- **زبان پیش‌فرض پنل اکنون انگلیسی (`en`) است** برای بازدیدکنندگانی که هنوز
  زبانی انتخاب نکرده‌اند (قبلاً چینی بود). فارسی زبان دوم است.
  کاربران چینی‌زبان می‌توانند رابط اصلی را به‌صورت دستی با
  `?lang=zh` بازگردانند؛ انتخاب آن‌ها در مرورگرشان به یاد سپرده می‌شود.
- نام نودها تغییر کرده است (بالا را ببینید). قواعد، فیلترها یا مسیریابی سمت کلاینت
  که با نام‌های چینی قبلی (مثلاً `CF官方优选`) تطبیق می‌دهند باید به‌روز شوند.

### فایل‌های تغییریافته

| فایل | تغییر |
|---|---|
| `_worker.js` | لایه‌ی ترجمه (خطوط 5 تا 737)، ۴ محل فراخوانی `fetch`، نام نودها و پیام‌های خطا، حذف BOM |
| `README_en.md` | جدید |
| `README_fa.md` | جدید |

### تشکر

- پروژه‌ی اصلی: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) از cmliu
- بومی‌سازی و به‌روزرسانی‌ها: [soroushse7o](https://github.com/soroushse7o)

<p align="left"><a href="#top">⬆ بازگشت به بالا</a></p>

</div>

---

<a id="chinese"></a>

# 🇨🇳 简体中文

本 Pull Request 中所有值得注意的变更均记录在此文件中。
格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)。

## [Unreleased] — 波斯语与英语本地化

基础项目：[cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 2.1
本地化维护者：[@soroushse7o](https://github.com/soroushse7o)（原作者：[@cmliu](https://github.com/cmliu)）

### 概述

本 PR 为 edgetunnel 添加波斯语（فارسی）和英语本地化，且不触碰任何代理、订阅或传输逻辑：

1. 项目 README 的完整波斯语和英语翻译。
2. 管理面板的客户端翻译层（中文 → 波斯语 / 英语）。
3. 生成的 CF 节点以及订阅生成器错误节点的英文名称。

### 新增

#### 文档
- `README_en.md` — `README.md` 的完整英文翻译。
- `README_fa.md` — `README.md` 的完整波斯语翻译，采用从右到左排版
  （包裹在 `<div dir="rtl">` 中）。
- 翻译版 README 中的语言切换行：
  `English | فارسی | 简体中文`。

#### 管理面板本地化（`_worker.js`）
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

### 变更

#### 经过注入器的面板页面
恰好修改了四处 `fetch(Pages静态页面 + …)` 调用：

| 页面 | 变更 |
|---|---|
| `/login` | 追加 `.then(本地化页面响应)` |
| `/admin` | 追加 `.then(本地化页面响应)` |
| `/noADMIN` | 现有响应处理器现在返回本地化后的响应 |
| `/noKV` | 现有响应处理器现在返回本地化后的响应 |

#### 节点命名（`生成随机IP`）
生成的节点名称现在是 ASCII/英文，而不是中文：

| 变更前 | 变更后 |
|---|---|
| `CF官方优选N` | `CF-Official-N` |
| `CF移动优选N` | `CF-Mobile-N` |
| `CF联通优选N` | `CF-Unicom-N` |
| `CF电信优选N` | `CF-Telecom-N` |
| `CF优选 …ms …MB/s`（API 结果） | `CF-Preferred …ms …MB/s` |

#### 订阅生成器错误信息
三条以占位节点（`127.0.0.1:1234#…`）形式输出、原本使用中文名称的错误信息，现在改为英文：

| 变更前 | 变更后 |
|---|---|
| `…优选订阅生成器格式化异常:…` | `… generator format error: …` |
| `…优选订阅生成器异常:<statusText>` | `… generator error: <statusText>` |
| `…优选订阅生成器异常:<message>` | `… generator error: <message>` |

> 仅替换了名称/信息字符串，未改动任何逻辑。

#### 代码整理
- 移除第 1 行开头的 UTF-8 BOM。

### 未改动

- 代理逻辑
- 订阅生成逻辑
- WebSocket / gRPC / XHTTP 传输
- 配置处理

### 验证

- `_worker.js` 通过 `node --check`。
- 注入的翻译脚本本身也通过 `node --check`。

### 已知限制

- **Network Information** 卡片中显示的运营商（ISP）名称（例如 `科赋锐科技`）
  来自外部 API，因此**不会被翻译**。
- 页面上的切换按钮仅提供英语和波斯语；中文只能
  通过 `?lang=zh` 手动启用。

### 兼容性说明

- 没有新增环境变量、依赖或部署步骤。
- 对于尚未选择语言的访客，**面板默认语言现在是英语（`en`）**
  （此前为中文）。波斯语为第二语言。
  中文用户可以通过
  `?lang=zh` 手动恢复原界面；该选择会保存在其浏览器中。
- 节点名称已变更（见上文）。客户端中匹配旧中文名称
  （例如 `CF官方优选`）的规则、过滤器或路由必须同步更新。

### 变更文件

| 文件 | 变更 |
|---|---|
| `_worker.js` | 翻译层（第 5–737 行）、4 处 `fetch` 调用、节点与错误信息名称、移除 BOM |
| `README_en.md` | 新增 |
| `README_fa.md` | 新增 |

### 致谢

- 原项目：[cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)，作者 cmliu
- 本地化与更新：[soroushse7o](https://github.com/soroushse7o)

<p align="right"><a href="#top">⬆ 返回顶部</a></p>
