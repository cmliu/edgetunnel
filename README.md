# 🚀 edgetunnel 2.1

![Admin panel](./img.png)

[![Stars](https://img.shields.io/github/stars/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/stargazers)
[![Forks](https://img.shields.io/github/forks/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/network/members)
[![License](https://img.shields.io/github/license/cmliu/edgetunnel?style=flat-square)](https://github.com/cmliu/edgetunnel/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Group-blue?style=flat-square&logo=telegram)](https://t.me/CMLiussss)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-red?style=flat-square&logo=youtube)](https://www.youtube.com/watch?v=LeT4jQUh8ok)
[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat-square&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/cmliu/edgetunnel)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cmliu/edgetunnel)

📖 **Full documentation · مستندات کامل · 完整文档:**
[English](README_en.md) | [فارسی](README_fa.md) | [简体中文](README_zh.md)

---

## 🇬🇧 English

**edgetunnel** is an edge-computing tunneling solution built on **CF Workers/Pages**. It processes network traffic efficiently and comes with a powerful admin panel and flexible node configuration. 🖥️ **Live demo:** [EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

**Highlights**

- 🛡️ VLESS, Trojan and Shadowsocks support with encrypted transport
- 📊 Built-in admin panel: live configuration, logs and traffic statistics
- 🛠️ Runs on CF Workers and CF Pages (GitHub or direct upload)
- 🔄 Automatic subscription generation and conversion for Clash, Sing-box, Surge and more
- ⚡ Custom ProxyIP, chained SOCKS5/HTTP proxies and a preferred-IP API
- 🌐 Windows, Android, iOS, macOS and soft-router clients

> [!TIP]
> ⚡ **Easiest install, no technical knowledge needed:** the one-click [Install Wizard](https://edge-panel-wizard.soroush.my.id). It deploys edgetunnel to your own Cloudflare account, creates the KV binding and sets `ADMIN` and `KEY` for you. [Wizard documentation](https://github.com/soroushse7o/edgetunnel/blob/feat/i18n-en-fa/wizard-panel/README.md)

**Manual deployment:** [Pages upload (highly recommended)](https://cmliussss.com/p/edt2/), Workers, or Pages + GitHub. You always need an `ADMIN` variable (your admin password) and a KV namespace bound as `KV`; the admin panel is then at `/admin`.

**Disclaimer:** for educational, research and personal security testing only. Follow your local laws; the author accepts no responsibility for misuse; delete test deployments within 24 hours.

📘 **[Read the full English documentation →](README_en.md)** (deployment guides, all environment variables, advanced tips, client compatibility, credits)

---

<div dir="rtl">

## 🇮🇷 فارسی

**edgetunnel** یک راهکار تونل‌زنی مبتنی بر محاسبات لبه (Edge Computing) است که روی **CF Workers/Pages** اجرا می‌شود. ترافیک شبکه را با کارایی بالا پردازش می‌کند و یک پنل مدیریت قدرتمند و پیکربندی انعطاف‌پذیر نودها در اختیارتان می‌گذارد. 🖥️ **دموی آنلاین:** [EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

**ویژگی‌های کلیدی**

- 🛡️ پشتیبانی از VLESS، Trojan و Shadowsocks با انتقال رمزنگاری‌شده
- 📊 پنل مدیریت داخلی: تغییر زنده‌ی تنظیمات، مشاهده‌ی لاگ و آمار ترافیک
- 🛠️ اجرا روی CF Workers و CF Pages (از طریق GitHub یا آپلود مستقیم)
- 🔄 تولید و تبدیل خودکار اشتراک برای Clash، Sing-box، Surge و غیره
- ⚡ ProxyIP سفارشی، پروکسی زنجیره‌ای SOCKS5/HTTP و API آی‌پی‌های برگزیده
- 🌐 کلاینت‌های ویندوز، اندروید، iOS، macOS و روترهای نرم‌افزاری

> [!TIP]
> ⚡ **ساده‌ترین روش نصب، بدون نیاز به دانش فنی:** [ویزارد نصب یک‌کلیکی](https://edge-panel-wizard.soroush.my.id). edgetunnel را روی حساب کلادفلر خودتان نصب می‌کند، بایند KV را می‌سازد و `ADMIN` و `KEY` را برایتان تنظیم می‌کند. [مستندات ویزارد](https://github.com/soroushse7o/edgetunnel/blob/feat/i18n-en-fa/wizard-panel/README.md)

**استقرار دستی:** [آپلود در Pages (به‌شدت توصیه می‌شود)](https://cmliussss.com/p/edt2/)، Workers یا Pages + GitHub. همیشه به متغیر `ADMIN` (رمز پنل مدیریت) و یک KV namespace با نام بایند `KV` نیاز دارید؛ سپس پنل مدیریت روی `/admin` در دسترس است.

**سلب مسئولیت:** فقط برای مقاصد آموزشی، پژوهشی و تست امنیتی شخصی. قوانین محل زندگی خود را رعایت کنید؛ نویسنده هیچ مسئولیتی در قبال سوءاستفاده ندارد؛ استقرارهای آزمایشی را ظرف ۲۴ ساعت حذف کنید.

📘 **[مطالعه‌ی مستندات کامل فارسی ←](README_fa.md)** (راهنمای استقرار، همه‌ی متغیرهای محیطی، نکات پیشرفته، سازگاری کلاینت‌ها، قدردانی‌ها)

</div>

---

## 🇨🇳 简体中文

**edgetunnel** 是一个基于 **CF Workers/Pages** 平台的边缘计算隧道解密方案，能高效处理网络流量，并提供强大的管理面板和灵活的节点配置能力。🖥️ **Demo 演示站点：** [EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

**核心特性**

- 🛡️ 支持 VLESS、Trojan、Shadowsocks 等主流协议，深度整合加密传输
- 📊 内置可视化管理面板：实时修改配置、查看日志与流量统计
- 🛠️ 兼容 CF Workers 与 CF Pages（GitHub 或直接上传）
- 🔄 自动生成并转换订阅，兼容 Clash、Sing-box、Surge 等主流客户端
- ⚡ 支持自定义 ProxyIP、SOCKS5/HTTP 链式代理和优选 IP API
- 🌐 适配 Windows、Android、iOS、macOS 及各类软路由

> [!TIP]
> ⚡ **最简单的安装方式，无需技术基础：** 一键[安装向导](https://edge-panel-wizard.soroush.my.id)。它会把 edgetunnel 部署到你自己的 Cloudflare 账户，自动创建 KV 绑定并设置 `ADMIN` 和 `KEY`。[向导文档](https://github.com/soroushse7o/edgetunnel/blob/feat/i18n-en-fa/wizard-panel/README.md)

**手动部署：** [Pages 上传部署（最佳推荐）](https://cmliussss.com/p/edt2/)、Workers，或 Pages + GitHub。始终需要 `ADMIN` 变量（管理密码）和以 `KV` 为变量名绑定的 KV 命名空间；之后在 `/admin` 打开管理面板。

**免责声明：** 仅供教育、科研和个人安全测试使用。请遵守所在地区法律；作者对滥用不承担任何责任；测试结束后请在 24 小时内删除相关部署。

📘 **[阅读完整中文文档 →](README_zh.md)**（部署教程、全部环境变量、高级技巧、客户端适配、特别鸣谢）

---

**⭐ If this project helps you, please give it a Star · اگر مفید بود یک Star بدهید · 如果项目对您有帮助，请给一个 Star 🌟**
