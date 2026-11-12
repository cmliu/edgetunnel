# 🚀 edgetunnel 2.1
![Backend Page](./img.png)

[![Stars](https://img.shields.io/github/stars/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/stargazers)
[![Forks](https://img.shields.io/github/forks/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/network/members)
[![License](https://img.shields.io/github/license/cmliu/edgetunnel?style=flat-square)](https://github.com/cmliu/edgetunnel/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Group-blue?style=flat-square&logo=telegram)](https://t.me/CMLiussss)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-red?style=flat-square&logo=youtube)](https://www.youtube.com/watch?v=LeT4jQUh8ok)
[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat-square&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/cmliu/edgetunnel)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cmliu/edgetunnel)

---

## 📖 Project Introduction

**edgetunnel** is an edge computing tunneling decryption solution based on the CF Workers/Pages platform. It can efficiently handle network traffic and provides a powerful management panel and flexible node configuration capabilities.

- 🖥️ **Demo Site**: [https://EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

### ✨ Core Features

- 🛡️ **Protocol Support**: Supports mainstream protocols such as VLESS, Trojan, and Shadowsocks, with deep integration of encrypted transmission.
- 📊 **Management Panel**: Built-in visual backend, supporting real-time configuration modification, log viewing, and traffic statistics.
- 🛠️ **Flexible Deployment**: Fully compatible with CF Workers and CF Pages (GitHub / Upload).
- 🔄 **Subscription System**: Built-in automatic subscription generation and obfuscation conversion, compatible with mainstream clients (Clash, Sing-box, Surge, etc.).
- ⚡ **Performance Acceleration**: Supports custom ProxyIP, SOCKS5/HTTP chained proxies, and preferred APIs to optimize network latency.
- 🌐 **Multi-device compatibility**: Perfectly compatible with Windows, Android, iOS, MacOS, and various software router firmware.

---

## 💡 Rapid Deployment
>[!TIP]
> 📖 **Detailed Illustrated Tutorial**: [edgetunnel Deployment Guide](https://cmliussss.com/p/edt2/)

>[!WARNING]
> ⚠️ **Error 1101**: [Video Analysis](https://www.youtube.com/watch?v=r4uVTEJptdE)

### ⚙️ Workers Deployment

<details>
<summary><code><strong>"Workers Deployment Text Tutorial"</strong></code></summary>

1. Deploy CF Worker:
   - Create a new Worker in the CF Worker console.
   - Paste the contents of [worker.js](https://github.com/cmliu/edgetunnel/blob/main/_worker.js) into the Worker editor.
   - In the Settings tab on the left, select Variables > Add Variable.
     Enter **ADMIN** as the variable name and your administrator password as the value. Then click `Save`.

2. Bind KV namespace:
   - In the `Bindings` tab, select `Add Binding+` > `KV Namespace` > `Add Binding`, and then select an existing namespace or create a new namespace to bind to.
   - Enter **KV** in the `Variable Name` field, and then click `Add Binding`.

3. Bind custom fields to Workers:
   - In the workers console, under the `triggers` tab, click `add custom domain`.
   - Enter your subdomain that you have transferred to CF DNS service, for example: `vless.google.com`, then click `Add Custom Domain` and wait for the certificate to take effect.

4. Access the backend:
   - Visit `https://vless.google.com/admin` and enter the administrator password to log in to the backend.

</details>

### 🛠 Pages Upload and Deployment Method **Best Recommendation!!!** [Illustrated Tutorial](https://cmliussss.com/p/edt2/)

<details>
<summary><code><strong>"Pages File Upload Deployment Text Tutorial"</strong></code></summary>

1. Deploy CF Pages:
   Download the [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) file and star it!!!
   - In the CF Pages console, select 'Upload Assets', name your project, click 'Create Project', then upload the downloaded [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) file and click 'Deploy Site'.
   - After deployment is complete, click `Continue to process the site`, then select `Settings` > `Environment Variables` > **Create** a variable for the production environment > `Add Variable`.
     Enter **ADMIN** as the variable name and your administrator password as the value. Then click `Save`.
   - Return to the `Deployment` tab, click `Create New Deployment` in the bottom right corner, then re-upload the [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) file and click `Save and Deploy`.

2. Bind KV namespace:
   - In the Settings tab, select Bindings > Add > KV Namespace, then select an existing namespace or create a new namespace for binding.
   - Enter **KV** in the `Variable Name` field, then click `Save` and try deploying again.

3. Bind a custom CNAME domain to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages console, on the Custom Fields tab, click Set Custom Field.
   - Enter your custom subdomain, being careful not to use your root domain, for example:
     If your assigned domain name is `fuck.cloudns.biz`, then you can add a custom domain by entering `lizi.fuck.cloudns.biz`.
   - As required by CF, you will be redirected to your domain's DNS service provider. After adding the CNAME record `edgetunnel.pages.dev` for the custom domain `lizi`, click `Activate Domain`.
   
4. Access the backend:
   - Visit `https://lizi.fuck.cloudns.biz/admin` and enter the administrator password to log in to the backend.

</details>

### 🛠 Pages + GitHub Deployment Method

<details>
<summary><code><strong>“Pages + GitHub Deployment Text Tutorial”</strong></code></summary>

1. Deploy CF Pages:
   - Fork this project on GitHub first, and then star it!
   - In the CF Pages console, select `Connect to Git`, then select the `edgetunnel` project and click `Start Setup`.
   - On the `Set up build and deployment` page, select `Environment Variables (Advanced)` and then `Add Variable`.
     Enter **ADMIN** as the variable name and your administrator password as the value. Then click `Save and Deploy`.

2. Bind KV namespace:
   - In the Settings tab, select Bindings > Add > KV Namespace, then select an existing namespace or create a new namespace for binding.
   - Enter **KV** in the `Variable Name` field, then click `Save` and try deploying again.

3. Bind a custom CNAME domain to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages console, on the Custom Fields tab, click Set Custom Field.
   - Enter your custom subdomain, being careful not to use your root domain, for example:
     If your assigned domain name is `fuck.cloudns.biz`, then you can add a custom domain by entering `lizi.fuck.cloudns.biz`.
   - As required by CF, you will be redirected to your domain's DNS service provider. After adding the CNAME record `edgetunnel.pages.dev` for the custom domain `lizi`, click `Activate Domain`.

4. Access the backend:
   - Visit `https://lizi.fuck.cloudns.biz/admin` and enter the administrator password to log in to the backend.

</details>

---

## 🔑 Explanation of Environment Variables

| Variable Name | Required | Example | Detailed Comments |
| :--- | :---: | :--- | :--- |
| **ADMIN** | ✅ | `123456` | Admin Panel Login Password |
| **KEY** | ❌ | `CMLiussss` | Quickly subscribe to the path key; access `/CMLiussss` to quickly obtain the node. |
| **UUID** | ❌ | `90cd4a77-141a-43c9-991b-08263cfe9c10` | Forces a fixed UUID, only supports the **UUIDv4** standard format |
| **PROXYIP** | ❌ | `proxyip.cmliussss.net:443` | Global Custom Reverse Proxy IP |
| **URL** | ❌ | `https://cloudflare-error-page-3th.pages.dev` | Default homepage spoofing address (can be a webpage URL or `1101`) |
| **GO2SOCKS5** | ❌ | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` | List of sites forced to use SOCKS5 (`*` represents global, domains are separated by commas) |
| **DEBUG** | ❌ | `1` or `true` | **Developer Mode**, disables debug logging (console.log) by default. Setting `1` or `true` enables debug logging.
| **OFF_LOG** | ❌ | `1` or `true` | Enables logging by default; setting `1` or `true` disables logging.
| **BEST_SUB** | ❌ | `1` or `true` | Disables the function as a **preferred subscription generator** by default. Setting `1` or `true` enables this function.
| **PRELOAD_RACE_DIAL** | ❌ | `1` or `true` | Disables the function of **preloading race dial** by default. Setting `1` or `true` enables this function.
| **TCP_CONCURRENT_DIAL** | ❌ | `2` | **TCP concurrent dialing count**, default value is `2`; after setting, it will no longer automatically reduce to single-path based on China Mobile network.
| **PROXY_CONCURRENT_DIAL** | ❌ | `1` | **Number of concurrent reverse proxy dialers**, default value is `1`; the higher the value, the faster the connection speed, but the more frequent the IP switching.

---

## 🔧 Advanced Practical Tips
To modify the **TOKEN** in the subscription address and the **UUID used for node verification**, you can modify the variables.
1. Modifying the value of the `ADMIN` or `KEY` variable can randomly change the **TOKEN in the subscription address** and the **UUID used for node verification**.
2. Setting the `UUID` variable can force the **TOKEN** in the subscription address and the **UUID used for node verification** to be fixed. Note that it must be in the **UUIDv4** standard format, otherwise the node will not be usable.

This tool supports dynamically switching the underlying proxy scheme via **PATH**:

- Specify the `PROXYIP` case
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   ```

- Specify the `SOCKS5` case
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (Global SOCKS5 is activated by default)
   /socks5://user:password@127.0.0.1:1080 (Default activation of global SOCKS5)
   ```

- Specifying an `HTTP proxy` example
   ```url
   /http=user:password@127.0.0.1:1080
   http://user:password@127.0.0.1:8080 (Default activation of global SOCKS5)
   ```

- Specify the `Trojan fallback` case (Since the use case is a self-built connection, only the Trojan is inbound, and the fallback service must be the same password, not WebSocket, and not TLS. In this case, UDP is passed through to the fallback, resulting in excellent performance and complete functionality).
   ```url
   /trojan=1.1.1.1:1234
   ```

---

## 💻 Client compatibility status

| Platform | Recommended Client |
| :--- | :--- |
| **Windows** | [v2rayN](https://github.com/2dust/v2rayN/releases)、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、[FlClash](https://github.com/chen08209/FlClash/releases)、[mihomo-party](https://github.com/mihomo-party-org/clash-party/releases)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)、[Clashmi](https://github.com/KaringX/clashmi/releases)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)、[Karing](https://github.com/KaringX/karing/releases)、[Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **Android** | [v2rayNG](https://github.com/2dust/v2rayNG/releases)、[ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid/releases/)、[FlClash](https://github.com/chen08209/FlClash/releases)、[Clashmi](https://github.com/KaringX/clashmi/releases)、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、[NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)、[Karing](https://github.com/KaringX/karing/releases)、[Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **iOS** | Surge、Shadowrocket、Stash、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、Loon、Egern、[Clashmi](https://clashmi.app/download)、[Karing](https://karing.app/)、Quantumult X |
| **macOS** | [FlClash](https://github.com/chen08209/FlClash/releases)、[mihomo-party](https://github.com/mihomo-party-org/clash-party/releases)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)、Surge、[Clashmi](https://clashmi.app/download)、[Karing](https://karing.app/)、[FlyClash](https://github.com/GtxFury/FlyClash/releases) |
| **鸿蒙** | [ClashBox](https://github.com/xiaobaigroup/ClashBox/releases) |
---

## ⭐ Project Popularity

![Stargazers over time](https://github.com/cmliu/cmliu/blob/main/star/edgetunnel.svg)

---

## 🙏 Special thanks
### 💖 Sponsorship Support - Cloud server provided to maintain [subscription conversion service](https://sub.cmliussss.net/)
- [Alice](https://url.cmliussss.com/alice)
- [EasyLinks](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)
- [ZMTO(VTEXS)](https://zmto.com/?affid=1532)

### 🛠 Open Source Code References
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [Stock Market Guru](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [Bestfreebie Guy](https://t.me/bestcfipas)
- [Mingyu](https://github.com/ymyuuu/workers-vless)
- [ToiCF/CF-Workers-HTTPS](https://github.com/ToiCF/CF-Workers-HTTPS)
- [ToiCF/CF-Workers-TURN](https://github.com/ToiCF/CF-Workers-TURN)
- [ToiCF/CF-Workers-SoftEther](https://github.com/ToiCF/CF-Workers-SoftEther)
- [eooce](https://github.com/eooce/Cloudflare-proxy)
- [Sukka](https://ip.skk.moe/)
- [zhangtaile](https://github.com/cmliu/edgetunnel/pull/999)
- [1345695](https://github.com/1345695/edcloudwasm)
- [ToiCF/GrainTCP](https://github.com/ToiCF/GrainTCP)

---

## ⚠️ Disclaimer

1. This project ("edgetunnel") is intended solely for **educational, scientific research, and personal safety testing** purposes.
2. Users must strictly comply with the laws and regulations of their region when downloading or using the code of this project.
3. The author, **cmliu**, assumes no responsibility for any actions or consequences resulting from the misuse of the code in this project.
4. This project is not liable for any direct or indirect damages arising from the use of the code.
5. It is recommended to delete the relevant deployments of this project within 24 hours after the test is completed.

---

If you found this project helpful, please give it a Star 🌟 – it's my biggest encouragement!
