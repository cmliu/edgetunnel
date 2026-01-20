# 🚀 edgetunnel 2.0
![后台页面](./img.png)

[![Stars](https://img.shields.io/github/stars/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/stargazers)
[![Forks](https://img.shields.io/github/forks/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/network/members)
[![License](https://img.shields.io/github/license/cmliu/edgetunnel?style=flat-square)](https://github.com/cmliu/edgetunnel/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Group-blue?style=flat-square&logo=telegram)](https://t.me/CMLiussss)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-red?style=flat-square&logo=youtube)](https://www.youtube.com/watch?v=LeT4jQUh8ok)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cmliu/edgetunnel)
---

## 📖 项目简介

**edgetunnel** 是一个基于 CF Workers/Pages 平台的边缘计算隧道解密方案。它能够高效地处理网络流量，并提供强大的管理面板和灵活的节点配置能力。

- 🖥️ **Demo 演示站点**：[https://EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

### ✨ 核心特性

- 🛡️ **协议支持**：支持 VLESS、Trojan 等主流协议，深度集成加密传输。
- 📊 **管理面板**：内置可视化后台，支持实时配置修改、日志查看及流量统计。
- 🛠️ **部署灵活**：完整适配 CF Workers 及 CF Pages (GitHub / 上传)。
- 🔄 **订阅系统**：内置自动订阅生成及混淆转换，适配主流客户端（Clash, Sing-box, Surge 等）。
- ⚡ **性能加速**：支持自定义 ProxyIP、SOCKS5/HTTP 链式代理及优选 API，优化网络延迟。
- 🌐 **多台适配**：完美适配 Windows, Android, iOS, MacOS 及各种软路由固件。

---

## 💡 快速部署
>[!TIP]
> 📖 **详尽图文教程**：[edgetunnel 部署指南](https://cmliussss.com/p/edt2/)

>[!WARNING]
> ⚠️ **Error 1101问题**：[视频解析](https://www.youtube.com/watch?v=r4uVTEJptdE)

### ⚙️ Workers 部署

<details>
<summary><code><strong>「 Workers 部署文字教程 」</strong></code></summary>

1. 部署 CF Worker：
   - 在 CF Worker 控制台中创建一个新的 Worker。
   - 将 [worker.js](https://github.com/cmliu/edgetunnel/blob/main/_worker.js) 的内容粘贴到 Worker 编辑器中。
   - 在左侧的 `设置`选项卡中，选择 `变量` > `添加变量`。
     变量名称填写**ADMIN**，值则为你的管理员密码，后点击 `保存`即可。

2. 绑定 KV 命名空间：
   - 在 `绑定`选项卡中选择 `添加绑定 +` > `KV 命名空间` > `添加绑定`，然后选择一个已有的命名空间或创建一个新的命名空间进行绑定。
   - `变量名称`填写**KV**，然后点击 `添加绑定`即可。

3. 给 Workers绑定 自定义域： 
   - 在 workers控制台的 `触发器`选项卡，下方点击 `添加自定义域`。
   - 填入你已转入 CF 域名解析服务的次级域名，例如:`vless.google.com`后 点击`添加自定义域`，等待证书生效即可。

4. 访问后台：
   - 访问 `https://vless.google.com/admin` 输入管理员密码即可登录后台。

</details>

### 🛠 Pages 上传 部署方法 **最佳推荐!!!** [图文教程](https://cmliussss.com/p/edt2/)

<details>
<summary><code><strong>「 Pages 上传文件部署文字教程 」</strong></code></summary>

1. 部署 CF Pages：
   - 下载 [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) 文件，并点上 Star !!!
   - 在 CF Pages 控制台中选择 `上传资产`后，为你的项目取名后点击 `创建项目`，然后上传你下载好的 [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) 文件后点击 `部署站点`。
   - 部署完成后点击 `继续处理站点` 后，选择 `设置` > `环境变量` > **制作**为生产环境定义变量 > `添加变量`。
     变量名称填写**ADMIN**，值则为你的管理员密码，后点击 `保存`即可。
   - 返回 `部署` 选项卡，在右下角点击 `创建新部署` 后，重新上传 [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) 文件后点击 `保存并部署` 即可。

2. 绑定 KV 命名空间：
   - 在 `设置`选项卡中选择 `绑定` > `+ 添加` > `KV 命名空间`，然后选择一个已有的命名空间或创建一个新的命名空间进行绑定。
   - `变量名称`填写**KV**，然后点击 `保存`后重试部署即可。

3. 给 Pages绑定 CNAME自定义域：[视频教程](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - 在 Pages控制台的 `自定义域`选项卡，下方点击 `设置自定义域`。
   - 填入你的自定义次级域名，注意不要使用你的根域名，例如：
     您分配到的域名是 `fuck.cloudns.biz`，则添加自定义域填入 `lizi.fuck.cloudns.biz`即可；
   - 按照 CF 的要求将返回你的域名DNS服务商，添加 该自定义域 `lizi`的 CNAME记录 `edgetunnel.pages.dev` 后，点击 `激活域`即可。
   
4. 访问后台：
   - 访问 `https://lizi.fuck.cloudns.biz/admin` 输入管理员密码即可登录后台。

</details>

### 🛠 Pages + GitHub 部署方法

<details>
<summary><code><strong>「 Pages + GitHub 部署文字教程 」</strong></code></summary>

1. 部署 CF Pages：
   - 在 Github 上先 Fork 本项目，并点上 Star !!!
   - 在 CF Pages 控制台中选择 `连接到 Git`后，选中 `edgetunnel`项目后点击 `开始设置`。
   - 在 `设置构建和部署`页面下方，选择 `环境变量（高级）`后并 `添加变量`
     变量名称填写**ADMIN**，值则为你的管理员密码，后点击 `保存并部署`即可。

2. 绑定 KV 命名空间：
   - 在 `设置`选项卡中选择 `绑定` > `+ 添加` > `KV 命名空间`，然后选择一个已有的命名空间或创建一个新的命名空间进行绑定。
   - `变量名称`填写**KV**，然后点击 `保存`后重试部署即可。

3. 给 Pages绑定 CNAME自定义域：[视频教程](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - 在 Pages控制台的 `自定义域`选项卡，下方点击 `设置自定义域`。
   - 填入你的自定义次级域名，注意不要使用你的根域名，例如：
     您分配到的域名是 `fuck.cloudns.biz`，则添加自定义域填入 `lizi.fuck.cloudns.biz`即可；
   - 按照 CF 的要求将返回你的域名DNS服务商，添加 该自定义域 `lizi`的 CNAME记录 `edgetunnel.pages.dev` 后，点击 `激活域`即可。

4. 访问后台：
   - 访问 `https://lizi.fuck.cloudns.biz/admin` 输入管理员密码即可登录后台。

</details>

---

## 🔑 环境变量说明

| 变量名 | 必填 | 示例 | 详细备注 |
| :--- | :---: | :--- | :--- |
| **ADMIN** | ✅ | `123456` | 后台管理面板登录密码 |
| **KEY** | ❌ | `CMLiussss` | 快速订阅路径密钥，访问 `/CMLiussss` 即可快速获取节点 |
| **UUID** | ❌ | `90cd4a77-141a-43c9-991b-08263cfe9c10` | 强制固定UUID |
| **HOST** | ❌ | `edt.pages.dev` | 强制固定伪装域名 |
| **PATH** | ❌ | `/` | 强制固定伪装路径 |
| **PROXYIP** | ❌ | `proxyip.cmliussss.net:443` | 全局自定义反代 IP  |
| **URL** | ❌ | `https://cloudflare-error-page-3th.pages.dev` | 默认主页伪装地址（可填写网页 URL 或 `1101`） |
| **GO2SOCKS5** | ❌ | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` | 强制走 SOCKS5 的名单 (`*` 为全局，域名用逗号分隔) |
| **DOH** | ❌ | `https://doh.cmliussss.com/CMLiussss` | 用于解析ECH的DoH服务器 |

---

## 🔧 高级实用技巧

本工具支持通过 **PATH路径** 动态切换底层代理方案：

- 指定 `PROXYIP` 案例
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   /proxyip.cmliussss.net (仅限于域名开头为'proxyip.'的域名)
   ```

- 指定 `SOCKS5` 案例
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (默认激活全局SOCKS5)
   /socks5://user:password@127.0.0.1:1080 (默认激活全局SOCKS5)
   ```

- 指定 `HTTP代理` 案例
   ```url
   /http=user:password@127.0.0.1:1080
   /http://user:password@127.0.0.1:8080 (默认激活全局SOCKS5)
   ```

---

## 💻 客户端适配情况

| 平台 | 推荐客户端 | 备注 |
| :--- | :--- | :--- |
| **Windows** | [v2rayN](https://github.com/2dust/v2rayN), [FlClash](https://github.com/chen08209/FlClash), [mihomo-party](https://github.com/mihomo-party-org/mihomo-party), [Clash Verge Rev](https://github.com/ClashVerge/ClashVerge-Rev) | 全面支持 |
| **Android** | [ClashMetaForAndroid](https://github.com/chen08209/ClashMetaForAndroid), [FlClash](https://github.com/chen08209/FlClash), [v2rayNG](https://github.com/2dust/v2rayNG) | 建议使用 Meta 核心 |
| **iOS** | [Surge](https://surgeapp.com/), [Shadowrocket](https://shadowrocket.com/), [Stash](https://stashapp.com/) | 完美适配 |
| **MacOS** | [FlClash](https://github.com/chen08209/FlClash), [mihomo-party](https://github.com/mihomo-party-org/mihomo-party), [Clash Verge Rev](https://github.com/ClashVerge/ClashVerge-Rev), [Surge](https://surgeapp.com/) | M1/M2 完美兼容 |

---

## ⭐ 项目热度

[![Stargazers over time](https://starchart.cc/cmliu/edgetunnel.svg?variant=adaptive)](https://starchart.cc/cmliu/edgetunnel)

---

## 🙏 特别鸣谢
### 💖 赞助支持 - 提供云服务器维持[订阅转换服务](https://sub.cmliussss.net/)
- [NodeLoc](https://www.nodeloc.com/)
- [Alice](https://url.cmliussss.com/alice)
- [EasyLinks](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)
- [ZMTO(VTEXS)](https://zmto.com/?affid=1532)

### 🛠 开源代码引用
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [股神](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [白嫖哥](https://t.me/bestcfipas)
- [Mingyu](https://github.com/ymyuuu/workers-vless)
- [Alexandre Kojève](https://t.me/Enkelte_notif/784)
- [eooce](https://github.com/eooce/Cloudflare-proxy)
- [Sukka](https://ip.skk.moe/)

---

## ⚠️ 免责声明

1. 本项目（"edgetunnel"）仅供**教育、科学研究及个人安全测试**之目的。
2. 使用者在下载或使用本项目代码时，必须严格遵守所在地区的法律法规。
3. 作者 **cmliu** 对任何滥用本项目代码导致的行为或后果均不承担任何责任。
4. 本项目不对因使用代码引起的任何直接或间接损害负责。
5. 建议在测试完成后 24 小时内删除本项目相关部署。

---

**如果您觉得项目对您有帮助，请给一个 Star 🌟，这是对我最大的鼓励！**