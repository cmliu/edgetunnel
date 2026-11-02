# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目性质

edgetunnel：运行在 Cloudflare Workers / Pages 上的单文件代理隧道（VLESS / Trojan / Shadowsocks，WS / gRPC / XHTTP 传输）+ 订阅生成 + 管理后台。全部逻辑在 [_worker.js](_worker.js) 一个文件里，没有 package.json、没有依赖、没有构建步骤、没有测试。用户的部署方式是把 `_worker.js` 直接粘贴进 CF Worker，或把整个仓库 zip 上传到 CF Pages —— 所以**必须保持单文件、无 import、无构建产物**。

## 常用命令

```powershell
node --check _worker.js        # 唯一可用的本地校验：语法检查
npx wrangler dev               # 本地运行（wrangler.toml: main=_worker.js；需自行在 wrangler.toml 打开 KV 绑定）
```

`wrangler.toml` 的 `name` 和 `compatibility_date` 随版本更新（如 `v20251104`），`keep_vars = true` 用于保留控制台里配置的变量。

## _worker.js 结构

约 33k 行，但**只有前约 6650 行是代码**；之后是一大段希伯来文圣经文本的块注释（`/* ... */`，到文件末尾），用于稀释特征，不要删除或改动，搜索/读取时跳过它。代码按 `////////…标题////////` 分隔：

| 行（约） | 段落 | 说明 |
| --- | --- | --- |
| 1–16 | 全局常量 / 查杀特征码 | `Version` 常量（发版时更新，格式 `YYYY-MM-DD HH:MM:SS`，`EDT_版本号` 由它派生）；敏感字符串（如 `PROXYIP`、作者名）用运行时拼接生成，不写字面量 |
| 17–530 | `export default { fetch }` | 全部路由：`/version`、WebSocket 升级→`处理WS请求`、POST 非 admin→gRPC 或 XHTTP、`/<KEY>` 快速订阅、`/login`、`/admin/*`（GET 读、POST 存配置）、`/sub` 订阅、`/locations`，其余走 `URL` 变量伪装/反代或 nginx/1101 伪装页 |
| 531–1290 | 叉HTTP(XHTTP) / gRPC 传输 | |
| 1290–3134 | WS 传输 + 协议解析 + 转发核心 | 木马(Trojan)/魏烈思(VLESS)/SS 解析，`forwardataTCP` / `forwardataudp`，上行合包队列与下行 Grain 发送器 |
| 3134–4744 | 出站代理 | SOCKS5 / HTTP / HTTPS 代理、纯 JS 实现的 TLS 客户端、TURN、SSTP |
| 4744–6524 | 功能性函数 | Clash / Sing-box / Surge 订阅热补丁、KV 日志、DoH、`读取config_JSON`、优选 API、`反代参数获取`（解析路径里的 `/proxyip=`、`/socks5=` 等）、CF 用量查询 |
| 6524–6645 | HTML 伪装页 | `nginx()`、`html1101()` |

关键约定：
- 标识符大量使用中文命名，协议名也用谐音规避（`木马`=Trojan，`魏烈思`=VLESS，`叉HTTP`=XHTTP），新代码沿用这一风格，同样不要引入协议名明文字面量。
- 缩进用 Tab。
- 管理后台和登录页的前端 **不在本仓库**：Worker 从 `Pages静态页面`（https://edt-pages.github.io）拉取 `/admin`、`/login`、`/noADMIN`、`/noKV` 页面再返回。改前端交互需要去那个仓库。
- 身份：`管理员密码` 取 `ADMIN` 等多个变量回退；`userID` 优先用合法的 `UUID` 变量，否则由 `MD5MD5(管理员密码 + KEY)` 派生成 UUIDv4。改这里会让所有已发出的订阅/节点失效。
- 持久化全靠 KV 绑定（变量名固定为 `KV`）：`config.json`（主配置，由 `读取config_JSON` 读取并补默认值）、`cf.json`、`tg.json`、`ADD.txt`（自定义优选 IP）、`log.json`。没绑 KV 时后台返回 `/noKV` 页。
- 环境变量（`ADMIN`、`KEY`、`UUID`、`PROXYIP`、`URL`、`GO2SOCKS5`、`DEBUG`、`OFF_LOG`、`BEST_SUB`、`PRELOAD_RACE_DIAL`、`TCP_CONCURRENT_DIAL`、`PROXY_CONCURRENT_DIAL`、`HOST` 等）含义见 [README.md](README.md) 的「环境变量说明」表。
- 调试输出用 `log()`（仅 `DEBUG=1/true` 时打印），不要直接 `console.log`。

## 发版习惯

改动记录写在 [CHANGELOG](CHANGELOG)（无扩展名），版本号格式 `[2.1.<YYYYMMDDHHMMSS>] - <日期时间>`，分 `ADD` / `Change` / `Debug` 小节，条目用 `- 新增/优化/修复 **功能名**：说明。`。同时更新 `_worker.js` 首行的 `Version`。

## 仓库 CI

- `.github/workflows/sync.yml`：fork 仓库每日自动同步上游。
- `.github/workflows/Auto-close-empty-PRs.yml`：PR 描述去掉空白和 HTML 注释后不超过 8 个字符会被自动关闭 —— 提 PR 必须写清改了什么、为什么。
