
import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
let DNS64Server = '';
//let sub = '';
let subConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
let enableHttp = false;
let noTLS = 'false';
const expire = 4102329600;//2099-12-31
let proxyIPs;
let socks5s;
let go2Socks5s = [
    '*ttvnw.net',
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
];
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;//CSV备注所在列偏移量
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2NtbGl1L2NtbGl1L21haW4vUHJveHlIT1NU');
let RproxyIP = 'false';
const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let 有效时间 = 7;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = '/?ed=2560';
let 动态UUID = userID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';
export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                动态UUID = env.KEY || env.TOKEN || userID;
                有效时间 = Number(env.TIME) || 有效时间;
                更新时间 = Number(env.UPTIME) || 更新时间;
                const userIDs = await 生成动态UUID(动态UUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            } else 动态UUID = userID;

            if (!userID) {
                return new Response('请设置你的UUID变量，或尝试重试部署，检查变量是否生效？', {
                    status: 404,
                    headers: {
                        "Content-Type": "text/plain;charset=utf-8",
                    }
                });
            }
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const fakeUserIDMD5 = await 双重哈希(`${userID}${timestamp}`);
            const fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20)
            ].join('-');

            const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await 整理(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            DNS64Server = env.DNS64 || env.NAT64 || DNS64Server;
            socks5Address = env.HTTP || env.SOCKS5 || socks5Address;
            socks5s = await 整理(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            enableHttp = env.HTTP ? true : socks5Address.toLowerCase().includes('http://');
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);
            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    RproxyIP = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    let e = err;
                    console.log(e.toString());
                    RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
            }

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await 整理(env.ADD);
                if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                ChatID = env.TGID || ChatID;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == '0') subEmoji = 'false';
                if (env.LINK) link = await 整理(env.LINK);
                let sub = env.SUB || '';
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = 'http';
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub').toLowerCase();
                if (url.searchParams.has('notls')) noTLS = 'true';

                if (url.searchParams.has('proxyip')) {
                    path = `/proxyip=${url.searchParams.get('proxyip')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks5')) {
                    path = `/?socks5=${url.searchParams.get('socks5')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks')) {
                    path = `/?socks5=${url.searchParams.get('socks')}`;
                    RproxyIP = 'false';
                }

                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';
                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response(await nginx(), {
                        status: 200,
                        headers: {
                            'Content-Type': 'text/html; charset=UTF-8',
                        },
                    });
                } else if (路径 == `/${fakeUserID}`) {
                    const fakeConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, fakeUserID, fakeHostName, env);
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if (url.pathname == `/${动态UUID}/edit` || 路径 == `/${userID}/edit`) {
                    return await KV(request, env);
                } else if (url.pathname == `/${动态UUID}/bestip` || 路径 == `/${userID}/bestip`) {
                    return await bestIP(request, env);
                } else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {
                    await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                    const 维列斯Config = await 生成配置信息(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env);
                    const now = Date.now();
                    //const timestamp = Math.floor(now / 1000);
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;
                    if ((env.CF_EMAIL && env.CF_APIKEY) || (env.CF_ID && env.CF_APITOKEN)) {
                        const usage = await getUsage(env.CF_ID, env.CF_EMAIL, env.CF_APIKEY, env.CF_APITOKEN, env.CF_ALL);
                        pagesSum = usage[1];
                        workersSum = usage[2];
                        total = env.CF_ALL ? Number(env.CF_ALL) : (1024 * 100); // 100K
                    }
                    if (userAgent && userAgent.includes('mozilla')) {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                                //"Content-Type": "text/plain;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            }
                        });
                    }
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response('不用怀疑！你UUID就是错的！！！', { status: 404 });
                }
            } else {
                socks5Address = url.searchParams.get('socks5') || socks5Address;
                if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
                else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname) || new RegExp('/http://', 'i').test(url.pathname)) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        const lastAtIndex = socks5Address.lastIndexOf('@');
                        let userPassword = socks5Address.substring(0, lastAtIndex).replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.substring(lastAtIndex + 1)}`;
                    }
                    go2Socks5s = ['all in'];//开启全局SOCKS5
                }

                if (socks5Address) {
                    try {
                        parsedSocks5Address = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        let e = err;
                        console.log(e.toString());
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                if (url.searchParams.has('proxyip')) {
                    proxyIP = url.searchParams.get('proxyip');
                    enableSocks = false;
                } else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
                    enableSocks = false;
                } else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
                    proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
                    enableSocks = false;
                } else if (new RegExp('/pyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
                    enableSocks = false;
                }

                return await 维列斯OverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    },
};

async function 维列斯OverWSHandler(request) {

    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    // 接受 WebSocket 连接
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    // 日志函数，用于记录连接信息
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    // 获取早期数据头部，可能包含了一些初始化数据
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    // 创建一个可读的 WebSocket 流，用于接收客户端数据
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    // 用于存储远程 Socket 的包装器
    let remoteSocketWapper = {
        value: null,
    };
    // 标记是否为 DNS 查询
    let udpStreamWrite = null;
    let isDns = false;

    // WebSocket 数据流向远程服务器的管道
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                // 如果是 DNS 查询，调用 DNS 处理函数
                //return await handleDNSQuery(chunk, webSocket, null, log);
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                // 如果已有远程 Socket，直接写入数据
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // 处理 维列斯 协议头部
            const {
                hasError,
                message,
                addressType,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                维列斯Version = new Uint8Array([0, 0]),
                isUDP,
            } = process维列斯Header(chunk, userID);
            // 设置地址和端口信息，用于日志
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
            if (hasError) {
                // 如果有错误，抛出异常
                throw new Error(message);
                return;
            }
            // 如果是 UDP 且端口不是 DNS 端口（53），则关闭连接
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    throw new Error('UDP 代理仅对 DNS（53 端口）启用');
                    return;
                }
            }
            // 构建 维列斯 响应头部
            const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
            // 获取实际的客户端数据
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                // 如果是 DNS 查询，调用 DNS 处理函数
                //return handleDNSQuery(rawClientData, webSocket, 维列斯ResponseHeader, log);
                const { write } = await handleUDPOutBound(webSocket, 维列斯ResponseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }
            // 处理 TCP 出站连接
            if (!banHosts.includes(addressRemote)) {
                log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
                handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
            } else {
                throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
            }
        },
        close() {
            log(`readableWebSocketStream 已关闭`);
        },
        abort(reason) {
            log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream 管道错误', err);
    });

    // 返回一个 WebSocket 升级的响应
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log,) {
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false, http = false) {
        log(`connected to ${address}:${port}`);
        //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
        // 先确定连接方式，再创建连接
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port, log) : await socks5Connect(addressType, address, port, log))
            : connect({ hostname: address, port: port });

        remoteSocket.value = tcpSocket;
        //log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        // 首次写入，通常是 TLS 客户端 Hello 消息
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function nat64() {
        if (!useSocks) {
            const nat64Proxyip = `[${await resolveToIPv6(addressRemote)}]`;
            log(`NAT64 代理连接到 ${nat64Proxyip}:443`);
            tcpSocket = await connectAndWrite(nat64Proxyip, 443);
        }
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
    }

    /**
     * 重试函数：当 Cloudflare 的 TCP Socket 没有传入数据时，我们尝试重定向 IP
     * 这可能是因为某些网络问题导致的连接失败
     */
    async function retry() {
        if (enableSocks) {
            // 如果启用了 SOCKS5，通过 SOCKS5 代理重试连接
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            // 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
            if (!proxyIP || proxyIP == '') {
                proxyIP = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==');
            } else if (proxyIP.includes(']:')) {
                portRemote = proxyIP.split(']:')[1] || portRemote;
                proxyIP = proxyIP.split(']:')[0] + "]" || proxyIP;
            } else if (proxyIP.split(':').length === 2) {
                portRemote = proxyIP.split(':')[1] || portRemote;
                proxyIP = proxyIP.split(':')[0] || proxyIP;
            }
            if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIP.toLowerCase() || addressRemote, portRemote);
        }
        /* 无论重试是否成功，都要关闭 WebSocket（可能是为了重新建立连接）
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        */
        // 建立从远程 Socket 到 WebSocket 的数据流
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, nat64, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    // 首次尝试连接远程服务器
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);

    // 当远程 Socket 就绪时，将其传递给 WebSocket
    // 建立从远程服务器到 WebSocket 的数据流，用于将远程服务器的响应发送回客户端
    // 如果连接失败或无数据，retry 函数将被调用进行重试
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    // 标记可读流是否已被取消
    let readableStreamCancel = false;

    // 创建一个新的可读流
    const stream = new ReadableStream({
        // 当流开始时的初始化函数
        start(controller) {
            // 监听 WebSocket 的消息事件
            webSocketServer.addEventListener('message', (event) => {
                // 如果流已被取消，不再处理新消息
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                // 将消息加入流的队列中
                controller.enqueue(message);
            });

            // 监听 WebSocket 的关闭事件
            // 注意：这个事件意味着客户端关闭了客户端 -> 服务器的流
            // 但是，服务器 -> 客户端的流仍然打开，直到在服务器端调用 close()
            // WebSocket 协议要求在每个方向上都要发送单独的关闭消息，以完全关闭 Socket
            webSocketServer.addEventListener('close', () => {
                // 客户端发送了关闭信号，需要关闭服务器端
                safeCloseWebSocket(webSocketServer);
                // 如果流未被取消，则关闭控制器
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            // 监听 WebSocket 的错误事件
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket 服务器发生错误');
                // 将错误传递给控制器
                controller.error(err);
            });

            // 处理 WebSocket 0-RTT（零往返时间）的早期数据
            // 0-RTT 允许在完全建立连接之前发送数据，提高了效率
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                // 如果解码早期数据时出错，将错误传递给控制器
                controller.error(error);
            } else if (earlyData) {
                // 如果有早期数据，将其加入流的队列中
                controller.enqueue(earlyData);
            }
        },

        // 当使用者从流中拉取数据时调用
        pull(controller) {
            // 这里可以实现反压机制
            // 如果 WebSocket 可以在流满时停止读取，我们就可以实现反压
            // 参考：https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        // 当流被取消时调用
        cancel(reason) {
            // 流被取消的几种情况：
            // 1. 当管道的 WritableStream 有错误时，这个取消函数会被调用，所以在这里处理 WebSocket 服务器的关闭
            // 2. 如果 ReadableStream 被取消，所有 controller.close/enqueue 都需要跳过
            // 3. 但是经过测试，即使 ReadableStream 被取消，controller.error 仍然有效
            if (readableStreamCancel) {
                return;
            }
            log(`可读流被取消，原因是 ${reason}`);
            readableStreamCancel = true;
            // 安全地关闭 WebSocket
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// https://xtls.github.io/development/protocols/维列斯.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 解析 维列斯 协议的头部数据
 * @param { ArrayBuffer} 维列斯Buffer 维列斯 协议的原始头部数据
 * @param {string} userID 用于验证的用户 ID
 * @returns {Object} 解析结果，包括是否有错误、错误信息、远程地址信息等
 */
function process维列斯Header(维列斯Buffer, userID) {
    // 检查数据长度是否足够（至少需要 24 字节）
    if (维列斯Buffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }

    // 解析 维列斯 协议版本（第一个字节）
    const version = new Uint8Array(维列斯Buffer.slice(0, 1));

    let isValidUser = false;
    let isUDP = false;

    // 验证用户 ID（接下来的 16 个字节）
    function isUserIDValid(userID, userIDLow, buffer) {
        const userIDArray = new Uint8Array(buffer.slice(1, 17));
        const userIDString = stringify(userIDArray);
        return userIDString === userID || userIDString === userIDLow;
    }

    // 使用函数验证
    isValidUser = isUserIDValid(userID, userIDLow, 维列斯Buffer);

    // 如果用户 ID 无效，返回错误
    if (!isValidUser) {
        return {
            hasError: true,
            message: `invalid user ${(new Uint8Array(维列斯Buffer.slice(1, 17)))}`,
        };
    }

    // 获取附加选项的长度（第 17 个字节）
    const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
    // 暂时跳过附加选项

    // 解析命令（紧跟在选项之后的 1 个字节）
    // 0x01: TCP, 0x02: UDP, 0x03: MUX（多路复用）
    const command = new Uint8Array(
        维列斯Buffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
        // TCP 命令，不需特殊处理
    } else if (command === 2) {
        // UDP 命令
        isUDP = true;
    } else {
        // 不支持的命令
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }

    // 解析远程端口（大端序，2 字节）
    const portIndex = 18 + optLength + 1;
    const portBuffer = 维列斯Buffer.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    // 解析地址类型和地址
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        维列斯Buffer.slice(addressIndex, addressIndex + 1)
    );

    // 地址类型：1-IPv4(4字节), 2-域名(可变长), 3-IPv6(16字节)
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            // IPv4 地址
            addressLength = 4;
            // 将 4 个字节转为点分十进制格式
            addressValue = new Uint8Array(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            // 域名
            // 第一个字节是域名长度
            addressLength = new Uint8Array(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            // 解码域名
            addressValue = new TextDecoder().decode(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            // IPv6 地址
            addressLength = 16;
            const dataView = new DataView(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            // 每 2 字节构成 IPv6 地址的一部分
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            // seems no need add [] for ipv6
            break;
        default:
            // 无效的地址类型
            return {
                hasError: true,
                message: `invild addressType is ${addressType}`,
            };
    }

    // 确保地址不为空
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    // 返回解析结果
    return {
        hasError: false,
        addressRemote: addressValue,  // 解析后的远程地址
        addressType,				 // 地址类型
        portRemote,				 // 远程端口
        rawDataIndex: addressValueIndex + addressLength,  // 原始数据的实际起始位置
        维列斯Version: version,	  // 维列斯 协议版本
        isUDP,					 // 是否是 UDP 请求
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
    // 将数据从远程服务器转发到 WebSocket
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let 维列斯Header = 维列斯ResponseHeader;
    let hasIncomingData = false; // 检查远程 Socket 是否有传入数据

    // 使用管道将远程 Socket 的可读流连接到一个可写流
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                    // 初始化时不需要任何操作
                },
                /**
                 * 处理每个数据块
                 * @param {Uint8Array} chunk 数据块
                 * @param {*} controller 控制器
                 */
                async write(chunk, controller) {
                    hasIncomingData = true; // 标记已收到数据
                    // remoteChunkCount++; // 用于流量控制，现在似乎不需要了

                    // 检查 WebSocket 是否处于开放状态
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe close'
                        );
                    }

                    if (维列斯Header) {
                        // 如果有 维列斯 响应头部，将其与第一个数据块一起发送
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null; // 清空头部，之后不再发送
                    } else {
                        // 直接发送数据块
                        // 以前这里有流量控制代码，限制大量数据的发送速率
                        // 但现在 Cloudflare 似乎已经修复了这个问题
                        // if (remoteChunkCount > 20000) {
                        // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // 	await delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    // 当远程连接的可读流关闭时
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // 不需要主动关闭 WebSocket，因为这可能导致 HTTP ERR_CONTENT_LENGTH_MISMATCH 问题
                    // 客户端无论如何都会发送关闭事件
                    // safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                    // 当远程连接的可读流中断时
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            // 捕获并记录任何异常
            console.error(
                `remoteSocketToWS has exception `,
                error.stack || error
            );
            // 发生错误时安全地关闭 WebSocket
            safeCloseWebSocket(webSocket);
        });

    // 处理 Cloudflare 连接 Socket 的特殊错误情况
    // 1. Socket.closed 将有错误
    // 2. Socket.readable 将关闭，但没有任何数据
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry(); // 调用重试函数，尝试重新建立连接
    }
}

/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer
 * 
 * @param {string} base64Str Base64 编码的输入字符串
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} 返回解码后的 ArrayBuffer 或错误
 */
function base64ToArrayBuffer(base64Str) {
    // 如果输入为空，直接返回空结果
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        // Go 语言使用了 URL 安全的 Base64 变体（RFC 4648）
        // 这种变体使用 '-' 和 '_' 来代替标准 Base64 中的 '+' 和 '/'
        // JavaScript 的 atob 函数不直接支持这种变体，所以我们需要先转换
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');

        // 使用 atob 函数解码 Base64 字符串
        // atob 将 Base64 编码的 ASCII 字符串转换为原始的二进制字符串
        const decode = atob(base64Str);

        // 将二进制字符串转换为 Uint8Array
        // 这是通过遍历字符串中的每个字符并获取其 Unicode 编码值（0-255）来完成的
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));

        // 返回 Uint8Array 的底层 ArrayBuffer
        // 这是实际的二进制数据，可以用于网络传输或其他二进制操作
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        // 如果在任何步骤中出现错误（如非法 Base64 字符），则返回错误
        return { earlyData: undefined, error };
    }
}

/**
 * 这不是真正的 UUID 验证，而是一个简化的版本
 * @param {string} uuid 要验证的 UUID 字符串
 * @returns {boolean} 如果字符串匹配 UUID 格式则返回 true，否则返回 false
 */
function isValidUUID(uuid) {
    // 定义一个正则表达式来匹配 UUID 格式
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    // 使用正则表达式测试 UUID 字符串
    return uuidRegex.test(uuid);
}

// WebSocket 的两个重要状态常量
const WS_READY_STATE_OPEN = 1;	 // WebSocket 处于开放状态，可以发送和接收消息
const WS_READY_STATE_CLOSING = 2;  // WebSocket 正在关闭过程中

function safeCloseWebSocket(socket) {
    try {
        // 只有在 WebSocket 处于开放或正在关闭状态时才调用 close()
        // 这避免了在已关闭或连接中的 WebSocket 上调用 close()
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        // 记录任何可能发生的错误，虽然按照规范不应该有错误
        console.error('safeCloseWebSocket error', error);
    }
}

// 预计算 0-255 每个字节的十六进制表示
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    // (i + 256).toString(16) 确保总是得到两位数的十六进制
    // .slice(1) 删除前导的 "1"，只保留两位十六进制数
    byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * 快速地将字节数组转换为 UUID 字符串，不进行有效性检查
 * 这是一个底层函数，直接操作字节，不做任何验证
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} UUID 字符串
 */
function unsafeStringify(arr, offset = 0) {
    // 直接从查找表中获取每个字节的十六进制表示，并拼接成 UUID 格式
    // 8-4-4-4-12 的分组是通过精心放置的连字符 "-" 实现的
    // toLowerCase() 确保整个 UUID 是小写的
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

/**
 * 将字节数组转换为 UUID 字符串，并验证其有效性
 * 这是一个安全的函数，它确保返回的 UUID 格式正确
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} 有效的 UUID 字符串
 * @throws {TypeError} 如果生成的 UUID 字符串无效
 */
function stringify(arr, offset = 0) {
    // 使用不安全的函数快速生成 UUID 字符串
    const uuid = unsafeStringify(arr, offset);
    // 验证生成的 UUID 是否有效
    if (!isValidUUID(uuid)) {
        // 原：throw TypeError("Stringified UUID is invalid");
        throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
        //uuid = userID;
    }
    return uuid;
}

/**
 * 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} 维列斯ResponseHeader 
 * @param {(string)=> void} log 
 */
async function handleUDPOutBound(webSocket, 维列斯ResponseHeader, log) {

    let is维列斯HeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {

        },
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPakcetLength)
                );
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    // only handle dns udp for now
    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query',
                {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                log(`doh success and dns message length is ${udpSize}`);
                if (is维列斯HeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([维列斯ResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    is维列斯HeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log('dns udp has error' + error)
    });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         * 
         * @param {Uint8Array} chunk 
         */
        write(chunk) {
            writer.write(chunk);
        }
    };
}

/**
 * 处理 DNS 查询的函数
 * @param {ArrayBuffer} udpChunk - 客户端发送的 DNS 查询数据
 * @param {ArrayBuffer} 维列斯ResponseHeader - 维列斯 协议的响应头部数据
 * @param {(string)=> void} log - 日志记录函数
 */
async function handleDNSQuery(udpChunk, webSocket, 维列斯ResponseHeader, log) {
    // 无论客户端发送到哪个 DNS 服务器，我们总是使用硬编码的服务器
    // 因为有些 DNS 服务器不支持 DNS over TCP
    try {
        // 选用 Google 的 DNS 服务器（注：后续可能会改为 Cloudflare 的 1.1.1.1）
        const dnsServer = '8.8.4.4'; // 在 Cloudflare 修复连接自身 IP 的 bug 后，将改为 1.1.1.1
        const dnsPort = 53; // DNS 服务的标准端口

        let 维列斯Header = 维列斯ResponseHeader; // 保存 维列斯 响应头部，用于后续发送

        // 与指定的 DNS 服务器建立 TCP 连接
        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`连接到 ${dnsServer}:${dnsPort}`); // 记录连接信息
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk); // 将客户端的 DNS 查询数据发送给 DNS 服务器
        writer.releaseLock(); // 释放写入器，允许其他部分使用

        // 将从 DNS 服务器接收到的响应数据通过 WebSocket 发送回客户端
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (维列斯Header) {
                        // 如果有 维列斯 头部，则将其与 DNS 响应数据合并后发送
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null; // 头部只发送一次，之后置为 null
                    } else {
                        // 否则直接发送 DNS 响应数据
                        webSocket.send(chunk);
                    }
                }
            },
            close() {
                log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`); // 记录连接关闭信息
            },
            abort(reason) {
                console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason); // 记录异常中断原因
            },
        }));
    } catch (error) {
        // 捕获并记录任何可能发生的错误
        console.error(
            `handleDNSQuery 函数发生异常，错误信息: ${error.message}`
        );
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 2: 域名, 3: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    // 连接到 SOCKS5 代理服务器
    const socket = connect({
        hostname, // SOCKS5 服务器的主机名
        port,	// SOCKS5 服务器的端口
    });

    // 请求头格式（Worker -> SOCKS5 服务器）:
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |	1	 | 1 to 255 |
    // +----+----------+----------+

    // https://en.wikipedia.org/wiki/SOCKS#SOCKS5
    // METHODS 字段的含义:
    // 0x00 不需要认证
    // 0x02 用户名/密码认证 https://datatracker.ietf.org/doc/html/rfc1929
    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    // 5: SOCKS5 版本号, 2: 支持的认证方法数, 0和2: 两种认证方法（无认证和用户名/密码）

    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    log('已发送 SOCKS5 问候消息');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;
    // 响应格式（SOCKS5 服务器 -> Worker）:
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1	|
    // +----+--------+
    if (res[0] !== 0x05) {
        log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("服务器不接受任何认证方法");
        return;
    }

    // 如果返回 0x0502，表示需要用户名/密码认证
    if (res[1] === 0x02) {
        log("SOCKS5 服务器需要认证");
        if (!username || !password) {
            log("请提供用户名和密码");
            return;
        }
        // 认证请求格式:
        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        const authRequest = new Uint8Array([
            1,				   // 认证子协议版本
            username.length,	// 用户名长度
            ...encoder.encode(username), // 用户名
            password.length,	// 密码长度
            ...encoder.encode(password)  // 密码
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        // 期望返回 0x0100 表示认证成功
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 服务器认证失败");
            return;
        }
    }

    // 请求数据格式（Worker -> SOCKS5 服务器）:
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |	2	 |
    // +----+-----+-------+------+----------+----------+
    // ATYP: 地址类型
    // 0x01: IPv4 地址
    // 0x03: 域名
    // 0x04: IPv6 地址
    // DST.ADDR: 目标地址
    // DST.PORT: 目标端口（网络字节序）

    // addressType
    // 1 --> IPv4  地址长度 = 4
    // 2 --> 域名
    // 3 --> IPv6  地址长度 = 16
    let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
    switch (addressType) {
        case 1: // IPv4
            DSTADDR = new Uint8Array(
                [1, ...addressRemote.split('.').map(Number)]
            );
            break;
        case 2: // 域名
            DSTADDR = new Uint8Array(
                [3, addressRemote.length, ...encoder.encode(addressRemote)]
            );
            break;
        case 3: // IPv6
            DSTADDR = new Uint8Array(
                [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
            );
            break;
        default:
            log(`无效的地址类型: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    // 5: SOCKS5版本, 1: 表示CONNECT请求, 0: 保留字段
    // ...DSTADDR: 目标地址, portRemote >> 8 和 & 0xff: 将端口转为网络字节序
    await writer.write(socksRequest);
    log('已发送 SOCKS5 请求');

    res = (await reader.read()).value;
    // 响应格式（SOCKS5 服务器 -> Worker）:
    //  +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |	2	 |
    // +----+-----+-------+------+----------+----------+
    if (res[1] === 0x00) {
        log("SOCKS5 连接已建立");
    } else {
        log("SOCKS5 连接建立失败");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

/**
 * 建立 HTTP 代理连接
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 */
async function httpConnect(addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({
        hostname: hostname,
        port: port
    });

    // 构建HTTP CONNECT请求
    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    // 添加代理认证（如果需要）
    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`; // 添加标准 Connection 头
    connectRequest += `\r\n`;

    log(`正在连接到 ${addressRemote}:${portRemote} 通过代理 ${hostname}:${port}`);

    try {
        // 发送连接请求
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('发送HTTP CONNECT请求失败:', err);
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    }

    // 读取HTTP响应
    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                console.error('HTTP代理连接中断');
                throw new Error('HTTP代理连接中断');
            }

            // 合并接收到的数据
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            // 将收到的数据转换为文本
            respText = new TextDecoder().decode(responseBuffer);

            // 检查是否收到完整的HTTP响应头
            if (respText.includes('\r\n\r\n')) {
                // 分离HTTP头和可能的数据部分
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                log(`收到HTTP代理响应: ${headers.split('\r\n')[0]}`);

                // 检查响应状态
                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    // 如果响应头之后还有数据，我们需要保存这些数据以便后续处理
                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        // 创建一个缓冲区来存储这些数据，以便稍后使用
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        // 创建一个新的TransformStream来处理额外数据
                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));

                        // 替换原始readable流
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
                    console.error(errorMsg);
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        throw new Error('HTTP代理连接失败: 未收到成功响应');
    }

    log(`HTTP代理连接成功: ${addressRemote}:${portRemote}`);
    return sock;
}

/**
 * SOCKS5 代理地址解析器
 * 此函数用于解析 SOCKS5 代理地址字符串，提取出用户名、密码、主机名和端口号
 * 
 * @param {string} address SOCKS5 代理地址，格式可以是：
 *   - "username:password@hostname:port" （带认证）
 *   - "hostname:port" （不需认证）
 *   - "username:password@[ipv6]:port" （IPv6 地址需要用方括号括起来）
 */
function socks5AddressParser(address) {
    // 使用 "@" 分割地址，分为认证部分和服务器地址部分
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;

    // 如果存在 former 部分，说明提供了认证信息
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }

    // 解析服务器地址部分
    const latters = latter.split(":");
    // 检查是否是IPv6地址带端口格式 [xxx]:port
    if (latters.length > 2 && latter.includes("]:")) {
        // IPv6地址带端口格式：[2001:db8::1]:8080
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]"; // 正确提取hostname部分
    } else if (latters.length === 2) {
        // IPv4地址带端口或域名带端口
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }

    // 处理 IPv6 地址的特殊情况
    // IPv6 地址包含多个冒号，所以必须用方括号括起来，如 [2001:db8::1]
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }

    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    // 返回解析后的结果
    return {
        username,  // 用户名，如果没有则为 undefined
        password,  // 密码，如果没有则为 undefined
        hostname,  // 主机名，可以是域名、IPv4 或 IPv6 地址
        port,	 // 端口号，已转换为数字类型
    }
}

/**
 * 恢复被伪装的信息
 * 这个函数用于将内容中的假用户ID和假主机名替换回真实的值
 * 
 * @param {string} content 需要处理的内容
 * @param {string} userID 真实的用户ID
 * @param {string} hostName 真实的主机名
 * @param {boolean} isBase64 内容是否是Base64编码的
 * @returns {string} 恢复真实信息后的内容
 */
function 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
    if (isBase64) content = atob(content);  // 如果内容是Base64编码的，先解码

    // 使用正则表达式全局替换（'g'标志）
    // 将所有出现的假用户ID和假主机名替换为真实的值
    content = content.replace(new RegExp(fakeUserID, 'g'), userID)
        .replace(new RegExp(fakeHostName, 'g'), hostName);

    if (isBase64) content = btoa(content);  // 如果原内容是Base64编码的，处理完后再次编码

    return content;
}

/**
 * 双重MD5哈希函数
 * 这个函数对输入文本进行两次MD5哈希，增强安全性
 * 第二次哈希使用第一次哈希结果的一部分作为输入
 * 
 * @param {string} 文本 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的小写十六进制字符串
 */
async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

    // 解析目标 URL
    let 解析后的网址 = new URL(完整网址);
    console.log(解析后的网址);
    // 提取并可能修改 URL 组件
    let 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    let 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    let 查询参数 = 解析后的网址.search;

    // 处理路径名
    if (路径名.charAt(路径名.length - 1) == '/') {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    // 构建新的 URL
    let 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

    // 反向代理请求
    let 响应 = await fetch(新网址);

    // 创建新的响应
    let 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });

    // 添加自定义头部，包含 URL 信息
    //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //新响应.headers.set('X-Original-URL', 完整网址);
    新响应.headers.set('X-New-URL', 新网址);

    return 新响应;
}

const 啥啥啥_写的这是啥啊 = atob('ZG14bGMzTT0=');
function 配置信息(UUID, 域名地址) {
    const 协议类型 = atob(啥啥啥_写的这是啥啊);

    const 别名 = FileName;
    let 地址 = 域名地址;
    let 端口 = 443;

    const 用户ID = UUID;
    const 加密方式 = 'none';

    const 传输层协议 = 'ws';
    const 伪装域名 = 域名地址;
    const 路径 = path;

    let 传输层安全 = ['tls', true];
    const SNI = 域名地址;
    const 指纹 = 'randomized';

    if (域名地址.includes('.workers.dev')) {
        地址 = atob('dmlzYS5jb20uaGs=');
        端口 = 80;
        传输层安全 = ['', false];
    }

    const 威图瑞 = `${协议类型}://${用户ID}@${地址}:${端口}\u003f\u0065\u006e\u0063\u0072\u0079` + 'p' + `${atob('dGlvbj0=') + 加密方式}\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${伪装域名}&path=${encodeURIComponent(路径) + allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}#${encodeURIComponent(别名)}`;
    const 猫猫猫 = `- {name: ${FileName}, server: ${地址}, port: ${端口}, type: ${协议类型}, uuid: ${用户ID}, tls: ${传输层安全[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: ${SCV}, servername: ${伪装域名}, client-fingerprint: ${指纹}, network: ${传输层协议}, ws-opts: {path: "${路径}", headers: {${伪装域名}}}}`;
    return [威图瑞, 猫猫猫];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));
/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function 生成配置信息(userID, hostName, sub, UA, RproxyIP, _url, fakeUserID, fakeHostName, env) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await 整理(sub);
        if (subs.length > 1) sub = subs[0];
    } else {
        if (env.KV) {
            await 迁移地址列表(env);
            const 优选地址列表 = await env.KV.get('ADD.txt');
            if (优选地址列表) {
                const 优选地址数组 = await 整理(优选地址列表);
                const 分类地址 = {
                    接口地址: new Set(),
                    链接地址: new Set(),
                    优选地址: new Set()
                };

                for (const 元素 of 优选地址数组) {
                    if (元素.startsWith('https://')) {
                        分类地址.接口地址.add(元素);
                    } else if (元素.includes('://')) {
                        分类地址.链接地址.add(元素);
                    } else {
                        分类地址.优选地址.add(元素);
                    }
                }

                addressesapi = [...分类地址.接口地址];
                link = [...分类地址.链接地址];
                addresses = [...分类地址.优选地址];
            }
        }

        if ((addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
            // 定义 Cloudflare IP 范围的 CIDR 列表
            let cfips = ['104.16.0.0/13'];
            // 请求 Cloudflare CIDR 列表
            try {
                const response = await fetch('https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt');
                if (response.ok) {
                    const data = await response.text();
                    cfips = await 整理(data);
                }
            } catch (error) {
                console.log('获取 CF-CIDR 失败，使用默认值:', error);
            }

            // 生成符合给定 CIDR 范围的随机 IP 地址
            function generateRandomIPFromCIDR(cidr) {
                const [base, mask] = cidr.split('/');
                const baseIP = base.split('.').map(Number);
                const subnetMask = 32 - parseInt(mask, 10);
                const maxHosts = Math.pow(2, subnetMask) - 1;
                const randomHost = Math.floor(Math.random() * maxHosts);

                const randomIP = baseIP.map((octet, index) => {
                    if (index < 2) return octet;
                    if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
                    return (octet & (255 << subnetMask)) + (randomHost & 255);
                });

                return randomIP.join('.');
            }
            addresses = addresses.concat('127.0.0.1:1234#CFnat');
            let counter = 1;
            if (hostName.includes("worker") || hostName.includes("notls")) {
                const randomPorts = httpPorts.concat('80');
                addressesnotls = addressesnotls.concat(
                    cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CF随机节点' + String(counter++).padStart(2, '0'))
                );
            } else {
                const randomPorts = httpsPorts.concat('443');
                addresses = addresses.concat(
                    cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CF随机节点' + String(counter++).padStart(2, '0'))
                );
            }
        }
    }

    const uuid = (_url.pathname == `/${动态UUID}`) ? 动态UUID : userID;
    const userAgent = UA.toLowerCase();
    const Config = 配置信息(userID, hostName);
    const v2ray = Config[0];
    const clash = Config[1];
    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
            try {
                const response = await fetch(proxyhostsURL);

                if (!response.ok) {
                    console.error('获取地址时出错:', response.status, response.statusText);
                    return; // 如果有错误，直接返回
                }

                const text = await response.text();
                const lines = text.split('\n');
                // 过滤掉空行或只包含空白字符的行
                const nonEmptyLines = lines.filter(line => line.trim() !== '');

                proxyhosts = proxyhosts.concat(nonEmptyLines);
            } catch (error) {
                //console.error('获取地址时出错:', error);
            }
        }
        if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
    }

    if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
        const newSocks5s = socks5s.map(socks5Address => {
            if (socks5Address.includes('@')) return socks5Address.split('@')[1];
            else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
            else return socks5Address;
        });

        let socks5List = '';
        if (go2Socks5s.length > 0 && enableSocks) {
            socks5List = `${(enableHttp ? "HTTP" : "Socks5") + decodeURIComponent('%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
            if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) socks5List += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>`;
            else socks5List += `<br>&nbsp;&nbsp;${go2Socks5s.join('<br>&nbsp;&nbsp;')}<br>`;
        }

        let 订阅器 = '<br>';
        if (sub) {
            if (enableSocks) 订阅器 += `CFCDN（访问方式）: ${enableHttp ? "HTTP" : "Socks5"}<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
            else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
            else if (RproxyIP == 'true') 订阅器 += `CFCDN（访问方式）: 自动获取ProxyIP<br>`;
            else 订阅器 += `CFCDN（访问方式）: 内置兜底, 您也可以设置 proxyIP/PROXYIP 。<br>`
            订阅器 += `<br>SUB（优选订阅生成器）: ${sub}`;
        } else {
            if (enableSocks) 订阅器 += `CFCDN（访问方式）: ${enableHttp ? "HTTP" : "Socks5"}<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
            else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
            else 订阅器 += `CFCDN（访问方式）: 内置兜底, 您也可以设置 proxyIP/PROXYIP 。<br>`;
            let 判断是否绑定KV空间 = '';
            if (env.KV) 判断是否绑定KV空间 = ` [<a href='${_url.pathname}/edit'>编辑优选列表</a>]  [<a href='${_url.pathname}/bestip'>在线优选IP</a>]`;
            订阅器 += `<br>您的订阅内容由 内置 addresses/ADD* 参数变量提供${判断是否绑定KV空间}<br>`;
            if (addresses.length > 0) 订阅器 += `ADD（TLS优选域名&IP）: <br>&nbsp;&nbsp;${addresses.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesnotls.length > 0) 订阅器 += `ADDNOTLS（noTLS优选域名&IP）: <br>&nbsp;&nbsp;${addressesnotls.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesapi.length > 0) 订阅器 += `ADDAPI（TLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesapi.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesnotlsapi.length > 0) 订阅器 += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesnotlsapi.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressescsv.length > 0) 订阅器 += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: <br>&nbsp;&nbsp;${addressescsv.join('<br>&nbsp;&nbsp;')}<br>`;
        }

        if (动态UUID && _url.pathname !== `/${动态UUID}`) 订阅器 = '';
        else 订阅器 += `<br>SUBAPI（订阅转换后端）: <a href='${subProtocol}://${subConverter}/version' target="_blank" rel="noopener noreferrer">${subProtocol}://${subConverter}</a><br>SUBCONFIG（订阅转换配置文件）: <a href='${subConfig}' target="_blank" rel="noopener noreferrer">${subConfig}</a>`;
        const 动态UUID信息 = (uuid != userID) ? `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME（动态UUID有效时间）: ${有效时间} 天<br>UPTIME（动态UUID更新时间）: ${更新时间} 时（北京时间）<br><br>` : `${userIDTime}`;
        const 节点配置页 = `
            ################################################################<br>
            Subscribe / sub 订阅地址, 点击链接自动 <strong>复制订阅链接</strong> 并 <strong>生成订阅二维码</strong> <br>
            ---------------------------------------------------------------<br>
            自适应订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}</a><br>
            <div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
            Base64订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?b64</a><br>
            <div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
            clash订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?clash</a><br>
            <div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
            singbox订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sb</a><br>
            <div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
            loon订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?loon</a><br>
            <div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
            <strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">实用订阅技巧∨</a></strong><br>
                <div id="noticeContent" class="notice-content" style="display: none;">
                    <strong>1.</strong> 如您使用的是 PassWall、PassWall2 路由插件，订阅编辑的 <strong>用户代理(User-Agent)</strong> 设置为 <strong>PassWall</strong> 即可；<br>
                    <br>
                    <strong>2.</strong> 如您使用的是 SSR+ 路由插件，推荐使用 <strong>Base64订阅地址</strong> 进行订阅；<br>
                    <br>
                    <strong>3.</strong> 快速切换 <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>优选订阅生成器</a> 至：sub.google.com，您可将"?sub=sub.google.com"参数添加到链接末尾，例如：<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br>
                    <br>
                    <strong>4.</strong> 快速更换 PROXYIP 至：proxyip.cmliussss.net:443，您可将"?proxyip=proxyip.cmliussss.net:443"参数添加到链接末尾，例如：<br>
                    &nbsp;&nbsp; https://${proxyhost}${hostName}/${uuid}<strong>?proxyip=proxyip.cmliussss.net:443</strong><br>
                    <br>
                    <strong>5.</strong> 快速更换 SOCKS5 至：user:password@127.0.0.1:1080，您可将"?socks5=user:password@127.0.0.1:1080"参数添加到链接末尾，例如：<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?socks5=user:password@127.0.0.1:1080</strong><br>
                    <br>
                    <strong>6.</strong> 如需指定多个参数则需要使用'&'做间隔，例如：<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.cmliussss.net<br>
                </div>
            <script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
            <script>
            function copyToClipboard(text, qrcode) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('已复制到剪贴板');
                }).catch(err => {
                    console.error('复制失败:', err);
                });
                const qrcodeDiv = document.getElementById(qrcode);
                qrcodeDiv.innerHTML = '';
                new QRCode(qrcodeDiv, {
                    text: text,
                    width: 220, // 调整宽度
                    height: 220, // 调整高度
                    colorDark: "#000000", // 二维码颜色
                    colorLight: "#ffffff", // 背景颜色
                    correctLevel: QRCode.CorrectLevel.Q, // 设置纠错级别
                    scale: 1 // 调整像素颗粒度
                });
            }

            function toggleNotice() {
                const noticeContent = document.getElementById('noticeContent');
                const noticeToggle = document.getElementById('noticeToggle');
                if (noticeContent.style.display === 'none') {
                    noticeContent.style.display = 'block';
                    noticeToggle.textContent = '实用订阅技巧∧';
                } else {
                    noticeContent.style.display = 'none'; 
                    noticeToggle.textContent = '实用订阅技巧∨';
                }
            }
            </script>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${FileName} 配置信息<br>
            ---------------------------------------------------------------<br>
            ${动态UUID信息}HOST: ${hostName}<br>
            UUID: ${userID}<br>
            FKID: ${fakeUserID}<br>
            UA: ${UA}<br>
            SCV（跳过TLS证书验证）: ${SCV}<br>
            ${订阅器}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            v2ray<br>
            ---------------------------------------------------------------<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('${v2ray}','qrcode_v2ray')" style="color:blue;text-decoration:underline;cursor:pointer;">${v2ray}</a><br>
            <div id="qrcode_v2ray" style="margin: 10px 10px 10px 10px;"></div>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            clash-meta<br>
            ---------------------------------------------------------------<br>
            ${clash}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${cmad}
            `;
        return `<div style="font-size:13px;">${节点配置页}</div>`;
    } else {
        if (typeof fetch != 'function') {
            return 'Error: fetch is not available in this environment.';
        }

        let newAddressesapi = [];
        let newAddressescsv = [];
        let newAddressesnotlsapi = [];
        let newAddressesnotlscsv = [];

        // 如果是使用默认域名，则改成一个workers的域名，订阅器会加上代理
        if (hostName.includes(".workers.dev")) {
            noTLS = 'true';
            fakeHostName = `${fakeHostName}.workers.dev`;
            newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
            newAddressesnotlscsv = await 整理测速结果('FALSE');
        } else if (hostName.includes(".pages.dev")) {
            fakeHostName = `${fakeHostName}.pages.dev`;
        } else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
            noTLS = 'true';
            fakeHostName = `notls${fakeHostName}.net`;
            newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
            newAddressesnotlscsv = await 整理测速结果('FALSE');
        } else {
            fakeHostName = `${fakeHostName}.xyz`
        }
        console.log(`虚假HOST: ${fakeHostName}`);
        let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID + atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent(path)}`;
        let isBase64 = true;

        if (!sub || sub == "") {
            if (hostName.includes('workers.dev')) {
                if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
                    try {
                        const response = await fetch(proxyhostsURL);

                        if (!response.ok) {
                            console.error('获取地址时出错:', response.status, response.statusText);
                            return; // 如果有错误，直接返回
                        }

                        const text = await response.text();
                        const lines = text.split('\n');
                        // 过滤掉空行或只包含空白字符的行
                        const nonEmptyLines = lines.filter(line => line.trim() !== '');

                        proxyhosts = proxyhosts.concat(nonEmptyLines);
                    } catch (error) {
                        console.error('获取地址时出错:', error);
                    }
                }
                // 使用Set对象去重
                proxyhosts = [...new Set(proxyhosts)];
            }

            newAddressesapi = await 整理优选列表(addressesapi);
            newAddressescsv = await 整理测速结果('TRUE');
            url = `https://${hostName}/${fakeUserID + _url.search}`;
            if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
                if (_url.search) url += '&notls';
                else url += '?notls';
            }
            console.log(`虚假订阅: ${url}`);
        }

        if (userAgent.includes(('CF-Workers-SUB').toLowerCase()) || _url.searchParams.has('b64') || _url.searchParams.has('base64') || userAgent.includes('subconverter')) {
            isBase64 = true;
        } else if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash'))) {
            url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || _url.searchParams.has('singbox') || _url.searchParams.has('sb')) {
            url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (userAgent.includes('loon') || _url.searchParams.has('loon')) {
            url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        }

        try {
            let content;
            if ((!sub || sub == "") && isBase64 == true) {
                content = await 生成本地订阅(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
            } else {
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': 'v2rayN' + atob('L2VkZ2V0dW5uZWwgKGh0dHBzOi8vZ2l0aHViLmNvbS9jbWxpdS9lZGdldHVubmVsKQ==')
                    }
                });
                content = await response.text();
            }

            if (_url.pathname == `/${fakeUserID}`) return content;

            return 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64);

        } catch (error) {
            console.error('Error fetching content:', error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function 整理优选列表(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";

    // 创建一个AbortController对象，用于控制fetch请求的取消
    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort(); // 取消所有请求
    }, 2000); // 2秒后触发

    try {
        // 使用Promise.allSettled等待所有API请求完成，无论成功或失败
        // 对api数组进行遍历，对每个API地址发起fetch请求
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
            },
            signal: controller.signal // 将AbortController的信号量添加到fetch请求中，以便于需要时可以取消请求
        }).then(response => response.ok ? response.text() : Promise.reject())));

        // 遍历所有响应
        for (const [index, response] of responses.entries()) {
            // 检查响应状态是否为'fulfilled'，即请求成功完成
            if (response.status === 'fulfilled') {
                // 获取响应的内容
                const content = await response.value;

                const lines = content.split(/\r?\n/);
                let 节点备注 = '';
                let 测速端口 = '443';

                if (lines[0].split(',').length > 3) {
                    const idMatch = api[index].match(/id=([^&]*)/);
                    if (idMatch) 节点备注 = idMatch[1];

                    const portMatch = api[index].match(/port=([^&]*)/);
                    if (portMatch) 测速端口 = portMatch[1];

                    for (let i = 1; i < lines.length; i++) {
                        const columns = lines[i].split(',')[0];
                        if (columns) {
                            newapi += `${columns}:${测速端口}${节点备注 ? `#${节点备注}` : ''}\n`;
                            if (api[index].includes('proxyip=true')) proxyIPPool.push(`${columns}:${测速端口}`);
                        }
                    }
                } else {
                    // 验证当前apiUrl是否带有'proxyip=true'
                    if (api[index].includes('proxyip=true')) {
                        // 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
                        proxyIPPool = proxyIPPool.concat((await 整理(content)).map(item => {
                            const baseItem = item.split('#')[0] || item;
                            if (baseItem.includes(':')) {
                                const port = baseItem.split(':')[1];
                                if (!httpsPorts.includes(port)) {
                                    return baseItem;
                                }
                            } else {
                                return `${baseItem}:443`;
                            }
                            return null; // 不符合条件时返回 null
                        }).filter(Boolean)); // 过滤掉 null 值
                    }
                    // 将内容添加到newapi中
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        // 无论成功或失败，最后都清除设置的超时定时器
        clearTimeout(timeout);
    }

    const newAddressesapi = await 整理(newapi);

    // 返回处理后的结果
    return newAddressesapi;
}

async function 整理测速结果(tls) {
    if (!addressescsv || addressescsv.length === 0) {
        return [];
    }

    let newAddressescsv = [];

    for (const csvUrl of addressescsv) {
        try {
            const response = await fetch(csvUrl);

            if (!response.ok) {
                console.error('获取CSV地址时出错:', response.status, response.statusText);
                continue;
            }

            const text = await response.text();// 使用正确的字符编码解析文本内容
            let lines;
            if (text.includes('\r\n')) {
                lines = text.split('\r\n');
            } else {
                lines = text.split('\n');
            }

            // 检查CSV头部是否包含必需字段
            const header = lines[0].split(',');
            const tlsIndex = header.indexOf('TLS');

            const ipAddressIndex = 0;// IP地址在 CSV 头部的位置
            const portIndex = 1;// 端口在 CSV 头部的位置
            const dataCenterIndex = tlsIndex + remarkIndex; // 数据中心是 TLS 的后一个字段

            if (tlsIndex === -1) {
                console.error('CSV文件缺少必需的字段');
                continue;
            }

            // 从第二行开始遍历CSV行
            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(',');
                const speedIndex = columns.length - 1; // 最后一个字段
                // 检查TLS是否为"TRUE"且速度大于DLS
                if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
                    const ipAddress = columns[ipAddressIndex];
                    const port = columns[portIndex];
                    const dataCenter = columns[dataCenterIndex];

                    const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                    newAddressescsv.push(formattedAddress);
                    if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
                        // 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
                        proxyIPPool.push(`${ipAddress}:${port}`);
                    }
                }
            }
        } catch (error) {
            console.error('获取CSV地址时出错:', error);
            continue;
        }
    }

    return newAddressescsv;
}

function 生成本地订阅(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
    const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
    addresses = addresses.concat(newAddressesapi);
    addresses = addresses.concat(newAddressescsv);
    let notlsresponseBody;
    if (noTLS == 'true') {
        addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
        addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
        const uniqueAddressesnotls = [...new Set(addressesnotls)];

        notlsresponseBody = uniqueAddressesnotls.map(address => {
            let port = "-1";
            let addressid = address;

            const match = addressid.match(regex);
            if (!match) {
                if (address.includes(':') && address.includes('#')) {
                    const parts = address.split(':');
                    address = parts[0];
                    const subParts = parts[1].split('#');
                    port = subParts[0];
                    addressid = subParts[1];
                } else if (address.includes(':')) {
                    const parts = address.split(':');
                    address = parts[0];
                    port = parts[1];
                } else if (address.includes('#')) {
                    const parts = address.split('#');
                    address = parts[0];
                    addressid = parts[1];
                }

                if (addressid.includes(':')) {
                    addressid = addressid.split(':')[0];
                }
            } else {
                address = match[1];
                port = match[2] || port;
                addressid = match[3] || address;
            }

            if (!isValidIPv4(address) && port == "-1") {
                for (let httpPort of httpPorts) {
                    if (address.includes(httpPort)) {
                        port = httpPort;
                        break;
                    }
                }
            }
            if (port == "-1") port = "80";

            let 伪装域名 = host;
            let 最终路径 = path;
            let 节点备注 = '';
            const 协议类型 = atob(啥啥啥_写的这是啥啊);

            const ctx = `${协议类型}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==') + 伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;

            return ctx;

        }).join('\n');

    }

    // 使用Set对象去重
    const uniqueAddresses = [...new Set(addresses)];

    const responseBody = uniqueAddresses.map(address => {
        let port = "-1";
        let addressid = address;

        const match = addressid.match(regex);
        if (!match) {
            if (address.includes(':') && address.includes('#')) {
                const parts = address.split(':');
                address = parts[0];
                const subParts = parts[1].split('#');
                port = subParts[0];
                addressid = subParts[1];
            } else if (address.includes(':')) {
                const parts = address.split(':');
                address = parts[0];
                port = parts[1];
            } else if (address.includes('#')) {
                const parts = address.split('#');
                address = parts[0];
                addressid = parts[1];
            }

            if (addressid.includes(':')) {
                addressid = addressid.split(':')[0];
            }
        } else {
            address = match[1];
            port = match[2] || port;
            addressid = match[3] || address;
        }

        if (!isValidIPv4(address) && port == "-1") {
            for (let httpsPort of httpsPorts) {
                if (address.includes(httpsPort)) {
                    port = httpsPort;
                    break;
                }
            }
        }
        if (port == "-1") port = "443";

        let 伪装域名 = host;
        let 最终路径 = path;
        let 节点备注 = '';
        const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
        if (matchingProxyIP) 最终路径 = `/proxyip=${matchingProxyIP}`;
        /*
        if (proxyhosts.length > 0 && (伪装域名.includes('.workers.dev'))) {
            最终路径 = `/${伪装域名}${最终路径}`;
            伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
            节点备注 = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
        }
        */
        const 协议类型 = atob(啥啥啥_写的这是啥啊);
        const ctx = `${协议类型}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ==') + 伪装域名}&fp=random&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径) + allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}#${encodeURIComponent(addressid + 节点备注)}`;

        return ctx;
    }).join('\n');

    let base64Response = responseBody; // 重新进行 Base64 编码
    if (noTLS == 'true') base64Response += `\n${notlsresponseBody}`;
    if (link.length > 0) base64Response += '\n' + link.join('\n');
    return btoa(base64Response);
}

async function 整理(内容) {
    // 将制表符、双引号、单引号和换行符都替换为逗号
    // 然后将连续的多个逗号替换为单个逗号
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');

    // 删除开头和结尾的逗号（如果有的话）
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

    // 使用逗号分割字符串，得到地址数组
    const 地址数组 = 替换后的内容.split(',');

    return 地址数组;
}

async function sendMessage(type, ip, add_data = "") {
    if (!BotToken || !ChatID) return;

    try {
        let msg = "";
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.ok) {
            const ipInfo = await response.json();
            msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
        } else {
            msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
        }

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
            }
        });
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

function isValidIPv4(address) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(address);
}

function 生成动态UUID(密钥) {
    const 时区偏移 = 8; // 北京时间相对于UTC的时区偏移+8小时
    const 起始日期 = new Date(2007, 6, 7, 更新时间, 0, 0); // 固定起始日期为2007年7月7日的凌晨3点
    const 一周的毫秒数 = 1000 * 60 * 60 * 24 * 有效时间;

    function 获取当前周数() {
        const 现在 = new Date();
        const 调整后的现在 = new Date(现在.getTime() + 时区偏移 * 60 * 60 * 1000);
        const 时间差 = Number(调整后的现在) - Number(起始日期);
        return Math.ceil(时间差 / 一周的毫秒数);
    }

    function 生成UUID(基础字符串) {
        const 哈希缓冲区 = new TextEncoder().encode(基础字符串);
        return crypto.subtle.digest('SHA-256', 哈希缓冲区).then((哈希) => {
            const 哈希数组 = Array.from(new Uint8Array(哈希));
            const 十六进制哈希 = 哈希数组.map(b => b.toString(16).padStart(2, '0')).join('');
            return `${十六进制哈希.substr(0, 8)}-${十六进制哈希.substr(8, 4)}-4${十六进制哈希.substr(13, 3)}-${(parseInt(十六进制哈希.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十六进制哈希.substr(18, 2)}-${十六进制哈希.substr(20, 12)}`;
        });
    }

    const 当前周数 = 获取当前周数(); // 获取当前周数
    const 结束时间 = new Date(起始日期.getTime() + 当前周数 * 一周的毫秒数);

    // 生成两个 UUID
    const 当前UUIDPromise = 生成UUID(密钥 + 当前周数);
    const 上一个UUIDPromise = 生成UUID(密钥 + (当前周数 - 1));

    // 格式化到期时间
    const 到期时间UTC = new Date(结束时间.getTime() - 时区偏移 * 60 * 60 * 1000); // UTC时间
    const 到期时间字符串 = `到期时间(UTC): ${到期时间UTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结束时间.toISOString().slice(0, 19).replace('T', ' ')}\n`;

    return Promise.all([当前UUIDPromise, 上一个UUIDPromise, 到期时间字符串]);
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
    const 旧数据 = await env.KV.get(`/${txt}`);
    const 新数据 = await env.KV.get(txt);

    if (旧数据 && !新数据) {
        // 写入新位置
        await env.KV.put(txt, 旧数据);
        // 删除旧数据
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function KV(request, env, txt = 'ADD.txt') {
    try {
        // POST请求处理
        if (request.method === "POST") {
            if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
            try {
                const content = await request.text();
                await env.KV.put(txt, content);
                return new Response("保存成功");
            } catch (error) {
                console.error('保存KV时发生错误:', error);
                return new Response("保存失败: " + error.message, { status: 500 });
            }
        }

        // GET请求部分
        let content = '';
        let hasKV = !!env.KV;

        if (hasKV) {
            try {
                content = await env.KV.get(txt) || '';
            } catch (error) {
                console.error('读取KV时发生错误:', error);
                content = '读取数据时发生错误: ' + error.message;
            }
        }

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>优选订阅列表</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {
                        margin: 0;
                        padding: 15px; /* 调整padding */
                        box-sizing: border-box;
                        font-size: 13px; /* 设置全局字体大小 */
                    }
                    .editor-container {
                        width: 100%;
                        max-width: 100%;
                        margin: 0 auto;
                    }
                    .editor {
                        width: 100%;
                        height: 520px; /* 调整高度 */
                        margin: 15px 0; /* 调整margin */
                        padding: 10px; /* 调整padding */
                        box-sizing: border-box;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 13px;
                        line-height: 1.5;
                        overflow-y: auto;
                        resize: none;
                    }
                    .save-container {
                        margin-top: 8px; /* 调整margin */
                        display: flex;
                        align-items: center;
                        gap: 10px; /* 调整gap */
                    }
                    .save-btn, .back-btn {
                        padding: 6px 15px; /* 调整padding */
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }
                    .save-btn {
                        background: #4CAF50;
                    }
                    .save-btn:hover {
                        background: #45a049;
                    }
                    .back-btn {
                        background: #666;
                    }
                    .back-btn:hover {
                        background: #555;
                    }
                    .bestip-btn {
                        background: #2196F3;
                        padding: 6px 15px;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }
                    .bestip-btn:hover {
                        background: #1976D2;
                    }
                    .save-status {
                        color: #666;
                    }
                    .notice-content {
                        display: none;
                        margin-top: 10px;
                        font-size: 13px;
                        color: #333;
                    }
                </style>
            </head>
            <body>
                ################################################################<br>
                ${FileName} 优选订阅列表:<br>
                ---------------------------------------------------------------<br>
                &nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">注意事项∨</a></strong><br>
                <div id="noticeContent" class="notice-content">
                    ${decodeURIComponent(atob('JTA5JTA5JTA5JTA5JTA5JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBRERBUEklMjAlRTUlQTYlODIlRTYlOUUlOUMlRTYlOTglQUYlRTUlOEYlOEQlRTQlQkIlQTNJUCVFRiVCQyU4QyVFNSU4RiVBRiVFNCVCRCU5QyVFNCVCOCVCQVBST1hZSVAlRTclOUElODQlRTglQUYlOUQlRUYlQkMlOEMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwcm94eWlwJTNEdHJ1ZSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzQiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGbWFpbiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QuY3N2JTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUzQ3N0cm9uZyUzRSUyNiUzQyUyRnN0cm9uZyUzRXBvcnQlM0QyMDUzJTNDYnIlM0U='))}
                </div>
                <div class="editor-container">
                    ${hasKV ? `
                    <textarea class="editor" 
                        placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}"
                        id="content">${content}</textarea>
                    <div class="save-container">
                        <button class="back-btn" onclick="goBack()">返回配置页</button>
                        <button class="bestip-btn" onclick="goBestIP()">在线优选IP</button>
                        <button class="save-btn" onclick="saveContent(this)">保存</button>
                        <span class="save-status" id="saveStatus"></span>
                    </div>
                    <br>
                    ################################################################<br>
                    ${cmad}
                    ` : '<p>未绑定KV空间</p>'}
                </div>
        
                <script>
                if (document.querySelector('.editor')) {
                    let timer;
                    const textarea = document.getElementById('content');
                    const originalContent = textarea.value;
        
                    function goBack() {
                        const currentUrl = window.location.href;
                        const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
                        window.location.href = parentUrl;
                    }
        
                    function goBestIP() {
                        const currentUrl = window.location.href;
                        const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
                        window.location.href = parentUrl + '/bestip';
                    }
        
                    function replaceFullwidthColon() {
                        const text = textarea.value;
                        textarea.value = text.replace(/：/g, ':');
                    }
                    
                    function saveContent(button) {
                        try {
                            const updateButtonText = (step) => {
                                button.textContent = \`保存中: \${step}\`;
                            };
                            // 检测是否为iOS设备
                            const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
                            
                            // 仅在非iOS设备上执行replaceFullwidthColon
                            if (!isIOS) {
                                replaceFullwidthColon();
                            }
                            updateButtonText('开始保存');
                            button.disabled = true;
                            // 获取textarea内容和原始内容
                            const textarea = document.getElementById('content');
                            if (!textarea) {
                                throw new Error('找不到文本编辑区域');
                            }
                            updateButtonText('获取内容');
                            let newContent;
                            let originalContent;
                            try {
                                newContent = textarea.value || '';
                                originalContent = textarea.defaultValue || '';
                            } catch (e) {
                                console.error('获取内容错误:', e);
                                throw new Error('无法获取编辑内容');
                            }
                            updateButtonText('准备状态更新函数');
                            const updateStatus = (message, isError = false) => {
                                const statusElem = document.getElementById('saveStatus');
                                if (statusElem) {
                                    statusElem.textContent = message;
                                    statusElem.style.color = isError ? 'red' : '#666';
                                }
                            };
                            updateButtonText('准备按钮重置函数');
                            const resetButton = () => {
                                button.textContent = '保存';
                                button.disabled = false;
                            };
                            if (newContent !== originalContent) {
                                updateButtonText('发送保存请求');
                                fetch(window.location.href, {
                                    method: 'POST',
                                    body: newContent,
                                    headers: {
                                        'Content-Type': 'text/plain;charset=UTF-8'
                                    },
                                    cache: 'no-cache'
                                })
                                .then(response => {
                                    updateButtonText('检查响应状态');
                                    if (!response.ok) {
                                        throw new Error(\`HTTP error! status: \${response.status}\`);
                                    }
                                    updateButtonText('更新保存状态');
                                    const now = new Date().toLocaleString();
                                    document.title = \`编辑已保存 \${now}\`;
                                    updateStatus(\`已保存 \${now}\`);
                                })
                                .catch(error => {
                                    updateButtonText('处理错误');
                                    console.error('Save error:', error);
                                    updateStatus(\`保存失败: \${error.message}\`, true);
                                })
                                .finally(() => {
                                    resetButton();
                                });
                            } else {
                                updateButtonText('检查内容变化');
                                updateStatus('内容未变化');
                                resetButton();
                            }
                        } catch (error) {
                            console.error('保存过程出错:', error);
                            button.textContent = '保存';
                            button.disabled = false;
                            const statusElem = document.getElementById('saveStatus');
                            if (statusElem) {
                                statusElem.textContent = \`错误: \${error.message}\`;
                                statusElem.style.color = 'red';
                            }
                        }
                    }
        
                    textarea.addEventListener('blur', saveContent);
                    textarea.addEventListener('input', () => {
                        clearTimeout(timer);
                        timer = setTimeout(saveContent, 5000);
                    });
                }
        
                function toggleNotice() {
                    const noticeContent = document.getElementById('noticeContent');
                    const noticeToggle = document.getElementById('noticeToggle');
                    if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
                        noticeContent.style.display = 'block';
                        noticeToggle.textContent = '注意事项∧';
                    } else {
                        noticeContent.style.display = 'none';
                        noticeToggle.textContent = '注意事项∨';
                    }
                }
        
                // 初始化 noticeContent 的 display 属性
                document.addEventListener('DOMContentLoaded', () => {
                    document.getElementById('noticeContent').style.display = 'none';
                });
                </script>
            </body>
            </html>
        `;

        return new Response(html, {
            headers: { "Content-Type": "text/html;charset=utf-8" }
        });
    } catch (error) {
        console.error('处理请求时发生错误:', error);
        return new Response("服务器错误: " + error.message, {
            status: 500,
            headers: { "Content-Type": "text/plain;charset=utf-8" }
        });
    }
}

async function resolveToIPv6(target) {
    const defaultAddress = atob('cHJveHlpcC5jbWxpdXNzc3MubmV0');
    if (!DNS64Server) {
        try {
            const response = await fetch(atob('aHR0cHM6Ly8xLjEuMS4xL2Rucy1xdWVyeT9uYW1lPW5hdDY0LmNtbGl1c3Nzcy5uZXQmdHlwZT1UWFQ='), {
                headers: { 'Accept': 'application/dns-json' }
            });

            if (!response.ok) return defaultAddress;
            const data = await response.json();
            const txtRecords = (data.Answer || []).filter(record => record.type === 16).map(record => record.data);

            if (txtRecords.length === 0) return defaultAddress;
            let txtData = txtRecords[0];
            if (txtData.startsWith('"') && txtData.endsWith('"')) txtData = txtData.slice(1, -1);
            const prefixes = txtData.replace(/\\010/g, '\n').split('\n').filter(prefix => prefix.trim());
            if (prefixes.length === 0) return defaultAddress;
            DNS64Server = prefixes[Math.floor(Math.random() * prefixes.length)];
        } catch (error) {
            console.error('DNS64Server查询失败:', error);
            return defaultAddress;
        }
    }

    // 检查是否为IPv4
    function isIPv4(str) {
        const parts = str.split('.');
        return parts.length === 4 && parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    // 检查是否为IPv6
    function isIPv6(str) {
        return str.includes(':') && /^[0-9a-fA-F:]+$/.test(str);
    }

    // 获取域名的IPv4地址
    async function fetchIPv4(domain) {
        const url = `https://1.1.1.1/dns-query?name=${domain}&type=A`;
        const response = await fetch(url, {
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) throw new Error('DNS查询失败');

        const data = await response.json();
        const ipv4s = (data.Answer || [])
            .filter(record => record.type === 1)
            .map(record => record.data);

        if (ipv4s.length === 0) throw new Error('未找到IPv4地址');
        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    // 查询NAT64 IPv6地址
    async function queryNAT64(domain) {
        const socket = connect({
            hostname: isIPv6(DNS64Server) ? `[${DNS64Server}]` : DNS64Server,
            port: 53
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            // 发送DNS查询
            const query = buildDNSQuery(domain);
            const queryWithLength = new Uint8Array(query.length + 2);
            queryWithLength[0] = query.length >> 8;
            queryWithLength[1] = query.length & 0xFF;
            queryWithLength.set(query, 2);
            await writer.write(queryWithLength);

            // 读取响应
            const response = await readDNSResponse(reader);
            const ipv6s = parseIPv6(response);

            return ipv6s.length > 0 ? ipv6s[0] : '未找到IPv6地址';
        } finally {
            await writer.close();
            await reader.cancel();
        }
    }

    // 构建DNS查询包
    function buildDNSQuery(domain) {
        const buffer = new ArrayBuffer(512);
        const view = new DataView(buffer);
        let offset = 0;

        // DNS头部
        view.setUint16(offset, Math.floor(Math.random() * 65536)); offset += 2; // ID
        view.setUint16(offset, 0x0100); offset += 2; // 标志
        view.setUint16(offset, 1); offset += 2; // 问题数
        view.setUint16(offset, 0); offset += 6; // 答案数/权威数/附加数

        // 域名编码
        for (const label of domain.split('.')) {
            view.setUint8(offset++, label.length);
            for (let i = 0; i < label.length; i++) {
                view.setUint8(offset++, label.charCodeAt(i));
            }
        }
        view.setUint8(offset++, 0); // 结束标记

        // 查询类型和类
        view.setUint16(offset, 28); offset += 2; // AAAA记录
        view.setUint16(offset, 1); offset += 2; // IN类

        return new Uint8Array(buffer, 0, offset);
    }

    // 读取DNS响应
    async function readDNSResponse(reader) {
        const chunks = [];
        let totalLength = 0;
        let expectedLength = null;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            chunks.push(value);
            totalLength += value.length;

            if (expectedLength === null && totalLength >= 2) {
                expectedLength = (chunks[0][0] << 8) | chunks[0][1];
            }

            if (expectedLength !== null && totalLength >= expectedLength + 2) {
                break;
            }
        }

        // 合并数据并跳过长度前缀
        const fullResponse = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            fullResponse.set(chunk, offset);
            offset += chunk.length;
        }

        return fullResponse.slice(2);
    }

    // 解析IPv6地址
    function parseIPv6(response) {
        const view = new DataView(response.buffer);
        let offset = 12; // 跳过DNS头部

        // 跳过问题部分
        while (view.getUint8(offset) !== 0) {
            offset += view.getUint8(offset) + 1;
        }
        offset += 5;

        const answers = [];
        const answerCount = view.getUint16(6); // 答案数量

        for (let i = 0; i < answerCount; i++) {
            // 跳过名称
            if ((view.getUint8(offset) & 0xC0) === 0xC0) {
                offset += 2;
            } else {
                while (view.getUint8(offset) !== 0) {
                    offset += view.getUint8(offset) + 1;
                }
                offset++;
            }

            const type = view.getUint16(offset); offset += 2;
            offset += 6; // 跳过类和TTL
            const dataLength = view.getUint16(offset); offset += 2;

            if (type === 28 && dataLength === 16) { // AAAA记录
                const parts = [];
                for (let j = 0; j < 8; j++) {
                    parts.push(view.getUint16(offset + j * 2).toString(16));
                }
                answers.push(parts.join(':'));
            }
            offset += dataLength;
        }

        return answers;
    }

    function convertToNAT64IPv6(ipv4Address) {
        const parts = ipv4Address.split('.');
        if (parts.length !== 4) {
            throw new Error('无效的IPv4地址');
        }

        // 将每个部分转换为16进制
        const hex = parts.map(part => {
            const num = parseInt(part, 10);
            if (num < 0 || num > 255) {
                throw new Error('无效的IPv4地址段');
            }
            return num.toString(16).padStart(2, '0');
        });

        // 构造NAT64
        return DNS64Server.split('/96')[0] + hex[0] + hex[1] + ":" + hex[2] + hex[3];
    }

    try {
        // 判断输入类型并处理
        if (isIPv6(target)) return target; // IPv6直接返回
        const ipv4 = isIPv4(target) ? target : await fetchIPv4(target);
        const nat64 = DNS64Server.endsWith('/96') ? convertToNAT64IPv6(ipv4) : await queryNAT64(ipv4 + atob('LmlwLjA5MDIyNy54eXo='));
        return isIPv6(nat64) ? nat64 : defaultAddress;
    } catch (error) {
        console.error('解析错误:', error);
        return defaultAddress;
    }
}

async function bestIP(request, env, txt = 'ADD.txt') {
    const country = request.cf?.country || 'CN';
    const url = new URL(request.url);
    async function getNipDomain() {
        try {
            const response = await fetch(atob('aHR0cHM6Ly9jbG91ZGZsYXJlLWRucy5jb20vZG5zLXF1ZXJ5P25hbWU9bmlwLjA5MDIyNy54eXomdHlwZT1UWFQ='), {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
                    // TXT记录的值通常包含在引号中，需要去除引号
                    const txtRecord = data.Answer[0].data;
                    // 去除首尾的引号
                    const domain = txtRecord.replace(/^"(.*)"$/, '$1');
                    console.log('通过DoH解析获取到域名: ' + domain);
                    return domain;
                }
            }
            console.warn('DoH解析失败，使用默认域名');
            return atob('bmlwLmxmcmVlLm9yZw==');
        } catch (error) {
            console.error('DoH解析出错:', error);
            return atob('aXAuMDkwMjI3Lnh5eg==');
        }
    }
    const nipDomain = await getNipDomain();
    async function GetCFIPs(ipSource = 'official', targetPort = '443') {
        try {
            let response;
            if (ipSource === 'as13335') {
                // AS13335列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt');
            } else if (ipSource === 'as209242') {
                // AS209242列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt');
            } else if (ipSource === 'as24429') {
                // AS24429列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24429/ipv4-aggregated.txt');
            } else if (ipSource === 'as35916') {
                // AS35916列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/35916/ipv4-aggregated.txt');
            } else if (ipSource === 'as199524') {
                // AS199524列表
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199524/ipv4-aggregated.txt');
            } else if (ipSource === 'cm') {
                // CM整理列表
                response = await fetch('https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt');
            } else if (ipSource === 'proxyip') {
                // 反代IP列表 (直接IP，非CIDR)
                response = await fetch('https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt');
                const text = response.ok ? await response.text() : '';

                // 解析并过滤符合端口的IP
                const allLines = text.split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#'));

                const validIps = [];

                for (const line of allLines) {
                    const parsedIP = parseProxyIPLine(line, targetPort);
                    if (parsedIP) {
                        validIps.push(parsedIP);
                    }
                }

                console.log(`反代IP列表解析完成，端口${targetPort}匹配到${validIps.length}个有效IP`);

                // 如果超过512个IP，随机选择512个
                if (validIps.length > 512) {
                    const shuffled = [...validIps].sort(() => 0.5 - Math.random());
                    const selectedIps = shuffled.slice(0, 512);
                    console.log(`IP数量超过512个，随机选择了${selectedIps.length}个IP`);
                    return selectedIps;
                } else {
                    return validIps;
                }
            } else {
                // CF官方列表 (默认)
                response = await fetch('https://www.cloudflare.com/ips-v4/');
            }

            const text = response.ok ? await response.text() : `173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22`;
            const cidrs = text.split('\n').filter(line => line.trim() && !line.startsWith('#'));

            const ips = new Set(); // 使用Set去重
            const targetCount = 512;
            let round = 1;

            // 不断轮次生成IP直到达到目标数量
            while (ips.size < targetCount) {
                console.log(`第${round}轮生成IP，当前已有${ips.size}个`);

                // 每轮为每个CIDR生成指定数量的IP
                for (const cidr of cidrs) {
                    if (ips.size >= targetCount) break;

                    const cidrIPs = generateIPsFromCIDR(cidr.trim(), round);
                    cidrIPs.forEach(ip => ips.add(ip));

                    console.log(`CIDR ${cidr} 第${round}轮生成${cidrIPs.length}个IP，总计${ips.size}个`);
                }

                round++;

                // 防止无限循环
                if (round > 100) {
                    console.warn('达到最大轮次限制，停止生成');
                    break;
                }
            }

            console.log(`最终生成${ips.size}个不重复IP`);
            return Array.from(ips).slice(0, targetCount);
        } catch (error) {
            console.error('获取CF IPs失败:', error);
            return [];
        }
    }

    // 新增：解析反代IP行的函数
    function parseProxyIPLine(line, targetPort) {
        try {
            // 移除首尾空格
            line = line.trim();
            if (!line) return null;

            let ip = '';
            let port = '';
            let comment = '';

            // 处理注释部分
            if (line.includes('#')) {
                const parts = line.split('#');
                const mainPart = parts[0].trim();
                comment = parts[1].trim();

                // 检查主要部分是否包含端口
                if (mainPart.includes(':')) {
                    const ipPortParts = mainPart.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                        port = ipPortParts[1].trim();
                    } else {
                        // 格式不正确，如":844347.254.171.15:8443"
                        console.warn(`无效的IP:端口格式: ${line}`);
                        return null;
                    }
                } else {
                    // 没有端口，默认443
                    ip = mainPart;
                    port = '443';
                }
            } else {
                // 没有注释
                if (line.includes(':')) {
                    const ipPortParts = line.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                        port = ipPortParts[1].trim();
                    } else {
                        // 格式不正确
                        console.warn(`无效的IP:端口格式: ${line}`);
                        return null;
                    }
                } else {
                    // 只有IP，默认443端口
                    ip = line;
                    port = '443';
                }
            }

            // 验证IP格式
            if (!isValidIP(ip)) {
                console.warn(`无效的IP地址: ${ip} (来源行: ${line})`);
                return null;
            }

            // 验证端口格式
            const portNum = parseInt(port);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                console.warn(`无效的端口号: ${port} (来源行: ${line})`);
                return null;
            }

            // 检查端口是否匹配
            if (port !== targetPort) {
                return null; // 端口不匹配，过滤掉
            }

            // 构建返回格式
            if (comment) {
                return ip + ':' + port + '#' + comment;
            } else {
                return ip + ':' + port;
            }

        } catch (error) {
            console.error(`解析IP行失败: ${line}`, error);
            return null;
        }
    }

    // 新增：验证IP地址格式的函数
    function isValidIP(ip) {
        const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const match = ip.match(ipRegex);

        if (!match) return false;

        // 检查每个数字是否在0-255范围内
        for (let i = 1; i <= 4; i++) {
            const num = parseInt(match[i]);
            if (num < 0 || num > 255) {
                return false;
            }
        }

        return true;
    }

    function generateIPsFromCIDR(cidr, count = 1) {
        const [network, prefixLength] = cidr.split('/');
        const prefix = parseInt(prefixLength);

        // 将IP地址转换为32位整数
        const ipToInt = (ip) => {
            return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
        };

        // 将32位整数转换为IP地址
        const intToIP = (int) => {
            return [
                (int >>> 24) & 255,
                (int >>> 16) & 255,
                (int >>> 8) & 255,
                int & 255
            ].join('.');
        };

        const networkInt = ipToInt(network);
        const hostBits = 32 - prefix;
        const numHosts = Math.pow(2, hostBits);

        // 限制生成数量不超过该CIDR的可用主机数
        const maxHosts = numHosts - 2; // -2 排除网络地址和广播地址
        const actualCount = Math.min(count, maxHosts);
        const ips = new Set();

        // 如果可用主机数太少，直接返回空数组
        if (maxHosts <= 0) {
            return [];
        }

        // 生成指定数量的随机IP
        let attempts = 0;
        const maxAttempts = actualCount * 10; // 防止无限循环

        while (ips.size < actualCount && attempts < maxAttempts) {
            const randomOffset = Math.floor(Math.random() * maxHosts) + 1; // +1 避免网络地址
            const randomIP = intToIP(networkInt + randomOffset);
            ips.add(randomIP);
            attempts++;
        }

        return Array.from(ips);
    }

    // POST请求处理
    if (request.method === "POST") {
        if (!env.KV) return new Response("未绑定KV空间", { status: 400 });

        try {
            const contentType = request.headers.get('Content-Type');

            // 处理JSON格式的保存/追加请求
            if (contentType && contentType.includes('application/json')) {
                const data = await request.json();
                const action = url.searchParams.get('action') || 'save';

                if (!data.ips || !Array.isArray(data.ips)) {
                    return new Response(JSON.stringify({ error: 'Invalid IP list' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                if (action === 'append') {
                    // 追加模式
                    const existingContent = await env.KV.get(txt) || '';
                    const newContent = data.ips.join('\n');

                    // 合并内容并去重
                    const existingLines = existingContent ?
                        existingContent.split('\n').map(line => line.trim()).filter(line => line) :
                        [];
                    const newLines = newContent.split('\n').map(line => line.trim()).filter(line => line);

                    // 使用Set进行去重
                    const allLines = [...existingLines, ...newLines];
                    const uniqueLines = [...new Set(allLines)];
                    const combinedContent = uniqueLines.join('\n');

                    // 检查合并后的内容大小
                    if (combinedContent.length > 24 * 1024 * 1024) {
                        return new Response(JSON.stringify({
                            error: `追加失败：合并后内容过大（${(combinedContent.length / 1024 / 1024).toFixed(2)}MB），超过KV存储限制（24MB）`
                        }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }

                    await env.KV.put(txt, combinedContent);

                    const addedCount = uniqueLines.length - existingLines.length;
                    const duplicateCount = newLines.length - addedCount;

                    let message = `成功追加 ${addedCount} 个新的优选IP（原有 ${existingLines.length} 个，现共 ${uniqueLines.length} 个）`;
                    if (duplicateCount > 0) {
                        message += `，已去重 ${duplicateCount} 个重复项`;
                    }

                    return new Response(JSON.stringify({
                        success: true,
                        message: message
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                } else {
                    // 保存模式（覆盖）
                    const content = data.ips.join('\n');

                    // 检查内容大小
                    if (content.length > 24 * 1024 * 1024) {
                        return new Response(JSON.stringify({
                            error: '内容过大，超过KV存储限制（24MB）'
                        }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }

                    await env.KV.put(txt, content);

                    return new Response(JSON.stringify({
                        success: true,
                        message: `成功保存 ${data.ips.length} 个优选IP`
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            } else {
                // 处理普通文本格式的保存请求（兼容原有功能）
                const content = await request.text();
                await env.KV.put(txt, content);
                return new Response("保存成功");
            }

        } catch (error) {
            console.error('处理POST请求时发生错误:', error);
            return new Response(JSON.stringify({
                error: '操作失败: ' + error.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // GET请求部分
    let content = '';
    let hasKV = !!env.KV;

    if (hasKV) {
        try {
            content = await env.KV.get(txt) || '';
        } catch (error) {
            console.error('读取KV时发生错误:', error);
            content = '读取数据时发生错误: ' + error.message;
        }
    }

    // 移除初始IP加载，改为在前端动态加载
    const cfIPs = []; // 初始为空数组

    // 判断是否为中国用户
    const isChina = country === 'CN';
    const countryDisplayClass = isChina ? '' : 'proxy-warning';
    const countryDisplayText = isChina ? `${country}` : `${country} ⚠️`;

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
    <title>Cloudflare IP优选</title>
    <style>
        body {
            width: 80%;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
            padding: 20px;
        }
        .ip-list {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            max-height: 400px;
            overflow-y: auto;
        }
        .ip-item {
            margin: 2px 0;
            font-family: monospace;
        }
        .stats {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .test-info {
            margin-top: 15px;
            padding: 12px;
            background-color: #f3e5f5;
            border: 1px solid #ce93d8;
            border-radius: 6px;
            color: #4a148c;
        }
        .test-info p {
            margin: 0;
            font-size: 14px;
            line-height: 1.5;
        }
        .proxy-warning {
            color: #d32f2f !important;
            font-weight: bold !important;
            font-size: 1.1em;
        }
        .warning-notice {
            background-color: #ffebee;
            border: 2px solid #f44336;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            color: #c62828;
        }
        .warning-notice h3 {
            margin: 0 0 10px 0;
            color: #d32f2f;
            font-size: 1.2em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .warning-notice p {
            margin: 8px 0;
            line-height: 1.5;
        }
        .warning-notice ul {
            margin: 10px 0 10px 20px;
            line-height: 1.6;
        }
        .test-controls {
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        .port-selector {
            margin: 10px 0;
        }
        .port-selector label {
            font-weight: bold;
            margin-right: 10px;
        }
        .port-selector select {
            padding: 5px 10px;
            font-size: 14px;
            border: 1px solid #ccc;
            border-radius: 3px;
        }
        .button-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 15px;
        }
        .test-button {
            background-color: #4CAF50;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .test-button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .save-button {
            background-color: #2196F3;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .save-button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .save-button:not(:disabled):hover {
            background-color: #1976D2;
        }
        .append-button {
            background-color: #FF9800;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .append-button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .append-button:not(:disabled):hover {
            background-color: #F57C00;
        }
        .edit-button {
            background-color: #9C27B0;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .edit-button:hover {
            background-color: #7B1FA2;
        }
        .back-button {
            background-color: #607D8B;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .back-button:hover {
            background-color: #455A64;
        }
        .save-warning {
            margin-top: 10px;
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            border-radius: 6px;
            padding: 12px;
            color: #e65100;
            font-weight: bold;
        }
        .save-warning small {
            font-size: 14px;
            line-height: 1.5;
            display: block;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            display: none;
        }
        .message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .progress {
            width: 100%;
            background-color: #f0f0f0;
            border-radius: 5px;
            margin: 10px 0;
        }
        .progress-bar {
            width: 0%;
            height: 20px;
            background-color: #4CAF50;
            border-radius: 5px;
            transition: width 0.3s;
        }
        .good-latency { color: #4CAF50; font-weight: bold; }
        .medium-latency { color: #FF9800; font-weight: bold; }
        .bad-latency { color: #f44336; font-weight: bold; }
        .show-more-section {
            text-align: center;
            margin: 10px 0;
            padding: 10px;
            background-color: #f0f0f0;
            border-radius: 5px;
        }
        .show-more-btn {
            background-color: #607D8B;
            color: white;
            padding: 8px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.3s;
        }
        .show-more-btn:hover {
            background-color: #455A64;
        }
        .ip-display-info {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        .save-tip {
            margin-top: 15px;
            padding: 12px;
            background-color: #e8f5e8;
            border: 1px solid #4CAF50;
            border-radius: 6px;
            color: #2e7d32;
            font-size: 14px;
            line-height: 1.5;
        }
        .save-tip strong {
            color: #1b5e20;
        }
        .warm-tips {
            margin: 20px 0;
            padding: 15px;
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            border-radius: 8px;
            color: #e65100;
        }
        .warm-tips h3 {
            margin: 0 0 10px 0;
            color: #f57c00;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .warm-tips p {
            margin: 8px 0;
            line-height: 1.6;
            font-size: 14px;
        }
        .warm-tips ul {
            margin: 10px 0 10px 20px;
            line-height: 1.6;
        }
        .warm-tips li {
            margin: 5px 0;
            font-size: 14px;
        }
        .warm-tips strong {
            color: #e65100;
            font-weight: bold;
        }
        .region-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        .region-btn {
            padding: 6px 12px;
            background-color: #e0e0e0;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }
        .region-btn:hover {
            background-color: #d5d5d5;
        }
        .region-btn.active {
            background-color: #2196F3;
            color: white;
        }
    </style>
    </head>
    <body>
    <h1>在线优选IP</h1>
    
    ${!isChina ? `
    <div class="warning-notice">
        <h3>🚨 代理检测警告</h3>
        <p><strong>检测到您当前很可能处于代理/VPN环境中！</strong></p>
        <p>在代理状态下进行的IP优选测试结果将不准确，可能导致：</p>
        <ul>
            <li>延迟数据失真，无法反映真实网络状况</li>
            <li>优选出的IP在直连环境下表现不佳</li>
            <li>测试结果对实际使用场景参考价值有限</li>
        </ul>
        <p><strong>建议操作：</strong>请关闭所有代理软件（VPN、科学上网工具等），确保处于直连网络环境后重新访问本页面。</p>
    </div>
    ` : ''}

    <div class="stats">
        <h2>统计信息</h2>
        <p><strong>您的国家：</strong><span class="${countryDisplayClass}">${countryDisplayText}</span></p>
        <p><strong>获取到的IP总数：</strong><span id="ip-count">点击开始测试后加载</span></p>
        <p><strong>测试进度：</strong><span id="progress-text">未开始</span></p>
        <div class="progress">
            <div class="progress-bar" id="progress-bar"></div>
        </div>
        <div class="test-info">
            <p><strong>📊 测试说明：</strong>当前优选方式仅进行网络延迟测试，主要评估连接响应速度，并未包含带宽速度测试。延迟测试可快速筛选出响应最快的IP节点，适合日常使用场景的初步优选。</p>
        </div>
    </div>
    
    <div class="warm-tips" id="warm-tips">
        <h3>💡 温馨提示</h3>
        <p><strong>优选完成但测试"真连接延迟"为 -1？</strong>这很有可能是您的网络运营商对你的请求进行了阻断。</p>
        <p><strong>建议尝试以下解决方案：</strong></p>
        <ul>
            <li><strong>更换端口：</strong>尝试使用其他端口（如 2053、2083、2087、2096、8443）</li>
            <li><strong>更换IP库：</strong>切换到不同的IP来源（CM整理列表、AS13335、AS209242列表等，但如果你不明白AS24429和AS199524意味着什么，那就不要选。）</li>
            <li><strong>更换自定义域名：</strong>如果您使用的还是免费域名，那么您更应该尝试一下更换自定义域</li>
        </ul>
        <p>💡 <strong>小贴士：</strong>不同地区和网络环境对各端口的支持情况可能不同，多尝试几个端口组合通常能找到适合的IP。</p>
    </div>

    <div class="test-controls">
        <div class="port-selector">
            <label for="ip-source-select">IP库：</label>
            <select id="ip-source-select">
                <option value="official">CF官方列表</option>
                <option value="cm">CM整理列表</option>
                <option value="as13335">AS13335列表</option>
                <option value="as209242">AS209242列表</option>
                <option value="as24429">AS24429列表(Alibaba)</option>
                <option value="as199524">AS199524列表(G-Core)</option>
                <option value="proxyip">反代IP列表</option>
            </select>

            <label for="port-select" style="margin-left: 20px;">端口：</label>
            <select id="port-select">
                <option value="443">443</option>
                <option value="2053">2053</option>
                <option value="2083">2083</option>
                <option value="2087">2087</option>
                <option value="2096">2096</option>
                <option value="8443">8443</option>
            </select>
        </div>
        <div class="button-group">
            <button class="test-button" id="test-btn" onclick="startTest()">开始延迟测试</button>
            <button class="save-button" id="save-btn" onclick="saveIPs()" disabled>覆盖保存优选IP</button>
            <button class="append-button" id="append-btn" onclick="appendIPs()" disabled>追加保存优选IP</button>
            <button class="edit-button" id="edit-btn" onclick="goEdit()">编辑优选列表</button>
            <button class="back-button" id="back-btn" onclick="goBack()">返回配置页</button>
        </div>
        <div class="save-warning">
            <small>⚠️ 重要提醒："覆盖保存优选IP"会完全覆盖当前 addresses/ADD 优选内容，请慎重考虑！建议优先使用"追加保存优选IP"功能。</small>
        </div>
        <div class="save-tip">
            <strong>💡 保存提示：</strong>[<strong>覆盖保存优选IP</strong>] 和 [<strong>追加保存优选IP</strong>] 功能仅会保存延迟最低的<strong>前16个优选IP</strong>。如需添加更多IP或进行自定义编辑，请使用 [<strong>编辑优选列表</strong>] 功能。
        </div>
        <div id="message" class="message"></div>
    </div>
    
    <h2>IP列表 <span id="result-count"></span></h2>
    <div class="ip-display-info" id="ip-display-info"></div>
    <div id="region-filter" style="margin: 15px 0; display: none;"></div>
    <div class="ip-list" id="ip-list">
        <div class="ip-item">请选择端口和IP库，然后点击"开始延迟测试"加载IP列表</div>
    </div>
    <div class="show-more-section" id="show-more-section" style="display: none;">
        <button class="show-more-btn" id="show-more-btn" onclick="toggleShowMore()">显示更多</button>
    </div>
    
    <script>
        let originalIPs = []; // 改为动态加载
        let testResults = [];
        let displayedResults = []; // 新增：存储当前显示的结果
        let showingAll = false; // 新增：标记是否显示全部内容
        let currentDisplayType = 'loading'; // 新增：当前显示类型 'loading' | 'results'
        let cloudflareLocations = {}; // 新增：存储Cloudflare位置信息
        
        // 新增：本地存储管理
        const StorageKeys = {
            PORT: 'cf-ip-test-port',
            IP_SOURCE: 'cf-ip-test-source'
        };
        
        // 新增：加载Cloudflare位置信息
        async function loadCloudflareLocations() {
            try {
                const response = await fetch('https://speed.cloudflare.com/locations');
                if (response.ok) {
                    const locations = await response.json();
                    // 转换为以iata为key的对象，便于快速查找
                    cloudflareLocations = {};
                    locations.forEach(location => {
                        cloudflareLocations[location.iata] = location;
                    });
                    console.log('Cloudflare位置信息加载成功:', Object.keys(cloudflareLocations).length, '个位置');
                } else {
                    console.warn('无法加载Cloudflare位置信息，将使用原始colo值');
                }
            } catch (error) {
                console.error('加载Cloudflare位置信息失败:', error);
                console.warn('将使用原始colo值');
            }
        }
        
        // 初始化页面设置
        function initializeSettings() {
            const portSelect = document.getElementById('port-select');
            const ipSourceSelect = document.getElementById('ip-source-select');
            
            // 从本地存储读取上次的选择
            const savedPort = localStorage.getItem(StorageKeys.PORT);
            const savedIPSource = localStorage.getItem(StorageKeys.IP_SOURCE);
            
            // 恢复端口选择
            if (savedPort && portSelect.querySelector(\`option[value="\${savedPort}"]\`)) {
                portSelect.value = savedPort;
            } else {
                portSelect.value = '8443'; // 默认值
            }
            
            // 恢复IP库选择
            if (savedIPSource && ipSourceSelect.querySelector(\`option[value="\${savedIPSource}"]\`)) {
                ipSourceSelect.value = savedIPSource;
            } else {
                ipSourceSelect.value = 'official'; // 默认值改为CF官方列表
            }
            
            // 添加事件监听器保存选择
            portSelect.addEventListener('change', function() {
                localStorage.setItem(StorageKeys.PORT, this.value);
            });
            
            ipSourceSelect.addEventListener('change', function() {
                localStorage.setItem(StorageKeys.IP_SOURCE, this.value);
            });
        }
        
        // 页面加载完成后初始化设置
        document.addEventListener('DOMContentLoaded', async function() {
            // 先加载Cloudflare位置信息
            await loadCloudflareLocations();
            // 然后初始化页面设置
            initializeSettings();
        });
        
        // 新增：切换显示更多/更少
        function toggleShowMore() {
            // 在测试过程中不允许切换显示
            if (currentDisplayType === 'testing') {
                return;
            }
            
            showingAll = !showingAll;
            
            if (currentDisplayType === 'loading') {
                displayLoadedIPs();
            } else if (currentDisplayType === 'results') {
                displayResults();
            }
        }
        
        // 新增：显示加载的IP列表
        function displayLoadedIPs() {
            const ipList = document.getElementById('ip-list');
            const showMoreSection = document.getElementById('show-more-section');
            const showMoreBtn = document.getElementById('show-more-btn');
            const ipDisplayInfo = document.getElementById('ip-display-info');
            
            if (originalIPs.length === 0) {
                ipList.innerHTML = '<div class="ip-item">加载IP列表失败，请重试</div>';
                showMoreSection.style.display = 'none';
                ipDisplayInfo.textContent = '';
                return;
            }
            
            const displayCount = showingAll ? originalIPs.length : Math.min(originalIPs.length, 16);
            const displayIPs = originalIPs.slice(0, displayCount);
            
            // 更新显示信息
            if (originalIPs.length <= 16) {
                ipDisplayInfo.textContent = \`显示全部 \${originalIPs.length} 个IP\`;
                showMoreSection.style.display = 'none';
            } else {
                ipDisplayInfo.textContent = \`显示前 \${displayCount} 个IP，共加载 \${originalIPs.length} 个IP\`;
                // 只在非测试状态下显示"显示更多"按钮
                if (currentDisplayType !== 'testing') {
                    showMoreSection.style.display = 'block';
                    showMoreBtn.textContent = showingAll ? '显示更少' : '显示更多';
                    showMoreBtn.disabled = false;
                } else {
                    showMoreSection.style.display = 'none';
                }
            }
            
            // 显示IP列表
            ipList.innerHTML = displayIPs.map(ip => \`<div class="ip-item">\${ip}</div>\`).join('');
        }
        
        function showMessage(text, type = 'success') {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = text;
            messageDiv.className = \`message \${type}\`;
            messageDiv.style.display = 'block';
            
            // 3秒后自动隐藏消息
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 3000);
        }
        
        function updateButtonStates() {
            const saveBtn = document.getElementById('save-btn');
            const appendBtn = document.getElementById('append-btn');
            const hasResults = displayedResults.length > 0;
            
            saveBtn.disabled = !hasResults;
            appendBtn.disabled = !hasResults;
        }
        
        function disableAllButtons() {
            const testBtn = document.getElementById('test-btn');
            const saveBtn = document.getElementById('save-btn');
            const appendBtn = document.getElementById('append-btn');
            const editBtn = document.getElementById('edit-btn');
            const backBtn = document.getElementById('back-btn');
            const portSelect = document.getElementById('port-select');
            const ipSourceSelect = document.getElementById('ip-source-select');
            
            testBtn.disabled = true;
            saveBtn.disabled = true;
            appendBtn.disabled = true;
            editBtn.disabled = true;
            backBtn.disabled = true;
            portSelect.disabled = true;
            ipSourceSelect.disabled = true;
        }
        
        function enableButtons() {
            const testBtn = document.getElementById('test-btn');
            const editBtn = document.getElementById('edit-btn');
            const backBtn = document.getElementById('back-btn');
            const portSelect = document.getElementById('port-select');
            const ipSourceSelect = document.getElementById('ip-source-select');
            
            testBtn.disabled = false;
            editBtn.disabled = false;
            backBtn.disabled = false;
            portSelect.disabled = false;
            ipSourceSelect.disabled = false;
            updateButtonStates();
        }
        
        async function saveIPs() {
            // 使用当前显示的结果而不是全部结果
            let ipsToSave = [];
            if (document.getElementById('region-filter') && document.getElementById('region-filter').style.display !== 'none') {
                // 如果地区筛选器可见，使用筛选后的结果
                ipsToSave = displayedResults;
            } else {
                // 否则使用全部测试结果
                ipsToSave = testResults;
            }
            
            if (ipsToSave.length === 0) {
                showMessage('没有可保存的IP结果', 'error');
                return;
            }
            
            const saveBtn = document.getElementById('save-btn');
            const originalText = saveBtn.textContent;
            
            // 禁用所有按钮
            disableAllButtons();
            saveBtn.textContent = '保存中...';
            
            try {
                // 只保存前16个最优IP
                const saveCount = Math.min(ipsToSave.length, 16);
                const ips = ipsToSave.slice(0, saveCount).map(result => result.display);
                
                const response = await fetch('?action=save', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ ips })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage(data.message + '（已保存前' + saveCount + '个最优IP）', 'success');
                } else {
                    showMessage(data.error || '保存失败', 'error');
                }
                
            } catch (error) {
                showMessage('保存失败: ' + error.message, 'error');
            } finally {
                saveBtn.textContent = originalText;
                enableButtons();
            }
        }
        
        async function appendIPs() {
            // 使用当前显示的结果而不是全部结果
            let ipsToAppend = [];
            if (document.getElementById('region-filter') && document.getElementById('region-filter').style.display !== 'none') {
                // 如果地区筛选器可见，使用筛选后的结果
                ipsToAppend = displayedResults;
            } else {
                // 否则使用全部测试结果
                ipsToAppend = testResults;
            }
            
            if (ipsToAppend.length === 0) {
                showMessage('没有可追加的IP结果', 'error');
                return;
            }
            
            const appendBtn = document.getElementById('append-btn');
            const originalText = appendBtn.textContent;
            
            // 禁用所有按钮
            disableAllButtons();
            appendBtn.textContent = '追加中...';
            
            try {
                // 只追加前16个最优IP
                const saveCount = Math.min(ipsToAppend.length, 16);
                const ips = ipsToAppend.slice(0, saveCount).map(result => result.display);
                
                const response = await fetch('?action=append', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ ips })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage(data.message + '（已追加前' + saveCount + '个最优IP）', 'success');
                } else {
                    showMessage(data.error || '追加失败', 'error');
                }
                
            } catch (error) {
                showMessage('追加失败: ' + error.message, 'error');
            } finally {
                appendBtn.textContent = originalText;
                enableButtons();
            }
        }
        
        function goEdit() {
            const currentUrl = window.location.href;
            const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
            window.location.href = parentUrl + '/edit';
        }
        
        function goBack() {
            const currentUrl = window.location.href;
            const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
            window.location.href = parentUrl;
        }
        
        async function testIP(ip, port) {
            const timeout = 5000; // 增加超时时间到5秒
            
            // 解析IP格式
            const parsedIP = parseIPFormat(ip, port);
            if (!parsedIP) {
                return null;
            }
            
            // 进行测试，最多重试3次
            let lastError = null;
            for (let attempt = 1; attempt <= 3; attempt++) {
                const result = await singleTest(parsedIP.host, parsedIP.port, timeout);
                if (result) {
                    console.log(\`IP \${parsedIP.host}:\${parsedIP.port} 第\${attempt}次测试成功: \${result.latency}ms, colo: \${result.colo}, 类型: \${result.type}\`);
                    
                    // 根据colo字段获取国家代码
                    const locationCode = cloudflareLocations[result.colo] ? cloudflareLocations[result.colo].cca2 : result.colo;
                    
                    // 生成显示格式
                    const typeText = result.type === 'official' ? '官方优选' : '反代优选';
                    const display = \`\${parsedIP.host}:\${parsedIP.port}#\${locationCode} \${typeText} \${result.latency}ms\`;
                    
                    return {
                        ip: parsedIP.host,
                        port: parsedIP.port,
                        latency: result.latency,
                        colo: result.colo,
                        type: result.type,
                        locationCode: locationCode,
                        comment: \`\${locationCode} \${typeText}\`,
                        display: display
                    };
                } else {
                    console.log(\`IP \${parsedIP.host}:\${parsedIP.port} 第\${attempt}次测试失败\`);
                    if (attempt < 3) {
                        // 短暂延迟后重试
                        await new Promise(resolve => setTimeout(resolve, 200));
                    }
                }
            }
            
            return null; // 所有尝试都失败
        }
        
        // 新增：解析IP格式的函数
        function parseIPFormat(ipString, defaultPort) {
            try {
                let host, port, comment;
                
                // 先处理注释部分（#之后的内容）
                let mainPart = ipString;
                if (ipString.includes('#')) {
                    const parts = ipString.split('#');
                    mainPart = parts[0];
                    comment = parts[1];
                }
                
                // 处理端口部分
                if (mainPart.includes(':')) {
                    const parts = mainPart.split(':');
                    host = parts[0];
                    port = parseInt(parts[1]);
                } else {
                    host = mainPart;
                    port = parseInt(defaultPort);
                }
                
                // 验证IP格式
                if (!host || !port || isNaN(port)) {
                    return null;
                }
                
                return {
                    host: host.trim(),
                    port: port,
                    comment: comment ? comment.trim() : null
                };
            } catch (error) {
                console.error('解析IP格式失败:', ipString, error);
                return null;
            }
        }
        
        async function singleTest(ip, port, timeout) {
            // 先进行预请求以缓存DNS解析结果
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeout);
                const parts = ip.split('.').map(part => {
                    const hex = parseInt(part, 10).toString(16);
                    return hex.length === 1 ? '0' + hex : hex; // 补零
                });
                const nip = parts.join('');
                
                // 预请求，不计入延迟时间
                await fetch('https://' + nip + '.${nipDomain}:' + port + '/cdn-cgi/trace', {
                    signal: controller.signal,
                    mode: 'cors'
                });
                
                clearTimeout(timeoutId);
            } catch (preRequestError) {
                // 预请求失败可以忽略，继续进行正式测试
                console.log('预请求失败 (' + ip + ':' + port + '):', preRequestError.message);
            }
            
            // 正式延迟测试
            const startTime = Date.now();
            
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), timeout);
                const parts = ip.split('.').map(part => {
                    const hex = parseInt(part, 10).toString(16);
                    return hex.length === 1 ? '0' + hex : hex; // 补零
                });
                const nip = parts.join('');
                const response = await fetch('https://' + nip + '.${nipDomain}:' + port + '/cdn-cgi/trace', {
                    signal: controller.signal,
                    mode: 'cors'
                });
                
                clearTimeout(timeoutId);
                
                // 检查响应状态
                if (response.status === 200) {
                    const latency = Date.now() - startTime;
                    const responseText = await response.text();
                    
                    // 解析trace响应
                    const traceData = parseTraceResponse(responseText);
                    
                    if (traceData && traceData.ip && traceData.colo) {
                        // 判断IP类型
                        const responseIP = traceData.ip;
                        let ipType = 'official'; // 默认官方IP
                        
                        // 检查是否是IPv6（包含冒号）或者IP相等
                        if (responseIP.includes(':') || responseIP === ip) {
                            ipType = 'proxy'; // 反代IP
                        }
                        // 如果responseIP与ip不相等且不是IPv6，则是官方IP
                        
                        return {
                            ip: ip,
                            port: port,
                            latency: latency,
                            colo: traceData.colo,
                            type: ipType,
                            responseIP: responseIP
                        };
                    }
                }
                
                return null;
                
            } catch (error) {
                const latency = Date.now() - startTime;
                
                // 检查是否是真正的超时（接近设定的timeout时间）
                if (latency >= timeout - 100) {
                    return null;
                }
                
                return null;
            }
        }
        
        // 新增：解析trace响应的函数
        function parseTraceResponse(responseText) {
            try {
                const lines = responseText.split('\\n');
                const data = {};
                
                for (const line of lines) {
                    const trimmedLine = line.trim();
                    if (trimmedLine && trimmedLine.includes('=')) {
                        const [key, value] = trimmedLine.split('=', 2);
                        data[key] = value;
                    }
                }
                
                return data;
            } catch (error) {
                console.error('解析trace响应失败:', error);
                return null;
            }
        }
        
        async function testIPsWithConcurrency(ips, port, maxConcurrency = 32) {
            const results = [];
            const totalIPs = ips.length;
            let completedTests = 0;
            
            const progressBar = document.getElementById('progress-bar');
            const progressText = document.getElementById('progress-text');
            
            // 创建工作队列
            let index = 0;
            
            async function worker() {
                while (index < ips.length) {
                    const currentIndex = index++;
                    const ip = ips[currentIndex];
                    
                    const result = await testIP(ip, port);
                    if (result) {
                        results.push(result);
                    }
                    
                    completedTests++;
                    
                    // 更新进度
                    const progress = (completedTests / totalIPs) * 100;
                    progressBar.style.width = progress + '%';
                    progressText.textContent = \`\${completedTests}/\${totalIPs} (\${progress.toFixed(1)}%) - 有效IP: \${results.length}\`;
                }
            }
            
            // 创建工作线程
            const workers = Array(Math.min(maxConcurrency, ips.length))
                .fill()
                .map(() => worker());
            
            await Promise.all(workers);
            
            return results;
        }
        
        async function startTest() {
            const testBtn = document.getElementById('test-btn');
            const portSelect = document.getElementById('port-select');
            const ipSourceSelect = document.getElementById('ip-source-select');
            const progressBar = document.getElementById('progress-bar');
            const progressText = document.getElementById('progress-text');
            const ipList = document.getElementById('ip-list');
            const resultCount = document.getElementById('result-count');
            const ipCount = document.getElementById('ip-count');
            const ipDisplayInfo = document.getElementById('ip-display-info');
            const showMoreSection = document.getElementById('show-more-section');
            
            const selectedPort = portSelect.value;
            const selectedIPSource = ipSourceSelect.value;
            
            // 保存当前选择到本地存储
            localStorage.setItem(StorageKeys.PORT, selectedPort);
            localStorage.setItem(StorageKeys.IP_SOURCE, selectedIPSource);
            
            testBtn.disabled = true;
            testBtn.textContent = '加载IP列表...';
            portSelect.disabled = true;
            ipSourceSelect.disabled = true;
            testResults = [];
            displayedResults = []; // 重置显示结果
            showingAll = false; // 重置显示状态
            currentDisplayType = 'loading'; // 设置当前显示类型
            ipList.innerHTML = '<div class="ip-item">正在加载IP列表，请稍候...</div>';
            ipDisplayInfo.textContent = '';
            showMoreSection.style.display = 'none';
            updateButtonStates(); // 更新按钮状态
            
            // 重置进度条
            progressBar.style.width = '0%';
            
            // 根据IP库类型显示对应的加载信息
            let ipSourceName = '';
            switch(selectedIPSource) {
                case 'official':
                    ipSourceName = 'CF官方';
                    break;
                case 'cm':
                    ipSourceName = 'CM整理';
                    break;
                case 'as13335':
                    ipSourceName = 'CF全段';
                    break;
                case 'as209242':
                    ipSourceName = 'CF非官方';
                    break;
                case 'as24429':
                    ipSourceName = 'Alibaba';
                    break;
                case 'as199524':
                    ipSourceName = 'G-Core';
                    break;
                case 'proxyip':
                    ipSourceName = '反代IP';
                    break;
                default:
                    ipSourceName = '未知';
            }
            
            progressText.textContent = '正在加载 ' + ipSourceName + ' IP列表...';
            
            // 加载IP列表
            originalIPs = await loadIPs(selectedIPSource, selectedPort);

            if (originalIPs.length === 0) {
                ipList.innerHTML = '<div class="ip-item">加载IP列表失败，请重试</div>';
                ipCount.textContent = '0 个';
                testBtn.disabled = false;
                testBtn.textContent = '开始延迟测试';
                portSelect.disabled = false;
                ipSourceSelect.disabled = false;
                progressText.textContent = '加载失败';
                return;
            }
            
            // 更新IP数量显示
            ipCount.textContent = originalIPs.length + ' 个';
            
            // 显示加载的IP列表（默认显示前16个）
            displayLoadedIPs();
            
            // 开始测试
            testBtn.textContent = '测试中...';
            progressText.textContent = '开始测试端口 ' + selectedPort + '...';
            currentDisplayType = 'testing'; // 切换到测试状态
            
            // 在测试开始时隐藏显示更多按钮
            showMoreSection.style.display = 'none';
            
            // 使用更高的并发数（从16增加到32）来加快测试速度
            const results = await testIPsWithConcurrency(originalIPs, selectedPort, 32);
            
            // 按延迟排序
            testResults = results.sort((a, b) => a.latency - b.latency);
            
            // 显示结果
            currentDisplayType = 'results'; // 切换到结果显示状态
            showingAll = false; // 重置显示状态
            displayResults();
            
            // 创建地区筛选器
            createRegionFilter();
            
            testBtn.disabled = false;
            testBtn.textContent = '重新测试';
            portSelect.disabled = false;
            ipSourceSelect.disabled = false;
            progressText.textContent = '完成 - 有效IP: ' + testResults.length + '/' + originalIPs.length + ' (端口: ' + selectedPort + ', IP库: ' + ipSourceName + ')';
        }
        
        // 新增：加载IP列表的函数
        async function loadIPs(ipSource, port) {
            try {
                const response = await fetch(\`?loadIPs=\${ipSource}&port=\${port}\`, {
                    method: 'GET'
                });
                
                if (!response.ok) {
                    throw new Error('Failed to load IPs');
                }
                
                const data = await response.json();
                return data.ips || [];
            } catch (error) {
                console.error('加载IP列表失败:', error);
                return [];
            }
        }
        
        function displayResults() {
            const ipList = document.getElementById('ip-list');
            const resultCount = document.getElementById('result-count');
            const showMoreSection = document.getElementById('show-more-section');
            const showMoreBtn = document.getElementById('show-more-btn');
            const ipDisplayInfo = document.getElementById('ip-display-info');
            
            if (testResults.length === 0) {
                ipList.innerHTML = '<div class="ip-item">未找到有效的IP</div>';
                resultCount.textContent = '';
                ipDisplayInfo.textContent = '';
                showMoreSection.style.display = 'none';
                displayedResults = [];
                updateButtonStates();
                return;
            }
            
            // 确定显示数量
            const maxDisplayCount = showingAll ? testResults.length : Math.min(testResults.length, 16);
            displayedResults = testResults.slice(0, maxDisplayCount);
            
            // 更新结果计数显示
            if (testResults.length <= 16) {
                resultCount.textContent = '(共测试出 ' + testResults.length + ' 个有效IP)';
                ipDisplayInfo.textContent = '显示全部 ' + testResults.length + ' 个测试结果';
                showMoreSection.style.display = 'none';
            } else {
                resultCount.textContent = '(共测试出 ' + testResults.length + ' 个有效IP)';
                ipDisplayInfo.textContent = '显示前 ' + maxDisplayCount + ' 个测试结果，共 ' + testResults.length + ' 个有效IP';
                showMoreSection.style.display = 'block';
                showMoreBtn.textContent = showingAll ? '显示更少' : '显示更多';
                showMoreBtn.disabled = false; // 确保在结果显示时启用按钮
            }
            
            const resultsHTML = displayedResults.map(result => {
                let className = 'good-latency';
                if (result.latency > 200) className = 'bad-latency';
                else if (result.latency > 100) className = 'medium-latency';
                
                return '<div class="ip-item ' + className + '">' + result.display + '</div>';
            }).join('');
            
            ipList.innerHTML = resultsHTML;
            updateButtonStates();
        }
        
        // 新增：创建地区筛选器
        function createRegionFilter() {
            // 获取所有唯一的地区代码（使用cca2代码）
            const uniqueRegions = [...new Set(testResults.map(result => result.locationCode))];
            uniqueRegions.sort(); // 按字母顺序排序
            
            const filterContainer = document.getElementById('region-filter');
            if (!filterContainer) return;
            
            if (uniqueRegions.length === 0) {
                filterContainer.style.display = 'none';
                return;
            }
            
            // 创建筛选按钮
            let filterHTML = '<h3>地区筛选：</h3><div class="region-buttons">';
            filterHTML += '<button class="region-btn active" data-region="all">全部 (' + testResults.length + ')</button>';
            
            uniqueRegions.forEach(region => {
                const count = testResults.filter(r => r.locationCode === region).length;
                filterHTML += '<button class="region-btn" data-region="' + region + '">' + region + ' (' + count + ')</button>';
            });
            
            filterHTML += '</div>';
            filterContainer.innerHTML = filterHTML;
            filterContainer.style.display = 'block';
            
            // 添加点击事件
            document.querySelectorAll('.region-btn').forEach(button => {
                button.addEventListener('click', function() {
                    // 更新活动按钮
                    document.querySelectorAll('.region-btn').forEach(btn => {
                        btn.classList.remove('active');
                    });
                    this.classList.add('active');
                    
                    // 筛选结果
                    const selectedRegion = this.getAttribute('data-region');
                    if (selectedRegion === 'all') {
                        displayedResults = [...testResults];
                    } else {
                        displayedResults = testResults.filter(result => result.locationCode === selectedRegion);
                    }
                    
                    // 重置显示状态
                    showingAll = false;
                    displayFilteredResults();
                });
            });
        }
        
        // 新增：显示筛选后的结果
        function displayFilteredResults() {
            const ipList = document.getElementById('ip-list');
            const resultCount = document.getElementById('result-count');
            const showMoreSection = document.getElementById('show-more-section');
            const showMoreBtn = document.getElementById('show-more-btn');
            const ipDisplayInfo = document.getElementById('ip-display-info');
            
            if (displayedResults.length === 0) {
                ipList.innerHTML = '<div class="ip-item">未找到有效的IP</div>';
                resultCount.textContent = '';
                ipDisplayInfo.textContent = '';
                showMoreSection.style.display = 'none';
                updateButtonStates();
                return;
            }
            
            // 确定显示数量
            const maxDisplayCount = showingAll ? displayedResults.length : Math.min(displayedResults.length, 16);
            const currentResults = displayedResults.slice(0, maxDisplayCount);
            
            // 更新结果计数显示
            const totalCount = testResults.length;
            const filteredCount = displayedResults.length;
            
            if (filteredCount <= 16) {
                resultCount.textContent = '(共测试出 ' + totalCount + ' 个有效IP，筛选出 ' + filteredCount + ' 个)';
                ipDisplayInfo.textContent = '显示全部 ' + filteredCount + ' 个筛选结果';
                showMoreSection.style.display = 'none';
            } else {
                resultCount.textContent = '(共测试出 ' + totalCount + ' 个有效IP，筛选出 ' + filteredCount + ' 个)';
                ipDisplayInfo.textContent = '显示前 ' + maxDisplayCount + ' 个筛选结果，共 ' + filteredCount + ' 个';
                showMoreSection.style.display = 'block';
                showMoreBtn.textContent = showingAll ? '显示更少' : '显示更多';
                showMoreBtn.disabled = false;
            }
            
            const resultsHTML = currentResults.map(result => {
                let className = 'good-latency';
                if (result.latency > 200) className = 'bad-latency';
                else if (result.latency > 100) className = 'medium-latency';
                
                return '<div class="ip-item ' + className + '">' + result.display + '</div>';
            }).join('');
            
            ipList.innerHTML = resultsHTML;
            updateButtonStates();
        }
    </script>
    
    </body>
    </html>
    `;

    // 处理加载IP的请求
    if (url.searchParams.get('loadIPs')) {
        const ipSource = url.searchParams.get('loadIPs');
        const port = url.searchParams.get('port') || '443';
        const ips = await GetCFIPs(ipSource, port);

        return new Response(JSON.stringify({ ips }), {
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    return new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
        },
    });
}

/**
 * 获取 Cloudflare 账户今日使用量统计
 * @param {string} accountId - 账户ID（可选，如果没有会自动获取）
 * @param {string} email - Cloudflare 账户邮箱
 * @param {string} apikey - Cloudflare API 密钥
 * @param {string} apitoken - Cloudflare API 令牌
 * @param {number} all - 总限额，默认10万次
 * @returns {Array} [总限额, Pages请求数, Workers请求数, 总请求数]
 */
async function getUsage(accountId, email, apikey, apitoken, all = 100000) {
    /**
     * 获取 Cloudflare 账户ID
     * @param {string} email - 账户邮箱
     * @param {string} apikey - API密钥
     * @param {number} accountIndex - 取第几个账户，默认第0个
     * @returns {string} 账户ID
     */
    async function getAccountId(email, apikey) {
        console.log('正在获取账户信息...');

        const response = await fetch("https://api.cloudflare.com/client/v4/accounts", {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "X-AUTH-EMAIL": email,
                "X-AUTH-KEY": apikey,
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`获取账户信息失败: ${response.status} ${response.statusText}`, errorText);
            throw new Error(`Cloudflare API 请求失败: ${response.status} ${response.statusText} - ${errorText}`);
        }

        const res = await response.json();
        //console.log(res);

        let accountIndex = 0; // 默认取第一个账户
        let foundMatch = false; // 标记是否找到匹配的账户

        // 如果有多个账户，智能匹配包含邮箱前缀的账户
        if (res?.result && res.result.length > 1) {
            console.log(`发现 ${res.result.length} 个账户，正在智能匹配...`);

            // 提取邮箱前缀并转为小写
            const emailPrefix = email.toLowerCase();
            console.log(`邮箱: ${emailPrefix}`);

            // 遍历所有账户，寻找名称开头包含邮箱前缀的账户
            for (let i = 0; i < res.result.length; i++) {
                const accountName = res.result[i]?.name?.toLowerCase() || '';
                console.log(`检查账户 ${i}: ${res.result[i]?.name}`);

                // 检查账户名称开头是否包含邮箱前缀
                if (accountName.startsWith(emailPrefix)) {
                    accountIndex = i;
                    foundMatch = true;
                    console.log(`✅ 找到匹配账户，使用第 ${i} 个账户`);
                    break;
                }
            }

            // 如果遍历完还没找到匹配的，使用默认值0
            if (!foundMatch) {
                console.log('❌ 未找到匹配的账户，使用默认第 0 个账户');
            }
        } else if (res?.result && res.result.length === 1) {
            console.log('只有一个账户，使用第 0 个账户');
            foundMatch = true;
        }

        const name = res?.result?.[accountIndex]?.name;
        const id = res?.result?.[accountIndex]?.id;

        console.log(`最终选择账户 ${accountIndex} - 名称: ${name}, ID: ${id}`);

        if (!id) {
            throw new Error("找不到有效的账户ID，请检查API权限");
        }

        return id;
    }

    try {
        // 如果没有提供账户ID，就自动获取
        if (!accountId) {
            console.log('未提供账户ID，正在自动获取...');
            accountId = await getAccountId(email, apikey);
        }

        // 设置查询时间范围：今天0点到现在
        const now = new Date();
        const endDate = now.toISOString(); // 结束时间：现在

        // 设置开始时间为今天凌晨0点
        now.setUTCHours(0, 0, 0, 0);
        const startDate = now.toISOString(); // 开始时间：今天0点

        console.log(`查询时间范围: ${startDate} 到 ${endDate}`);
        // 准备请求头
        let headers = {}
        if (apikey) {
            headers = {
                "Content-Type": "application/json",
                "X-AUTH-EMAIL": email,
                "X-AUTH-KEY": apikey,
            };
        }
        if (apitoken) {
            headers = {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apitoken}`,
            }
        }

        // 向 Cloudflare GraphQL API 发送请求，获取今日使用量
        const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
            method: "POST",
            headers: headers,
            body: JSON.stringify({
                // GraphQL 查询语句：获取 Pages 和 Workers 的请求数统计
                query: `query getBillingMetrics($accountId: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer {
                        accounts(filter: {accountTag: $accountId}) {
                            pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) {
                                sum {
                                    requests
                                }
                            }
                            workersInvocationsAdaptive(limit: 10000, filter: $filter) {
                                sum {
                                    requests
                                }
                            }
                        }
                    }
                }`,
                variables: {
                    accountId: accountId,
                    filter: {
                        datetime_geq: startDate, // 大于等于开始时间
                        datetime_leq: endDate    // 小于等于结束时间
                    },
                },
            }),
        });

        // 检查API请求是否成功
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`GraphQL查询失败: ${response.status} ${response.statusText}`, errorText);
            console.log('返回默认值：全部为0');
            return [all, 0, 0, 0];
        }

        const res = await response.json();

        // 检查GraphQL响应是否有错误
        if (res.errors && res.errors.length > 0) {
            console.error('GraphQL查询错误:', res.errors[0].message);
            console.log('返回默认值：全部为0');
            return [all, 0, 0, 0];
        }

        // 从响应中提取账户数据
        const accounts = res?.data?.viewer?.accounts?.[0];

        if (!accounts) {
            console.warn('未找到账户数据');
            return [all, 0, 0, 0];
        }

        // 计算 Pages 请求数（Cloudflare Pages 的请求统计）
        const pagesArray = accounts?.pagesFunctionsInvocationsAdaptiveGroups || [];
        const pages = pagesArray.reduce((total, item) => {
            return total + (item?.sum?.requests || 0);
        }, 0);

        // 计算 Workers 请求数（Cloudflare Workers 的请求统计）
        const workersArray = accounts?.workersInvocationsAdaptive || [];
        const workers = workersArray.reduce((total, item) => {
            return total + (item?.sum?.requests || 0);
        }, 0);

        // 计算总请求数
        const total = pages + workers;

        console.log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}`);

        // 返回格式：[总限额, Pages请求数, Workers请求数, 总请求数]
        return [all, pages || 0, workers || 0, total || 0];

    } catch (error) {
        console.error('获取使用量时发生错误:', error.message);
        // 发生错误时返回默认值
        return [all, 0, 0, 0];
    }
}

async function nginx() {
    const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
    return text;
}
