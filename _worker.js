// src/worker.js
import { connect } from "cloudflare:sockets";
 
let Pswd = "trojan";
const proxyIPs = ["pyip.ygkkk.dpdns.org"]; //""之间填写proxyip，留空将无法访问CF网站
let cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
// http_ip
let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP3 = '\u0061\u0066\u0072\u0069\u0063\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP4 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
let IP5 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074'
let IP6 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074'
let IP7 = '\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d'

// https_ip
let IP8 = '\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP9 = '\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP10 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077'
let IP11 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068'
let IP12 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072'
let IP13 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d'

// http_port
let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

// https_port
let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

let sha224Password;
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.match(/:(\d+)$/) ? proxyIP.match(/:(\d+)$/)[1] : '443';
const worker_default = {
  /**
   * @param {any} request
   * @param {{proxyip: string, pswd: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string}} env
   * @param {any} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      const { proxyip } = env;
			if (proxyip) {
				if (proxyip.includes(']:')) {
					let lastColonIndex = proxyip.lastIndexOf(':');
					proxyPort = proxyip.slice(lastColonIndex + 1);
					proxyIP = proxyip.slice(0, lastColonIndex);
					
				} else if (!proxyip.includes(']:') && !proxyip.includes(']')) {
					[proxyIP, proxyPort = '443'] = proxyip.split(':');
				} else {
					proxyPort = '443';
					proxyIP = proxyip;
				}				
			} else {
				if (proxyIP.includes(']:')) {
					let lastColonIndex = proxyIP.lastIndexOf(':');
					proxyPort = proxyIP.slice(lastColonIndex + 1);
					proxyIP = proxyIP.slice(0, lastColonIndex);	
				} else {
					const match = proxyIP.match(/^(.*?)(?::(\d+))?$/);
					proxyIP = match[1];
					let proxyPort = match[2] || '443';
					console.log("IP:", proxyIP, "Port:", proxyPort);
				}
			}
			console.log('ProxyIP:', proxyIP);
			console.log('ProxyPort:', proxyPort);
      CDNIP = env.cdnip || CDNIP;
      Pswd = env.pswd || Pswd;
      IP1 = env.ip1 || IP1;
      IP2 = env.ip2 || IP2;
      IP3 = env.ip3 || IP3;
      IP4 = env.ip4 || IP4;
      IP5 = env.ip5 || IP5;
      IP6 = env.ip6 || IP6;
      IP7 = env.ip7 || IP7;
      IP8 = env.ip8 || IP8;
      IP9 = env.ip9 || IP9;
      IP10 = env.ip10 || IP10;
      IP11 = env.ip11 || IP11;
      IP12 = env.ip12 || IP12;
      IP13 = env.ip13 || IP13;
      PT1 = env.pt1 || PT1;
      PT2 = env.pt2 || PT2;
      PT3 = env.pt3 || PT3;
      PT4 = env.pt4 || PT4;
      PT5 = env.pt5 || PT5;
      PT6 = env.pt6 || PT6;
      PT7 = env.pt7 || PT7;
      PT8 = env.pt8 || PT8;
      PT9 = env.pt9 || PT9;
      PT10 = env.pt10 || PT10;
      PT11 = env.pt11 || PT11;
      PT12 = env.pt12 || PT12;
      PT13 = env.pt13 || PT13;
      sha224Password = sha256.sha224(Pswd);
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/${Pswd}`: {
            const ygkkkConfig = getygkkkConfig(Pswd, request.headers.get("Host"));
            return new Response(`${ygkkkConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
		  case `/${Pswd}/ty`: {
			const tyConfig = gettyConfig(Pswd, request.headers.get('Host'));
			return new Response(`${tyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/cl`: {
			const clConfig = getclConfig(Pswd, request.headers.get('Host'));
			return new Response(`${clConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/sb`: {
			const sbConfig = getsbConfig(Pswd, request.headers.get('Host'));
			return new Response(`${sbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/pty`: {
			const ptyConfig = getptyConfig(Pswd, request.headers.get('Host'));
			return new Response(`${ptyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/pcl`: {
			const pclConfig = getpclConfig(Pswd, request.headers.get('Host'));
			return new Response(`${pclConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${Pswd}/psb`: {
			const psbConfig = getpsbConfig(Pswd, request.headers.get('Host'));
			return new Response(`${psbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
          default:
            // return new Response('Not found', { status: 404 });
            // For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
            if (cn_hostnames.includes('')) {
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
            }
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            // Use fetch to proxy the request to 15 different domains
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            // Check for 302 or 301 redirect status and return an error response
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden",
              });
            }
            // Return the response from the proxy server
            return proxyResponse;
        }
      } else {
			if(url.pathname.includes('/pyip='))
			{
				const tmp_ip=url.pathname.split("=")[1];
				if(isValidIP(tmp_ip))
				{
					proxyIP=tmp_ip;
					if (proxyIP.includes(']:')) {
						let lastColonIndex = proxyIP.lastIndexOf(':');
						proxyPort = proxyIP.slice(lastColonIndex + 1);
						proxyIP = proxyIP.slice(0, lastColonIndex);	
					} else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
						[proxyIP, proxyPort = '443'] = proxyIP.split(':');
					} else {
						proxyPort = '443';
					}
				}	
			}
        return await ygkkkOverWSHandler(request);
		}
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

function isValidIP(ip) {
    var reg = /^[\s\S]*$/;
    return reg.test(ip);
}

async function ygkkkOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }
          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawClientData,
          } = await parseygkkkHeader(chunk);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
          if (hasError) {
            throw new Error(message);
            return;
          }
          handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
          log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });
  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client,
  });
}

async function parseygkkkHeader(buffer) {
  if (buffer.byteLength < 56) {
    return {
      hasError: true,
      message: "invalid data",
    };
  }
  let crLfIndex = 56;
  if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
    return {
      hasError: true,
      message: "invalid header format (missing CR LF)",
    };
  }
  const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
  if (password !== sha224Password) {
    return {
      hasError: true,
      message: "invalid password",
    };
  }

  const socks5DataBuffer = buffer.slice(crLfIndex + 2);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }

  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd !== 1) {
    return {
      hasError: true,
      message: "unsupported command, only TCP (CONNECT) is allowed",
    };
  }

  const atype = view.getUint8(1);
  // 0x01: IPv4 address
  // 0x03: Domain name
  // 0x04: IPv6 address
  let addressLength = 0;
  let addressIndex = 2;
  let address = "";
  switch (atype) {
    case 1:
      addressLength = 4;
      address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
      addressIndex += 1;
      address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      address = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${atype}`,
      };
  }

  if (!address) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${atype}`,
    };
  }

  const portIndex = addressIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: address,
    portRemote,
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
  };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(addressRemote)) addressRemote = `${atob('d3d3Lg==')}${addressRemote}${atob('LnNzbGlwLmlv')}`;
  async function connectAndWrite(address, port) {
    const tcpSocket2 = connect({
      hostname: address,
      port,
    });
    remoteSocket.value = tcpSocket2;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  async function retry() {
    const tcpSocket2 = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote);
    tcpSocket2.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket2, webSocket, null, log);
  }
  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`readableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        /**
         *
         * @param {Uint8Array} chunk
         * @param {*} controller
         */
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket connection is not open");
          }
          webSocket.send(chunk);
        },
        close() {
          log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error("remoteSocket.readable abort", reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS error:`, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
export { worker_default as default };
//# sourceMappingURL=worker.js.map
function getygkkkConfig(Pswd, hostName) {
  const w\u0074\u0072\u006F\u006A\u0061\u006Ews = atob(btoa(`\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}@${CDNIP}:8880?security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`));
  const p\u0074\u0072\u006F\u006A\u0061\u006Ewstls = atob(btoa(`\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}@${CDNIP}:8443?security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`));
  const note = `甬哥博客地址：https://ygkkk.blogspot.com\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP全局运行中：${proxyIP}:${proxyPort}`;
  const ty = `https://${hostName}/${Pswd}/ty`
  const cl = `https://${hostName}/${Pswd}/cl`
  const sb = `https://${hostName}/${Pswd}/sb`
  const pty = `https://${hostName}/${Pswd}/pty`
  const pcl = `https://${hostName}/${Pswd}/pcl`
  const psb = `https://${hostName}/${Pswd}/psb`

  const wk\u0074\u0072\u006F\u006A\u0061\u006Eshare = btoa(`\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T1_${IP1}_${PT1}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T2_${IP2}_${PT2}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T3_${IP3}_${PT3}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T4_${IP4}_${PT4}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T5_${IP5}_${PT5}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T6_${IP6}_${PT6}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T7_${IP7}_${PT7}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T8_${IP8}_${PT8}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T9_${IP9}_${PT9}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T10_${IP10}_${PT10}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T11_${IP11}_${PT11}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T12_${IP12}_${PT12}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T13_${IP13}_${PT13}`);
	
  const pg\u0074\u0072\u006F\u006A\u0061\u006Eshare = btoa(`\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T8_${IP8}_${PT8}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T9_${IP9}_${PT9}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T10_${IP10}_${PT10}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T11_${IP11}_${PT11}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T12_${IP12}_${PT12}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T13_${IP13}_${PT13}`);
	
  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
.limited-width {
    max-width: 200px;
    overflow: auto;
    word-wrap: break-word;
}
</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  alert('已复制到剪贴板');
}
</script>
`;
if (hostName.includes("workers.dev")) {
return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-\u0074\u0072\u006F\u006A\u0061\u006E代理脚本 V25.5.4</h1>
			<hr>
            <p>${noteshow}</p>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>1：CF-workers-\u0074\u0072\u006F\u006A\u0061\u006E+ws节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">关闭了TLS加密，无视域名阻断</td>
						<td class="limited-width">${w\u0074\u0072\u006F\u006A\u0061\u006Ews}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${w\u0074\u0072\u006F\u006A\u0061\u006Ews}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：7个http端口可任意选择(80、8080、8880、2052、2082、2086、2095)，或反代IP对应端口</li>
                <li>密码(password)：${Pswd}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：关闭</li>
            </ul>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>2：CF-workers-\u0074\u0072\u006F\u006A\u0061\u006E+ws+tls</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，建议开启，防止域名阻断</td>
						<td class="limited-width">${p\u0074\u0072\u006F\u006A\u0061\u006Ewstls}</td>	
						<td><button class="btn btn-primary" onclick="copyToClipboard('${p\u0074\u0072\u006F\u006A\u0061\u006Ewstls}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                <li>密码(password)：${Pswd}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：开启</li>
                <li>跳过证书验证(allowlnsecure)：false</li>
			</ul>
			<hr>
			<hr>
			<hr>
			<br>	
			<br>
			<h3>3：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
			<hr>
			<p>注意：<br>1、默认每个订阅链接包含TLS+非TLS共13个端口节点 (Clash节点仅6个TLS节点)<br>2、当前workers域名作为订阅链接，需通过代理进行订阅更新<br>3、如使用的客户端不支持分片功能，则TLS节点不可用</p>	
                        <hr>


			<table class="table">
					<thead>
						<tr>
							<th>聚合通用分享链接 (可直接导入客户端，80系非tls节点在某些客户端可能被强制开启TLS，且不可用)：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><button class="btn btn-primary" onclick="copyToClipboard('${wk\u0074\u0072\u006F\u006A\u0061\u006Eshare}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
   
			<table class="table">
					<thead>
						<tr>
							<th>聚合通用订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${ty}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${ty}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>	

				<table class="table">
						<thead>
							<tr>
								<th>Clash-meta订阅链接：</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td class="limited-width">${cl}</td>	
								<td><button class="btn btn-primary" onclick="copyToClipboard('${cl}')">点击复制链接</button></td>
							</tr>
						</tbody>
					</table>

					<table class="table">
					<thead>
						<tr>
							<th>Sing-box订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${sb}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${sb}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
				<br>
				<br>
        </div>
    </div>
</div>
</body>
`;
  } else {
    return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-\u0074\u0072\u006F\u006A\u0061\u006E代理脚本 V25.5.4</h1>
			<hr>
            <p>${noteshow}</p>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
            <h3>1：CF-pages/workers/自定义域-\u0074\u0072\u006F\u006A\u0061\u006E+ws+tls节点</h3>
			<table class="table">
				<thead>
					<tr>
						<th>节点特色：</th>
						<th>单节点链接如下：</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">启用了TLS加密，<br>如果客户端支持分片(Fragment)功能，可开启，防止域名阻断</td>
						<td class="limited-width">${p\u0074\u0072\u006F\u006A\u0061\u006Ewstls}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${p\u0074\u0072\u006F\u006A\u0061\u006Ewstls}')">点击复制链接</button></td>
					</tr>
				</tbody>
			</table>
            <h5>客户端参数如下：</h5>
            <ul>
                <li>客户端地址(address)：自定义的域名 或者 优选域名 或者 优选IP 或者 反代IP</li>
                <li>端口(port)：6个https端口可任意选择(443、8443、2053、2083、2087、2096)，或反代IP对应端口</li>
                <li>密码(password)：${Pswd}</li>
                <li>传输协议(network)：ws 或者 websocket</li>
                <li>伪装域名(host)：${hostName}</li>
                <li>路径(path)：/?ed=2560</li>
                <li>传输安全(TLS)：开启</li>
                <li>跳过证书验证(allowlnsecure)：false</li>
			</ul>
            <hr>
			<hr>
			<hr>
            <br>
            <br>
			<h3>2：聚合通用、Clash-meta、Sing-box订阅链接如下：</h3>
			<hr>
			<p>注意：以下订阅链接仅6个TLS端口节点</p>
			<hr>

			<table class="table">
					<thead>
						<tr>
							<th>聚合通用分享链接 (可直接导入客户端)：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><button class="btn btn-primary" onclick="copyToClipboard('${pg\u0074\u0072\u006F\u006A\u0061\u006Eshare}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>


			<table class="table">
					<thead>
						<tr>
							<th>聚合通用订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${pty}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${pty}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>	

				<table class="table">
						<thead>
							<tr>
								<th>Clash-meta订阅链接：</th>
							</tr>
						</thead>
						<tbody>
							<tr>
								<td class="limited-width">${pcl}</td>	
								<td><button class="btn btn-primary" onclick="copyToClipboard('${pcl}')">点击复制链接</button></td>
							</tr>
						</tbody>
					</table>

					<table class="table">
					<thead>
						<tr>
							<th>Sing-box订阅链接：</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td class="limited-width">${psb}</td>	
							<td><button class="btn btn-primary" onclick="copyToClipboard('${psb}')">点击复制链接</button></td>
						</tr>
					</tbody>
				</table>
				<br>
				<br>
        </div>
    </div>
</div>
</body>
`;
  }
}

function gettyConfig(Pswd, hostName) {
  const \u0074\u0072\u006F\u006A\u0061\u006Eshare = btoa(`\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T1_${IP1}_${PT1}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T2_${IP2}_${PT2}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T3_${IP3}_${PT3}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T4_${IP4}_${PT4}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T5_${IP5}_${PT5}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T6_${IP6}_${PT6}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T7_${IP7}_${PT7}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T8_${IP8}_${PT8}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T9_${IP9}_${PT9}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T10_${IP10}_${PT10}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T11_${IP11}_${PT11}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T12_${IP12}_${PT12}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T13_${IP13}_${PT13}`);
  return `${\u0074\u0072\u006F\u006A\u0061\u006Eshare}`
}

function getclConfig(Pswd, hostName) {
return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_T8_${IP8}_${PT8}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T9_${IP9}_${PT9}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T10_${IP10}_${PT10}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T11_${IP11}_${PT11}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T12_${IP12}_${PT12}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T13_${IP13}_${PT13}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}
	
function getsbConfig(Pswd, hostName) {
return `{
	  "log": {
		"disabled": false,
		"level": "info",
		"timestamp": true
	  },
	  "experimental": {
		"clash_api": {
		  "external_controller": "127.0.0.1:9090",
		  "external_ui": "ui",
		  "external_ui_download_url": "",
		  "external_ui_download_detour": "",
		  "secret": "",
		  "default_mode": "Rule"
		},
		"cache_file": {
		  "enabled": true,
		  "path": "cache.db",
		  "store_fakeip": true
		}
	  },
	  "dns": {
		"servers": [
		  {
			"tag": "proxydns",
			"address": "tls://8.8.8.8/dns-query",
			"detour": "select"
		  },
		  {
			"tag": "localdns",
			"address": "h3://223.5.5.5/dns-query",
			"detour": "direct"
		  },
		  {
			"tag": "dns_fakeip",
			"address": "fakeip"
		  }
		],
		"rules": [
		  {
			"outbound": "any",
			"server": "localdns",
			"disable_cache": true
		  },
		  {
			"clash_mode": "Global",
			"server": "proxydns"
		  },
		  {
			"clash_mode": "Direct",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-cn",
			"server": "localdns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"server": "proxydns"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"query_type": [
			  "A",
			  "AAAA"
			],
			"server": "dns_fakeip"
		  }
		],
		"fakeip": {
		  "enabled": true,
		  "inet4_range": "198.18.0.0/15",
		  "inet6_range": "fc00::/18"
		},
		"independent_cache": true,
		"final": "proxydns"
	  },
	  "inbounds": [
		{
		  "type": "tun",
                  "tag": "tun-in",
		  "address": [
                    "172.19.0.1/30",
		    "fd00::1/126"
      ],
		  "auto_route": true,
		  "strict_route": true,
		  "sniff": true,
		  "sniff_override_destination": true,
		  "domain_strategy": "prefer_ipv4"
		}
	  ],
	  "outbounds": [
      {
        "tag": "select",
        "type": "selector",
        "default": "auto",
        "outbounds": [
        "auto",
        "CF_T1_${IP1}_${PT1}",
        "CF_T2_${IP2}_${PT2}",
        "CF_T3_${IP3}_${PT3}",
        "CF_T4_${IP4}_${PT4}",
        "CF_T5_${IP5}_${PT5}",
        "CF_T6_${IP6}_${PT6}",
        "CF_T7_${IP7}_${PT7}",
        "CF_T8_${IP8}_${PT8}",
        "CF_T9_${IP9}_${PT9}",
        "CF_T10_${IP10}_${PT10}",
        "CF_T11_${IP11}_${PT11}",
        "CF_T12_${IP12}_${PT12}",
        "CF_T13_${IP13}_${PT13}"
        ]
      },
      {
        "server": "${IP1}",
        "server_port": ${PT1},
        "tag": "CF_T1_${IP1}_${PT1}",
        "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          }, 
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP2}",
        "server_port": ${PT2},
        "tag": "CF_T2_${IP2}_${PT2}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP3}",
        "server_port": ${PT3},
        "tag": "CF_T3_${IP3}_${PT3}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP4}",
        "server_port": ${PT4},
        "tag": "CF_T4_${IP4}_${PT4}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP5}",
        "server_port": ${PT5},
        "tag": "CF_T5_${IP5}_${PT5}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP6}",
        "server_port": ${PT6},
        "tag": "CF_T6_${IP6}_${PT6}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP7}",
        "server_port": ${PT7},
        "tag": "CF_T7_${IP7}_${PT7}",
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP8}",
        "server_port": ${PT8},
        "tag": "CF_T8_${IP8}_${PT8}",
        "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
        "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP9}",
        "server_port": ${PT9},
        "tag": "CF_T9_${IP9}_${PT9}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP10}",
        "server_port": ${PT10},
        "tag": "CF_T10_${IP10}_${PT10}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP11}",
        "server_port": ${PT11},
        "tag": "CF_T11_${IP11}_${PT11}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "server": "${IP12}",
        "server_port": ${PT12},
        "tag": "CF_T12_${IP12}_${PT12}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {     
        "server": "${IP13}",
        "server_port": ${PT13},
        "tag": "CF_T13_${IP13}_${PT13}",
        "tls": {
        "enabled": true,
        "server_name": "${hostName}",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
        },
        "transport": {
        "headers": {
          "Host": [
          "${hostName}"
          ]
        },
        "path": "/?ed=2560",
        "type": "ws"
        },
        "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
        "password": "${Pswd}"
      },
      {
        "tag": "direct",
        "type": "direct"
      },
      {
        "tag": "auto",
        "type": "urltest",
        "outbounds": [
        "CF_T1_${IP1}_${PT1}",
        "CF_T2_${IP2}_${PT2}",
        "CF_T3_${IP3}_${PT3}",
        "CF_T4_${IP4}_${PT4}",
        "CF_T5_${IP5}_${PT5}",
        "CF_T6_${IP6}_${PT6}",
        "CF_T7_${IP7}_${PT7}",
        "CF_T8_${IP8}_${PT8}",
        "CF_T9_${IP9}_${PT9}",
        "CF_T10_${IP10}_${PT10}",
        "CF_T11_${IP11}_${PT11}",
        "CF_T12_${IP12}_${PT12}",
        "CF_T13_${IP13}_${PT13}"
        ],
		  "url": "https://www.gstatic.com/generate_204",
		  "interval": "1m",
		  "tolerance": 50,
		  "interrupt_exist_connections": false
		}
	  ],
	  "route": {
		"rule_set": [
		  {
			"tag": "geosite-geolocation-!cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geosite-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  },
		  {
			"tag": "geoip-cn",
			"type": "remote",
			"format": "binary",
			"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
			"download_detour": "select",
			"update_interval": "1d"
		  }
		],
		"auto_detect_interface": true,
		"final": "select",
		"rules": [
                     {
                     "inbound": "tun-in",
                     "action": "sniff"
                     },
                      {
                    "protocol": "dns",
                    "action": "hijack-dns"
                     },
                      {
                    "port": 443,
                    "network": "udp",
                    "action": "reject"
                    },
		  {
			"clash_mode": "Direct",
			"outbound": "direct"
		  },
		  {
			"clash_mode": "Global",
			"outbound": "select"
		  },
		  {
			"rule_set": "geoip-cn",
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-cn",
			"outbound": "direct"
		  },
		  {
			"ip_is_private": true,
			"outbound": "direct"
		  },
		  {
			"rule_set": "geosite-geolocation-!cn",
			"outbound": "select"
		  }
		]
	  },
	  "ntp": {
		"enabled": true,
		"server": "time.apple.com",
		"server_port": 123,
		"interval": "30m",
		"detour": "direct"
	  }
	}`
}

function getptyConfig(Pswd, hostName) {
  const \u0074\u0072\u006F\u006A\u0061\u006Eshare = btoa(`\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T8_${IP8}_${PT8}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T9_${IP9}_${PT9}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T10_${IP10}_${PT10}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T11_${IP11}_${PT11}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T12_${IP12}_${PT12}\n\u0074\u0072\u006F\u006A\u0061\u006E://${Pswd}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_T13_${IP13}_${PT13}`);
  return `${\u0074\u0072\u006F\u006A\u0061\u006Eshare}`
}
	
function getpclConfig(Pswd, hostName) {
return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_T8_${IP8}_${PT8}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T9_${IP9}_${PT9}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T10_${IP10}_${PT10}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T11_${IP11}_${PT11}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T12_${IP12}_${PT12}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_T13_${IP13}_${PT13}
  type: \u0074\u0072\u006F\u006A\u0061\u006E
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  password: ${Pswd}
  udp: false
  sni: ${hostName}
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_T8_${IP8}_${PT8}
    - CF_T9_${IP9}_${PT9}
    - CF_T10_${IP10}_${PT10}
    - CF_T11_${IP11}_${PT11}
    - CF_T12_${IP12}_${PT12}
    - CF_T13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}
		
function getpsbConfig(Pswd, hostName) {
return `{
		  "log": {
			"disabled": false,
			"level": "info",
			"timestamp": true
		  },
		  "experimental": {
			"clash_api": {
			  "external_controller": "127.0.0.1:9090",
			  "external_ui": "ui",
			  "external_ui_download_url": "",
			  "external_ui_download_detour": "",
			  "secret": "",
			  "default_mode": "Rule"
			},
			"cache_file": {
			  "enabled": true,
			  "path": "cache.db",
			  "store_fakeip": true
			}
		  },
		  "dns": {
			"servers": [
			  {
				"tag": "proxydns",
				"address": "tls://8.8.8.8/dns-query",
				"detour": "select"
			  },
			  {
				"tag": "localdns",
				"address": "h3://223.5.5.5/dns-query",
				"detour": "direct"
			  },
			  {
				"tag": "dns_fakeip",
				"address": "fakeip"
			  }
			],
			"rules": [
			  {
				"outbound": "any",
				"server": "localdns",
				"disable_cache": true
			  },
			  {
				"clash_mode": "Global",
				"server": "proxydns"
			  },
			  {
				"clash_mode": "Direct",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-cn",
				"server": "localdns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"server": "proxydns"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"query_type": [
				  "A",
				  "AAAA"
				],
				"server": "dns_fakeip"
			  }
			],
			"fakeip": {
			  "enabled": true,
			  "inet4_range": "198.18.0.0/15",
			  "inet6_range": "fc00::/18"
			},
			"independent_cache": true,
			"final": "proxydns"
		  },
		  "inbounds": [
			{
			  "type": "tun",
                        "tag": "tun-in",
		  "address": [
                    "172.19.0.1/30",
		    "fd00::1/126"
      ],
			  "auto_route": true,
			  "strict_route": true,
			  "sniff": true,
			  "sniff_override_destination": true,
			  "domain_strategy": "prefer_ipv4"
			}
		  ],
		  "outbounds": [
        {
          "tag": "select",
          "type": "selector",
          "default": "auto",
          "outbounds": [
          "auto",
          "CF_T8_${IP8}_${PT8}",
          "CF_T9_${IP9}_${PT9}",
          "CF_T10_${IP10}_${PT10}",
          "CF_T11_${IP11}_${PT11}",
          "CF_T12_${IP12}_${PT12}",
          "CF_T13_${IP13}_${PT13}"
          ]
        },
        {
          "server": "${IP8}",
          "server_port": ${PT8},
          "tag": "CF_T8_${IP8}_${PT8}",        
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
          "password": "${Pswd}"
        },
        {
          "server": "${IP9}",
          "server_port": ${PT9},
          "tag": "CF_T9_${IP9}_${PT9}", 
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
          "password": "${Pswd}"
        },
        {
          "server": "${IP10}",
          "server_port": ${PT10},
          "tag": "CF_T10_${IP10}_${PT10}", 
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
          "password": "${Pswd}"
        },
        {
          "server": "${IP11}",
          "server_port": ${PT11},
          "tag": "CF_T11_${IP11}_${PT11}",
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
          "password": "${Pswd}"
        },
        {
          "server": "${IP12}",
          "server_port": ${PT12},
          "tag": "CF_T12_${IP12}_${PT12}",
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
          "password": "${Pswd}"
        },
        {
          "server": "${IP13}",
          "server_port": ${PT13},
          "tag": "CF_T13_${IP13}_${PT13}",
          "tls": {
          "enabled": true,
          "server_name": "${hostName}",
          "insecure": false,
          "utls": {
            "enabled": true,
            "fingerprint": "chrome"
          }
          },
          "transport": {
          "headers": {
            "Host": [
            "${hostName}"
            ]
          },
          "path": "/?ed=2560",
          "type": "ws"
          },
          "type": "\u0074\u0072\u006F\u006A\u0061\u006E",
          "password": "${Pswd}"
        },
        {
          "tag": "direct",
          "type": "direct"
        },
        {
          "tag": "auto",
          "type": "urltest",
          "outbounds": [
          "CF_T8_${IP8}_${PT8}",
          "CF_T9_${IP9}_${PT9}",
          "CF_T10_${IP10}_${PT10}",
          "CF_T11_${IP11}_${PT11}",
          "CF_T12_${IP12}_${PT12}",
          "CF_T13_${IP13}_${PT13}"
          ],
			  "url": "https://www.gstatic.com/generate_204",
			  "interval": "1m",
			  "tolerance": 50,
			  "interrupt_exist_connections": false
			}
		  ],
		  "route": {
			"rule_set": [
			  {
				"tag": "geosite-geolocation-!cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geosite-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  },
			  {
				"tag": "geoip-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
				"download_detour": "select",
				"update_interval": "1d"
			  }
			],
			"auto_detect_interface": true,
			"final": "select",
			"rules": [
                            {
                           "inbound": "tun-in",
                           "action": "sniff"
                             },
                             {
                             "protocol": "dns",
                             "action": "hijack-dns"
                               },
                              {
                            "port": 443,
                            "network": "udp",
                            "action": "reject"
                            },
			  {
				"clash_mode": "Direct",
				"outbound": "direct"
			  },
			  {
				"clash_mode": "Global",
				"outbound": "select"
			  },
			  {
				"rule_set": "geoip-cn",
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-cn",
				"outbound": "direct"
			  },
			  {
				"ip_is_private": true,
				"outbound": "direct"
			  },
			  {
				"rule_set": "geosite-geolocation-!cn",
				"outbound": "select"
			  }
			]
		  },
		  "ntp": {
			"enabled": true,
			"server": "time.apple.com",
			"server_port": 123,
			"interval": "30m",
			"detour": "direct"
		  }
		}`;
}

/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.11.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2024
 * @license MIT
 */
/*jslint bitwise: true */
(function () {
  "use strict";

  var ERROR = "input is invalid type";
  var WINDOW = typeof window === "object";
  var root = WINDOW ? window : {};
  if (root.JS_SHA256_NO_WINDOW) {
    WINDOW = false;
  }
  var WEB_WORKER = !WINDOW && typeof self === "object";
  var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === "object" && process.versions && process.versions.node;
  if (NODE_JS) {
    root = global;
  } else if (WEB_WORKER) {
    root = self;
  }
  var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === "object" && module.exports;
  var AMD = typeof define === "function" && define.amd;
  var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== "undefined";
  var HEX_CHARS = "0123456789abcdef".split("");
  var EXTRA = [-2147483648, 8388608, 32768, 128];
  var SHIFT = [24, 16, 8, 0];
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
  ];
  var OUTPUT_TYPES = ["hex", "array", "digest", "arrayBuffer"];

  var blocks = [];

  if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
    Array.isArray = function (obj) {
      return Object.prototype.toString.call(obj) === "[object Array]";
    };
  }

  if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
    ArrayBuffer.isView = function (obj) {
      return typeof obj === "object" && obj.buffer && obj.buffer.constructor === ArrayBuffer;
    };
  }

  var createOutputMethod = function (outputType, is224) {
    return function (message) {
      return new Sha256(is224, true).update(message)[outputType]();
    };
  };

  var createMethod = function (is224) {
    var method = createOutputMethod("hex", is224);
    if (NODE_JS) {
      method = nodeWrap(method, is224);
    }
    method.create = function () {
      return new Sha256(is224);
    };
    method.update = function (message) {
      return method.create().update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createOutputMethod(type, is224);
    }
    return method;
  };

  var nodeWrap = function (method, is224) {
    var crypto = require("crypto");
    var Buffer = require("buffer").Buffer;
    var algorithm = is224 ? "sha224" : "sha256";
    var bufferFrom;
    if (Buffer.from && !root.JS_SHA256_NO_BUFFER_FROM) {
      bufferFrom = Buffer.from;
    } else {
      bufferFrom = function (message) {
        return new Buffer(message);
      };
    }
    var nodeMethod = function (message) {
      if (typeof message === "string") {
        return crypto.createHash(algorithm).update(message, "utf8").digest("hex");
      } else {
        if (message === null || message === undefined) {
          throw new Error(ERROR);
        } else if (message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        }
      }
      if (Array.isArray(message) || ArrayBuffer.isView(message) || message.constructor === Buffer) {
        return crypto.createHash(algorithm).update(bufferFrom(message)).digest("hex");
      } else {
        return method(message);
      }
    };
    return nodeMethod;
  };

  var createHmacOutputMethod = function (outputType, is224) {
    return function (key, message) {
      return new HmacSha256(key, is224, true).update(message)[outputType]();
    };
  };

  var createHmacMethod = function (is224) {
    var method = createHmacOutputMethod("hex", is224);
    method.create = function (key) {
      return new HmacSha256(key, is224);
    };
    method.update = function (key, message) {
      return method.create(key).update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createHmacOutputMethod(type, is224);
    }
    return method;
  };

  function Sha256(is224, sharedMemory) {
    if (sharedMemory) {
      blocks[0] =
        blocks[16] =
        blocks[1] =
        blocks[2] =
        blocks[3] =
        blocks[4] =
        blocks[5] =
        blocks[6] =
        blocks[7] =
        blocks[8] =
        blocks[9] =
        blocks[10] =
        blocks[11] =
        blocks[12] =
        blocks[13] =
        blocks[14] =
        blocks[15] =
          0;
      this.blocks = blocks;
    } else {
      this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    if (is224) {
      this.h0 = 0xc1059ed8;
      this.h1 = 0x367cd507;
      this.h2 = 0x3070dd17;
      this.h3 = 0xf70e5939;
      this.h4 = 0xffc00b31;
      this.h5 = 0x68581511;
      this.h6 = 0x64f98fa7;
      this.h7 = 0xbefa4fa4;
    } else {
      // 256
      this.h0 = 0x6a09e667;
      this.h1 = 0xbb67ae85;
      this.h2 = 0x3c6ef372;
      this.h3 = 0xa54ff53a;
      this.h4 = 0x510e527f;
      this.h5 = 0x9b05688c;
      this.h6 = 0x1f83d9ab;
      this.h7 = 0x5be0cd19;
    }

    this.block = this.start = this.bytes = this.hBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
    this.is224 = is224;
  }

  Sha256.prototype.update = function (message) {
    if (this.finalized) {
      return;
    }
    var notString,
      type = typeof message;
    if (type !== "string") {
      if (type === "object") {
        if (message === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        } else if (!Array.isArray(message)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
      notString = true;
    }
    var code,
      index = 0,
      i,
      length = message.length,
      blocks = this.blocks;
    while (index < length) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        this.block =
          blocks[16] =
          blocks[1] =
          blocks[2] =
          blocks[3] =
          blocks[4] =
          blocks[5] =
          blocks[6] =
          blocks[7] =
          blocks[8] =
          blocks[9] =
          blocks[10] =
          blocks[11] =
          blocks[12] =
          blocks[13] =
          blocks[14] =
          blocks[15] =
            0;
      }

      if (notString) {
        for (i = this.start; index < length && i < 64; ++index) {
          blocks[i >>> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.start; index < length && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >>> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >>> 2] |= (0xc0 | (code >>> 6)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >>> 2] |= (0xe0 | (code >>> 12)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >>> 2] |= (0xf0 | (code >>> 18)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          }
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;
      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this.hash();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }
    if (this.bytes > 4294967295) {
      this.hBytes += (this.bytes / 4294967296) << 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  Sha256.prototype.finalize = function () {
    if (this.finalized) {
      return;
    }
    this.finalized = true;
    var blocks = this.blocks,
      i = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[i >>> 2] |= EXTRA[i & 3];
    this.block = blocks[16];
    if (i >= 56) {
      if (!this.hashed) {
        this.hash();
      }
      blocks[0] = this.block;
      blocks[16] =
        blocks[1] =
        blocks[2] =
        blocks[3] =
        blocks[4] =
        blocks[5] =
        blocks[6] =
        blocks[7] =
        blocks[8] =
        blocks[9] =
        blocks[10] =
        blocks[11] =
        blocks[12] =
        blocks[13] =
        blocks[14] =
        blocks[15] =
          0;
    }
    blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
    blocks[15] = this.bytes << 3;
    this.hash();
  };

  Sha256.prototype.hash = function () {
    var a = this.h0,
      b = this.h1,
      c = this.h2,
      d = this.h3,
      e = this.h4,
      f = this.h5,
      g = this.h6,
      h = this.h7,
      blocks = this.blocks,
      j,
      s0,
      s1,
      maj,
      t1,
      t2,
      ch,
      ab,
      da,
      cd,
      bc;

    for (j = 16; j < 64; ++j) {
      // rightrotate
      t1 = blocks[j - 15];
      s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
      t1 = blocks[j - 2];
      s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
      blocks[j] = (blocks[j - 16] + s0 + blocks[j - 7] + s1) << 0;
    }

    bc = b & c;
    for (j = 0; j < 64; j += 4) {
      if (this.first) {
        if (this.is224) {
          ab = 300032;
          t1 = blocks[0] - 1413257819;
          h = (t1 - 150054599) << 0;
          d = (t1 + 24177077) << 0;
        } else {
          ab = 704751109;
          t1 = blocks[0] - 210244248;
          h = (t1 - 1521486534) << 0;
          d = (t1 + 143694565) << 0;
        }
        this.first = false;
      } else {
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ab = a & b;
        maj = ab ^ (a & c) ^ bc;
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[j] + blocks[j];
        t2 = s0 + maj;
        h = (d + t1) << 0;
        d = (t1 + t2) << 0;
      }
      s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
      s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
      da = d & a;
      maj = da ^ (d & b) ^ ab;
      ch = (h & e) ^ (~h & f);
      t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
      t2 = s0 + maj;
      g = (c + t1) << 0;
      c = (t1 + t2) << 0;
      s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
      s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
      cd = c & d;
      maj = cd ^ (c & a) ^ da;
      ch = (g & h) ^ (~g & e);
      t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
      t2 = s0 + maj;
      f = (b + t1) << 0;
      b = (t1 + t2) << 0;
      s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
      s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
      bc = b & c;
      maj = bc ^ (b & d) ^ cd;
      ch = (f & g) ^ (~f & h);
      t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
      t2 = s0 + maj;
      e = (a + t1) << 0;
      a = (t1 + t2) << 0;
      this.chromeBugWorkAround = true;
    }

    this.h0 = (this.h0 + a) << 0;
    this.h1 = (this.h1 + b) << 0;
    this.h2 = (this.h2 + c) << 0;
    this.h3 = (this.h3 + d) << 0;
    this.h4 = (this.h4 + e) << 0;
    this.h5 = (this.h5 + f) << 0;
    this.h6 = (this.h6 + g) << 0;
    this.h7 = (this.h7 + h) << 0;
  };

  Sha256.prototype.hex = function () {
    this.finalize();

    var h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4,
      h5 = this.h5,
      h6 = this.h6,
      h7 = this.h7;

    var hex =
      HEX_CHARS[(h0 >>> 28) & 0x0f] +
      HEX_CHARS[(h0 >>> 24) & 0x0f] +
      HEX_CHARS[(h0 >>> 20) & 0x0f] +
      HEX_CHARS[(h0 >>> 16) & 0x0f] +
      HEX_CHARS[(h0 >>> 12) & 0x0f] +
      HEX_CHARS[(h0 >>> 8) & 0x0f] +
      HEX_CHARS[(h0 >>> 4) & 0x0f] +
      HEX_CHARS[h0 & 0x0f] +
      HEX_CHARS[(h1 >>> 28) & 0x0f] +
      HEX_CHARS[(h1 >>> 24) & 0x0f] +
      HEX_CHARS[(h1 >>> 20) & 0x0f] +
      HEX_CHARS[(h1 >>> 16) & 0x0f] +
      HEX_CHARS[(h1 >>> 12) & 0x0f] +
      HEX_CHARS[(h1 >>> 8) & 0x0f] +
      HEX_CHARS[(h1 >>> 4) & 0x0f] +
      HEX_CHARS[h1 & 0x0f] +
      HEX_CHARS[(h2 >>> 28) & 0x0f] +
      HEX_CHARS[(h2 >>> 24) & 0x0f] +
      HEX_CHARS[(h2 >>> 20) & 0x0f] +
      HEX_CHARS[(h2 >>> 16) & 0x0f] +
      HEX_CHARS[(h2 >>> 12) & 0x0f] +
      HEX_CHARS[(h2 >>> 8) & 0x0f] +
      HEX_CHARS[(h2 >>> 4) & 0x0f] +
      HEX_CHARS[h2 & 0x0f] +
      HEX_CHARS[(h3 >>> 28) & 0x0f] +
      HEX_CHARS[(h3 >>> 24) & 0x0f] +
      HEX_CHARS[(h3 >>> 20) & 0x0f] +
      HEX_CHARS[(h3 >>> 16) & 0x0f] +
      HEX_CHARS[(h3 >>> 12) & 0x0f] +
      HEX_CHARS[(h3 >>> 8) & 0x0f] +
      HEX_CHARS[(h3 >>> 4) & 0x0f] +
      HEX_CHARS[h3 & 0x0f] +
      HEX_CHARS[(h4 >>> 28) & 0x0f] +
      HEX_CHARS[(h4 >>> 24) & 0x0f] +
      HEX_CHARS[(h4 >>> 20) & 0x0f] +
      HEX_CHARS[(h4 >>> 16) & 0x0f] +
      HEX_CHARS[(h4 >>> 12) & 0x0f] +
      HEX_CHARS[(h4 >>> 8) & 0x0f] +
      HEX_CHARS[(h4 >>> 4) & 0x0f] +
      HEX_CHARS[h4 & 0x0f] +
      HEX_CHARS[(h5 >>> 28) & 0x0f] +
      HEX_CHARS[(h5 >>> 24) & 0x0f] +
      HEX_CHARS[(h5 >>> 20) & 0x0f] +
      HEX_CHARS[(h5 >>> 16) & 0x0f] +
      HEX_CHARS[(h5 >>> 12) & 0x0f] +
      HEX_CHARS[(h5 >>> 8) & 0x0f] +
      HEX_CHARS[(h5 >>> 4) & 0x0f] +
      HEX_CHARS[h5 & 0x0f] +
      HEX_CHARS[(h6 >>> 28) & 0x0f] +
      HEX_CHARS[(h6 >>> 24) & 0x0f] +
      HEX_CHARS[(h6 >>> 20) & 0x0f] +
      HEX_CHARS[(h6 >>> 16) & 0x0f] +
      HEX_CHARS[(h6 >>> 12) & 0x0f] +
      HEX_CHARS[(h6 >>> 8) & 0x0f] +
      HEX_CHARS[(h6 >>> 4) & 0x0f] +
      HEX_CHARS[h6 & 0x0f];
    if (!this.is224) {
      hex +=
        HEX_CHARS[(h7 >>> 28) & 0x0f] +
        HEX_CHARS[(h7 >>> 24) & 0x0f] +
        HEX_CHARS[(h7 >>> 20) & 0x0f] +
        HEX_CHARS[(h7 >>> 16) & 0x0f] +
        HEX_CHARS[(h7 >>> 12) & 0x0f] +
        HEX_CHARS[(h7 >>> 8) & 0x0f] +
        HEX_CHARS[(h7 >>> 4) & 0x0f] +
        HEX_CHARS[h7 & 0x0f];
    }
    return hex;
  };

  Sha256.prototype.toString = Sha256.prototype.hex;

  Sha256.prototype.digest = function () {
    this.finalize();

    var h0 = this.h0,
      h1 = this.h1,
      h2 = this.h2,
      h3 = this.h3,
      h4 = this.h4,
      h5 = this.h5,
      h6 = this.h6,
      h7 = this.h7;

    var arr = [
      (h0 >>> 24) & 0xff,
      (h0 >>> 16) & 0xff,
      (h0 >>> 8) & 0xff,
      h0 & 0xff,
      (h1 >>> 24) & 0xff,
      (h1 >>> 16) & 0xff,
      (h1 >>> 8) & 0xff,
      h1 & 0xff,
      (h2 >>> 24) & 0xff,
      (h2 >>> 16) & 0xff,
      (h2 >>> 8) & 0xff,
      h2 & 0xff,
      (h3 >>> 24) & 0xff,
      (h3 >>> 16) & 0xff,
      (h3 >>> 8) & 0xff,
      h3 & 0xff,
      (h4 >>> 24) & 0xff,
      (h4 >>> 16) & 0xff,
      (h4 >>> 8) & 0xff,
      h4 & 0xff,
      (h5 >>> 24) & 0xff,
      (h5 >>> 16) & 0xff,
      (h5 >>> 8) & 0xff,
      h5 & 0xff,
      (h6 >>> 24) & 0xff,
      (h6 >>> 16) & 0xff,
      (h6 >>> 8) & 0xff,
      h6 & 0xff,
    ];
    if (!this.is224) {
      arr.push((h7 >>> 24) & 0xff, (h7 >>> 16) & 0xff, (h7 >>> 8) & 0xff, h7 & 0xff);
    }
    return arr;
  };

  Sha256.prototype.array = Sha256.prototype.digest;

  Sha256.prototype.arrayBuffer = function () {
    this.finalize();

    var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
    var dataView = new DataView(buffer);
    dataView.setUint32(0, this.h0);
    dataView.setUint32(4, this.h1);
    dataView.setUint32(8, this.h2);
    dataView.setUint32(12, this.h3);
    dataView.setUint32(16, this.h4);
    dataView.setUint32(20, this.h5);
    dataView.setUint32(24, this.h6);
    if (!this.is224) {
      dataView.setUint32(28, this.h7);
    }
    return buffer;
  };

  function HmacSha256(key, is224, sharedMemory) {
    var i,
      type = typeof key;
    if (type === "string") {
      var bytes = [],
        length = key.length,
        index = 0,
        code;
      for (i = 0; i < length; ++i) {
        code = key.charCodeAt(i);
        if (code < 0x80) {
          bytes[index++] = code;
        } else if (code < 0x800) {
          bytes[index++] = 0xc0 | (code >>> 6);
          bytes[index++] = 0x80 | (code & 0x3f);
        } else if (code < 0xd800 || code >= 0xe000) {
          bytes[index++] = 0xe0 | (code >>> 12);
          bytes[index++] = 0x80 | ((code >>> 6) & 0x3f);
          bytes[index++] = 0x80 | (code & 0x3f);
        } else {
          code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[index++] = 0xf0 | (code >>> 18);
          bytes[index++] = 0x80 | ((code >>> 12) & 0x3f);
          bytes[index++] = 0x80 | ((code >>> 6) & 0x3f);
          bytes[index++] = 0x80 | (code & 0x3f);
        }
      }
      key = bytes;
    } else {
      if (type === "object") {
        if (key === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
          key = new Uint8Array(key);
        } else if (!Array.isArray(key)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
    }

    if (key.length > 64) {
      key = new Sha256(is224, true).update(key).array();
    }

    var oKeyPad = [],
      iKeyPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oKeyPad[i] = 0x5c ^ b;
      iKeyPad[i] = 0x36 ^ b;
    }

    Sha256.call(this, is224, sharedMemory);

    this.update(iKeyPad);
    this.oKeyPad = oKeyPad;
    this.inner = true;
    this.sharedMemory = sharedMemory;
  }
  HmacSha256.prototype = new Sha256();

  HmacSha256.prototype.finalize = function () {
    Sha256.prototype.finalize.call(this);
    if (this.inner) {
      this.inner = false;
      var innerHash = this.array();
      Sha256.call(this, this.is224, this.sharedMemory);
      this.update(this.oKeyPad);
      this.update(innerHash);
      Sha256.prototype.finalize.call(this);
    }
  };

  var exports = createMethod();
  exports.sha256 = exports;
  exports.sha224 = createMethod(true);
  exports.sha256.hmac = createHmacMethod();
  exports.sha224.hmac = createHmacMethod(true);

  if (COMMON_JS) {
    module.exports = exports;
  } else {
    root.sha256 = exports.sha256;
    root.sha224 = exports.sha224;
    if (AMD) {
      define(function () {
        return exports;
      });
    }
  }
})();
