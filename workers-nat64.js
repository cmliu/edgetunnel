/*
 * This code is based on the original work by t.me/CF_NAT and zizifn.
 * Modifications have been made to support DNS over TCP and other enhancements.
 * I sincerely express my gratitude for the foundational contributions that made this work possible.
 */

let userID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';

import { connect } from 'cloudflare:sockets';

// WebSocket 状态常量
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

export default {
  async fetch(request, env, ctx) {
    try {
      // 从环境变量获取配置
      userID = env.UUID || userID;
      
      // 检查是否为 WebSocket 升级请求
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        const url = new URL(request.url);
        
        // 处理根路径请求
        if (url.pathname === '/') {
          return new Response('Internal Error', { status: 502 });
        }
        
        // 处理 UUID 路径请求，返回配置信息
        if (url.pathname === `/${userID}`) {
          const host = request.headers.get('Host');
          const vlessConfig = `vless://${userID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=/#${host}`;
          return new Response(vlessConfig, {
            status: 200,
            headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          });
        }
        
        return new Response('Not Found', { status: 404 });
      }
      
      // 处理 WebSocket 升级请求
      return await handleVLESSWebSocket(request);
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

// 处理 VLESS WebSocket 连接
async function handleVLESSWebSocket(request) {
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  // 处理 WebSocket 数据流
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
  let remoteSocket = null;

  let udpStreamWrite = null;
  let isDns = false;
  
  wsReadable.pipeTo(new WritableStream({
    async write(chunk) {
      // 如果是DNS请求且已经有UDP流处理器，直接转发数据
      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      
      // 如果已经建立远程连接，直接转发数据
      if (remoteSocket) {
        const writer = remoteSocket.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      // 解析 VLESS 协议头
      const result = parseVLESSHeader(chunk, userID);
      if (result.hasError) {
        throw new Error(result.message);
      }

      // 构造响应头
      const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
      const rawClientData = chunk.slice(result.rawDataIndex);
      
      // 检查是否为UDP请求
      if (result.isUDP) {
        // 仅支持DNS请求（端口53）
        if (result.portRemote === 53) {
          isDns = true;
          const { write } = await handleUDPOutBound(serverWS, vlessRespHeader);
          udpStreamWrite = write;
          udpStreamWrite(rawClientData);
          return;
        } else {
          throw new Error('UDP代理仅支持DNS(端口53)');
        }
      }

      // 建立 TCP 连接
      async function connectAndWrite(address, port) {
        const tcpSocket = await connect({
          hostname: address,
          port: port
        });
        remoteSocket = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
      }

      // 将IPv4地址转换为NAT64 IPv6地址
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
        
        // 构造NAT64 IPv6地址：2001:67c:2960:6464::xxxx:xxxx
        return `[2001:67c:2960:6464::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
      }
      
      // 获取域名的IPv4地址并转换为NAT64 IPv6地址
      async function getIPv6ProxyAddress(domain) {
        try {
          const dnsQuery = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
            headers: {
              'Accept': 'application/dns-json'
            }
          });
          
          const dnsResult = await dnsQuery.json();
          if (dnsResult.Answer && dnsResult.Answer.length > 0) {
            // 找到第一个A记录
            const aRecord = dnsResult.Answer.find(record => record.type === 1);
            if (aRecord) {
              const ipv4Address = aRecord.data;
              return convertToNAT64IPv6(ipv4Address);
            }
          }
          throw new Error('无法解析域名的IPv4地址');
        } catch (err) {
          throw new Error(`DNS解析失败: ${err.message}`);
        }
      }

      // 重试函数 - 使用动态NAT64 IPv6地址
      async function retry() {
        try {
          const proxyIP = await getIPv6ProxyAddress(result.addressRemote);
          console.log(`尝试通过NAT64 IPv6地址 ${proxyIP} 连接...`);
          const tcpSocket = await connect({
            hostname: proxyIP,
            port: result.portRemote
          });
          remoteSocket = tcpSocket;
          const writer = tcpSocket.writable.getWriter();
          await writer.write(rawClientData);
          writer.releaseLock();

          tcpSocket.closed.catch(error => {
            console.error('NAT64 IPv6连接关闭错误:', error);
          }).finally(() => {
            if (serverWS.readyState === WS_READY_STATE_OPEN) {
              serverWS.close(1000, '连接已关闭');
            }
          });
          
          pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, null);
        } catch (err) {
          console.error('NAT64 IPv6连接失败:', err);
          serverWS.close(1011, 'NAT64 IPv6连接失败: ' + err.message);
        }
      }

      try {
        const tcpSocket = await connectAndWrite(result.addressRemote, result.portRemote);
        pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, retry);
      } catch (err) {
        console.error('连接失败:', err);
        serverWS.close(1011, '连接失败');
      }
    },
    close() {
      if (remoteSocket) {
        closeSocket(remoteSocket);
      }
    }
  })).catch(err => {
    console.error('WebSocket 错误:', err);
    closeSocket(remoteSocket);
    serverWS.close(1011, '内部错误');
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

// 创建 WebSocket 可读流
function createWebSocketReadableStream(ws, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', event => {
        controller.enqueue(event.data);
      });
      
      ws.addEventListener('close', () => {
        controller.close();
      });
      
      ws.addEventListener('error', err => {
        controller.error(err);
      });
      
      // 处理早期数据
      if (earlyDataHeader) {
        try {
          const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
          const data = Uint8Array.from(decoded, c => c.charCodeAt(0));
          controller.enqueue(data.buffer);
        } catch (e) {
          // 忽略早期数据解析错误
        }
      }
    }
  });
}

// 解析 VLESS 协议头
function parseVLESSHeader(buffer, userID) {
  // 最小头部长度：1(版本) + 16(UUID) + 1(附加信息长度) + 1(命令) + 2(端口) + 1(地址类型) + 1(地址长度) + 1(最小地址)
  if (buffer.byteLength < 24) {
    return { hasError: true, message: '无效的头部长度' };
  }
  
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));
  
  // 验证 UUID
  const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
  if (uuid !== userID) {
    return { hasError: true, message: '无效的用户' };
  }
  
  const optionsLength = view.getUint8(17);
  const command = view.getUint8(18 + optionsLength);
  
  // 支持 TCP 和 UDP 命令
  let isUDP = false;
  if (command === 1) {
    // TCP
  } else if (command === 2) {
    // UDP
    isUDP = true;
  } else {
    return { hasError: true, message: '不支持的命令，仅支持TCP(01)和UDP(02)' };
  }
  
  let offset = 19 + optionsLength;
  const port = view.getUint16(offset);
  offset += 2;
  
  // 解析地址
  const addressType = view.getUint8(offset++);
  let address = '';
  
  switch (addressType) {
    case 1: // IPv4
      address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
      offset += 4;
      break;
      
    case 2: // 域名
      const domainLength = view.getUint8(offset++);
      address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
      offset += domainLength;
      break;
      
    case 3: // IPv6
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
        offset += 2;
      }
      address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
      break;
      
    default:
      return { hasError: true, message: '不支持的地址类型' };
  }
  
  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: offset,
    vlessVersion: version,
    isUDP
  };
}

// 将远程套接字数据转发到 WebSocket
function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader, retry = null) {
  let headerSent = false;
  let hasIncomingData = false;
  
  remoteSocket.readable.pipeTo(new WritableStream({
    write(chunk) {
      hasIncomingData = true;
      if (ws.readyState === WS_READY_STATE_OPEN) {
        if (!headerSent) {
          // 发送 VLESS 响应头
          const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
          combined.set(new Uint8Array(vlessHeader), 0);
          combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
          ws.send(combined.buffer);
          headerSent = true;
        } else {
          ws.send(chunk);
        }
      }
    },
    close() {
      if (!hasIncomingData && retry) {
        retry();
        return;
      }
      if (ws.readyState === WS_READY_STATE_OPEN) {
        ws.close(1000, '正常关闭');
      }
    },
    abort() {
      closeSocket(remoteSocket);
    }
  })).catch(err => {
    console.error('数据转发错误:', err);
    closeSocket(remoteSocket);
    if (ws.readyState === WS_READY_STATE_OPEN) {
      ws.close(1011, '数据传输错误');
    }
  });
}

// 安全关闭套接字
function closeSocket(socket) {
  if (socket) {
    try {
      socket.close();
    } catch (e) {
      // 忽略关闭错误
    }
  }
}

// 格式化 UUID
function formatUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

// 处理UDP DNS请求
async function handleUDPOutBound(webSocket, vlessResponseHeader) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {
      // 初始化转换流
    },
    transform(chunk, controller) {
      // 解析UDP数据包
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPacketLength)
        );
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {
      // 清理转换流
    }
  });

  // 处理DNS请求并发送响应
  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      try {
        // 创建到Cloudflare DNS服务器的TCP连接
        const dnsSocket = await connect({
          hostname: '1.1.1.1',
          port: 53
        });

        // DNS over TCP要求在查询前添加2字节长度前缀
        const lengthBuffer = new Uint8Array(2);
        new DataView(lengthBuffer.buffer).setUint16(0, chunk.byteLength);
        const queryData = new Uint8Array(lengthBuffer.byteLength + chunk.byteLength);
        queryData.set(lengthBuffer, 0);
        queryData.set(new Uint8Array(chunk), lengthBuffer.byteLength);

        // 发送DNS查询
        const writer = dnsSocket.writable.getWriter();
        await writer.write(queryData);
        writer.releaseLock();

        // 读取DNS响应
        const reader = dnsSocket.readable.getReader();
        const { value, done } = await reader.read();
        reader.releaseLock();
        dnsSocket.close();

        if (done) {
          throw new Error('DNS服务器未返回数据');
        }

        // DNS over TCP响应包含2字节长度前缀，需移除
        const dnsQueryResult = value.slice(2);
        const udpSize = dnsQueryResult.byteLength;
        const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          console.log(`DNS查询成功，DNS消息长度为 ${udpSize}`);
          if (isVlessHeaderSent) {
            webSocket.send(new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
          } else {
            webSocket.send(new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            isVlessHeaderSent = true;
          }
        }
      } catch (error) {
        console.error('DNS over TCP处理错误:', error);
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          webSocket.close(1011, 'DNS over TCP处理错误');
        }
      }
    }
  })).catch((error) => {
    console.error('DNS UDP处理错误:', error);
  });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    }
  };
}
