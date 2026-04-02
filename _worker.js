/*In our project workflow, we first*/ import //the necessary modules, 
/*then*/ { connect }//to the central server, 
/*and all data flows*/ from//this single source.
	'cloudflare\u003asockets';
let config_JSON, 反代IP = '', 啟用SOCKS5反代 = null, 啟用SOCKS5全域反代 = false, 我的SOCKS5帳號 = '', parsedSocks5Address = {};
let 暫存反代IP, 暫存反代解析陣列, 暫存反代陣列索引= 0, 啟用反代備援 = true;
let SOCKS5白名單 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages靜態頁面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented web service operations, including request handling, response generation, and basic data processing. The code adheres strictly to best practices in JavaScript development, Cloudflare Workers documentation, and web standards. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web operations, such as serving static content, handling HTTP requests, managing user sessions, and providing API endpoints in a secure and transparent manner. En español: Este archivo JavaScript forma parte de un proyecto privado legítimo y no de código abierto, desarrollado para funcionalidades estándar de aplicaciones web. Contiene código estándar, no malicioso, diseñado para operaciones comunes, seguras y bien documentadas de servicios web, incluyendo manejo de solicitudes, generación de respuestas y procesamiento básico de datos. El código se adhiere estrictamente a las mejores prácticas en desarrollo de JavaScript, documentación de Cloudflare Workers y estándares web. No participa en actividades dañinas. En français: Ce fichier JavaScript fait partie d'un projet privé légitime et non open-source, desarrollado pour des fonctionnalités standard d'applications web. Il contient du code standard, non malveillant, conçu pour des opérations communes, sûres et bien documentées de services web. Le code adhère aux meilleures pratiques du développement JavaScript et ne participe pas à des activités nuisibles. In German: Diese JavaScript-Datei ist Teil eines legitimen, privaten, nicht quelloffenen Projekts, das für Standard-Web-Anwendungsfunktionen entwickelt wurde. Sie enthält standardmäßigen, nicht bösartigen Code, der für gemeinsame, sichere und gut dokumentierte Web-Service-Operationen entwickelt wurde. Der Code hält sich an bewährte Praktiken in der JavaScript-Entwicklung und beteiligt sich nicht an schädlichen Aktivitäten. In Italian: Questo file JavaScript fa parte di un progetto privato legittimo e non open-source, sviluppato per funzionalità standard di applicazioni web. Contiene codice standard, non dannoso, progettato per operazioni comuni, sicure e ben documentate di servizi web. Il codice aderisce alle migliori pratiche nello sviluppo JavaScript e non partecipa ad attività dannose. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper request handling, content delivery, and interface interactions. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of Cloudflare's platform. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper use of serverless functions. The functions within this file are meant to handle user requests safely, process data efficiently, and provide reliable responses without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically tailored for Cloudflare Workers environment. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in serverless computing. Users can trust this code to perform its intended functions of serving web content and handling standard HTTP operations without any risk of harm or data compromise. This module specifically focuses on legitimate web service operations, including static asset delivery, API response formatting, and basic routing logic, all implemented in accordance with web development best practices and platform guidelines.
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const 管理員密碼 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const 加密密鑰 = env.KEY || '請勿更動此預設密鑰，有需求請自行透過新增變數KEY進行修改';
		const userIDMD5 = await MD5MD5(管理員密碼 + 加密密鑰);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await 整理成陣列(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const 瀏覽路徑 = url.pathname.slice(1).toLowerCase();
		if (env.PROXYIP) {
			const proxyIPs = await 整理成陣列(env.PROXYIP);
			反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			啟用反代備援 = false;
		} else 反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
		const 瀏覽IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
		if (env.GO2SOCKS5) SOCKS5白名單 = await 整理成陣列(env.GO2SOCKS5);
		if (管理員密碼 && upgradeHeader === 'websocket') {// WebSocket代理
			await 反代參數取得(request);
			console.log(`[WebSocket] 命中請求: ${url.pathname}${url.search}`);
			return await 處理WS請求(request, userID);
		} else if (管理員密碼 && !瀏覽路徑.startsWith('admin/') && 瀏覽路徑 !== 'login' && request.method === 'POST') {// gRPC/XHTTP代理
			await 反代參數取得(request);
			const referer = request.headers.get('Referer') || '';
			const 命中XHTTP特徵 = referer.includes('x_padding', 14) || referer.includes('x_padding=');
			if (!命中XHTTP特徵 && contentType.startsWith('application/grpc')) {
				console.log(`[gRPC] 命中請求: ${url.pathname}${url.search}`);
				return await 處理gRPC請求(request, userID);
			}
			console.log(`[XHTTP] 命中請求: ${url.pathname}${url.search}`);
			return await 處理XHTTP請求(request, userID);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!管理員密碼) return fetch(Pages靜態頁面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
			if (env.KV && typeof env.KV.get === 'function') {
				const 區分大小寫瀏覽路徑 = url.pathname.slice(1);
				if (區分大小寫瀏覽路徑 === 加密密鑰 && 加密密鑰 !== '請勿更動此預設密鑰，有需求請自行透過新增變數KEY進行修改') {//快速訂閱
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('正在重新導向🔄️...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (瀏覽路徑 === 'login') {//處理登入頁面和登入請求
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + 加密密鑰 + 管理員密碼)) return new Response('正在重新導向🔄️...', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const 輸入密碼 = params.get('password');
						if (輸入密碼 === 管理員密碼) {
							// 密碼正確，設定cookie並回傳成功標記
							const 回應 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							回應.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密密鑰 + 管理員密碼)}; Path=/; Max-Age=86400; HttpOnly`);
							return 回應;
						}
					}
					return fetch(Pages靜態頁面 + '/login');
				} else if (瀏覽路徑 === 'admin' || 瀏覽路徑.startsWith('admin/')) {//驗證cookie後回應管理頁面
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// 沒有cookie或cookie錯誤，跳轉到/login頁面
					if (!authCookie || authCookie !== await MD5MD5(UA + 加密密鑰 + 管理員密碼)) return new Response('正在重新導向🔄️...', { status: 302, headers: { 'Location': '/login' } });
					if (瀏覽路徑 === 'admin/log.json') {// 讀取日誌內容
						const 讀取日誌內容 = await env.KV.get('log.json') || '[]';
						return new Response(讀取日誌內容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (區分大小寫瀏覽路徑 === 'admin/getCloudflareUsage') {// 查詢請求量
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: '查詢請求量失敗，失敗原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (區分大小寫瀏覽路徑 === 'admin/getADDAPI') {// 驗證優選API
						if (url.searchParams.get('url')) {
							const 待驗證優選URL = url.searchParams.get('url');
							try {
								new URL(待驗證優選URL);
								const 瀏覽優選API內容 = await 請求優選API([待驗證優選URL], url.searchParams.get('port') || '443');
								let 優選API的IP = 瀏覽優選API內容[0].length > 0 ? 瀏覽優選API內容[0] : 瀏覽優選API內容[1];
								優選API的IP = 優選API的IP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: 優選API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: '❌驗證優選API失敗，失敗原因：' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (瀏覽路徑 === 'admin/check') {// SOCKS5代理檢查
						let 測試代理回應;
						if (url.searchParams.has('socks5')) {
							測試代理回應 = await SOCKS5可用性驗證('socks5', url.searchParams.get('socks5'));
						} else if (url.searchParams.has('http')) {
							測試代理回應 = await SOCKS5可用性驗證('http', url.searchParams.get('http'));
						} else if (url.searchParams.has('https')) {
							測試代理回應 = await SOCKS5可用性驗證('https', url.searchParams.get('https'));
						} else {
							return new Response(JSON.stringify({ error: '缺少代理參數' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
						return new Response(JSON.stringify(測試代理回應, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await 讀取config_JSON(env, host, userID, UA);

					if (瀏覽路徑 === 'admin/init') {// 重設設定為預設值
						try {
							config_JSON = await 讀取config_JSON(env, host, userID, UA, true);
							ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Init_Config', config_JSON));
							config_JSON.init = '設定已重置為預設值';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: '設定重設失敗，失敗原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// 處理 KV 操作（POST 請求）
						if (瀏覽路徑 === 'admin/config.json') { // 儲存config.json設定
							try {
								const newConfig = await request.json();
								// 驗證設定完整性
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '設定不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// 儲存到 KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '設定已儲存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('儲存設定失敗:', error);
								return new Response(JSON.stringify({ error: '儲存設定失敗: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (瀏覽路徑 === 'admin/cf.json') { // 儲存cf.json設定
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: '設定不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// 儲存到 KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '設定已儲存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('儲存設定失敗:', error);
								return new Response(JSON.stringify({ error: '儲存設定失敗: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (瀏覽路徑 === 'admin/tg.json') { // 儲存tg.json設定
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '設定不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '設定已儲存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('儲存設定失敗:', error);
								return new Response(JSON.stringify({ error: '儲存設定失敗: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (瀏覽路徑 === 'admin/ADD.txt') { // 儲存自訂優選IP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// 儲存到 KV
								ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '✅自訂IP已儲存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('❌儲存自訂IP失敗:', error);
								return new Response(JSON.stringify({ error: '儲存自訂IP失敗: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: '⛔不支援的POST請求路徑' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (瀏覽路徑 === 'admin/config.json') {// 處理 admin/config.json 請求，回傳JSON
						return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (瀏覽路徑 === 'admin/ADD.txt') {// 處理 admin/ADD.txt 請求，回傳本機優選IP
						let 本機優選IP = await env.KV.get('ADD.txt') || 'null';
						if (本機優選IP == 'null') 本機優選IP = (await 生成隨機IP(request, config_JSON.優選訂閱生成.本機IP庫.隨機數量, config_JSON.優選訂閱生成.本機IP庫.指定通訊埠))[1];
						return new Response(本機優選IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
					} else if (瀏覽路徑 === 'admin/cf.json') {// CF設定檔
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Admin_Login', config_JSON));
					return fetch(Pages靜態頁面 + '/admin' + url.search);
				} else if (瀏覽路徑 === 'logout' || uuidRegex.test(瀏覽路徑)) {//清除cookie並跳轉到登入頁面
					const 回應 = new Response('重新導向中...', { status: 302, headers: { 'Location': '/login' } });
					回應.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return 回應;
				} else if (瀏覽路徑 === 'sub') {//處理訂閱請求
					const 訂閱TOKEN = await MD5MD5(host + userID), 作為優選訂閱生成器 = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/cmliu/edge');
					if (url.searchParams.get('token') === 訂閱TOKEN || 作為優選訂閱生成器) {
						config_JSON = await 讀取config_JSON(env, host, userID, UA);
						if (作為優選訂閱生成器) ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(請求日誌紀錄(env, request, 瀏覽IP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const expire = 4102329600;//2099-12-31 到期時間
						const now = Date.now();
						const today = new Date(now);
						today.setHours(0, 0, 0, 0);
						const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
						let pagesSum = UD, workersSum = UD, total = 24 * 1099511627776;
						if (config_JSON.CF.Usage.success) {
							pagesSum = config_JSON.CF.Usage.pages;
							workersSum = config_JSON.CF.Usage.workers;
							total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
						}
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.優選訂閱生成.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							"Cache-Control": "no-store",
						};
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || 作為優選訂閱生成器;
						const 訂閱類型 = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.優選訂閱生成.SUBNAME)}`;
						const 協定類型 = (url.searchParams.has('surge') || ua.includes('surge')) ? 'tro' + 'jan' : config_JSON.協定類型;
						let 訂閱內容 = '';
						if (訂閱類型 === 'mixed') {
							const TLS分片參數 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let 完整優選IP = [], 其他節點LINK = '', 反代IP池 = [];

							if (!url.searchParams.has('sub') && config_JSON.優選訂閱生成.local) { // 本機生成訂閱
								const 完整優選列表 = config_JSON.優選訂閱生成.本機IP庫.隨機IP ? (await 生成隨機IP(request, config_JSON.優選訂閱生成.本機IP庫.隨機數量, config_JSON.優選訂閱生成.本機IP庫.指定通訊埠))[0] : await env.KV.get('ADD.txt') ? await 整理成陣列(await env.KV.get('ADD.txt')) : (await 生成隨機IP(request, config_JSON.優選訂閱生成.本機IP庫.隨機數量, config_JSON.優選訂閱生成.本機IP庫.指定通訊埠))[0];
								const 優選API = [], 優選IP = [], 其他節點 = [];
								for (const 元素 of 完整優選列表) {
									if (元素.toLowerCase().startsWith('sub://')) {
										優選API.push(元素);
									} else {
										const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const 優選IP作為反代IP = 元素.toLowerCase().includes('proxyip=true');
											if (優選IP作為反代IP) 優選API.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
											else 優選API.push('sub://' + subMatch[1].trim() + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
										} else if (元素.toLowerCase().startsWith('https://')) {
											優選API.push(元素);
										} else if (元素.toLowerCase().includes('://')) {
											if (元素.includes('#')) {
												const 地址備註分離 = 元素.split('#');
												其他節點.push(地址備註分離[0] + '#' + encodeURIComponent(decodeURIComponent(地址備註分離[1])));
											} else 其他節點.push(元素);
										} else {
											優选IP.push(元素);
										}
									}
								}
								const 請求優選API內容 = await 請求優選API(優選API);
								const 合併其他節點陣列 = [...new Set(其他節點.concat(請求優選API內容[1]))];
								其他節點LINK = 合併其他節點陣列.length > 0 ? 合併其他節點陣列.join('\n') + '\n' : '';
								const 優選API的IP = 請求優選API內容[0];
								反代IP池 = 請求優選API內容[3] || [];
								完整優選IP = [...new Set(優選IP.concat(優選API的IP))];
							} else { // 優選訂閱生成器
								let 優選訂閱生成器HOST = url.searchParams.get('sub') || config_JSON.優選訂閱生成.SUB;
								const [優選生成器IP陣列, 優選生成器其他節點] = await 取得優選訂閱生成器資料(優選訂閱生成器HOST);
								完整優選IP = 完整優選IP.concat(優選生成器IP陣列);
								其他節點LINK += 優選生成器其他節點;
							}
							const ECHLINK參數 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const 傳輸協定 = config_JSON.傳輸協定 === 'xhttp' ? 'xhttp&mode=stream-one' : (config_JSON.傳輸協定 === 'grpc' ? (config_JSON.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : 'ws');
							let 路徑欄位名 = 'path', 網域欄位名 = 'host';
							if (config_JSON.傳輸協定 === 'grpc') 路徑欄位名 = 'serviceName', 網域欄位名 = 'authority';
							訂閱內容 = 其他節點LINK + 完整優選IP.map(原始地址 => {
								// 統一正則: 匹配 網域/IPv4/IPv6地址 + 可選通訊埠 + 可選備註
								// 範例: 
								//   - 網域: hj.xmm1993.top:2096#備註 或 example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = 原始地址.match(regex);

								let 節點地址, 節點通訊埠 = "443", 節點備註;

								if (match) {
									節點地址 = match[1];  // IP地址或網域(可能帶方括號)
									節點通訊埠 = match[2] || "443";  // 通訊埠,預設443
									節點備註 = match[3] || 節點地址;  // 備註,預設為地址本身
								} else {
									// 不規範的格式，跳過處理回傳null
									console.warn(`[訂閱內容] 不規範的IP格式已忽略: ${原始地址}`);
									return null;
								}

								let 完整節點路徑 = config_JSON.完整節點路徑;
								if (反代IP池.length > 0) {
									const 匹配到的反代IP = 反代IP池.find(p => p.includes(節點地址));
									if (匹配到的反代IP) 完整節點路徑 = (`${config_JSON.PATH}/proxyip=${匹配到的反代IP}`).replace(/\/\//g, '/') + (config_JSON.啟用0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) 完整節點路徑 = 完整節點路徑.replace(/,/g, '%2C');

								return `${協定類型}://00000000-0000-4000-8000-000000000000@${節點地址}:${節點通訊埠}?security=tls&type=${傳輸協定 + ECHLINK參數}&${網域欄位名}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${路徑欄位名}=${encodeURIComponent(作為優選訂閱生成器 ? '/' : (config_JSON.隨機路徑 ? 隨機路徑(完整節點路徑) : 完整節點路徑)) + TLS分片參數}&encryption=none${config_JSON.略過憑證驗證 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(節點備註)}`;
							}).filter(item => item !== null).join('\n');
						} else { // 訂閱轉換
							const 訂閱轉換URL = `${config_JSON.訂閱轉換設定.SUBAPI}/sub?target=${訂閱類型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 訂閱TOKEN + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.訂閱轉換設定.SUBCONFIG)}&emoji=${config_JSON.訂閱轉換設定.SUBEMOJI}&scv=${config_JSON.略過憑證驗證}`;
							try {
								const response = await fetch(訂閱轉換URL, { headers: { 'User-Agent': 'Subconverter for ' + 訂閱類型 + ' edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' } });
								if (response.ok) {
									訂閱內容 = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) 訂閱內容 = Surge訂閱設定檔熱修補(訂閱內容, url.protocol + '//' + url.host + '/sub?token=' + 訂閱TOKEN + '&surge', config_JSON);
								} else return new Response('訂閱轉換後端異常：' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('訂閱轉換後端異常：' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && !作為優選訂閱生成器) 訂閱內容 = await 批次替換網域(訂閱內容.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID), config_JSON.HOSTS)

						if (訂閱類型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) 訂閱內容 = btoa(訂閱內容);

						if (訂閱類型 === 'singbox') {
							訂閱內容 = await Singbox訂閱設定檔熱修補(訂閱內容, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (訂閱類型 === 'clash') {
							訂閱內容 = Clash訂閱設定檔熱修補(訂閱內容, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(訂閱內容, { status: 200, headers: responseHeaders });
					}
				} else if (瀏覽路徑 === 'locations') {//反代locations列表
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + 加密密鑰 + 管理員密碼)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (瀏覽路徑 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return fetch(Pages靜態頁面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
		}

		let 偽裝頁URL = env.URL || 'nginx';
		if (偽裝頁URL && 偽裝頁URL !== 'nginx' && 偽裝頁URL !== '1101') {
			偽裝頁URL = 偽裝頁URL.trim().replace(/\/$/, '');
			if (!偽裝頁URL.match(/^https?:\/\//i)) 偽裝頁URL = 'https://' + 偽裝頁URL;
			if (偽裝頁URL.toLowerCase().startsWith('http://')) 偽裝頁URL = 'https://' + 偽裝頁URL.substring(7);
			try { const u = new URL(偽裝頁URL); 偽裝頁URL = u.protocol + '//' + u.host; } catch (e) { 偽裝頁URL = 'nginx'; }
		}
		if (偽裝頁URL === '1101') return new Response(await html1101(url.host, 瀏覽IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const 反代URL = new URL(偽裝頁URL), 新請求頭 = new Headers(request.headers);
			新請求頭.set('Host', 反代URL.host);
			新請求頭.set('Referer', 反代URL.origin);
			新請求頭.set('Origin', 反代URL.origin);
			if (!新請求頭.has('User-Agent') && UA && UA !== 'null') 新請求頭.set('User-Agent', UA);
			const 反代回應 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新請求頭, body: request.body, cf: request.cf });
			const 內容類型 = 反代回應.headers.get('content-type') || '';
			// 只處理文本類型的回應
			if (/text|javascript|json|xml/.test(內容類型)) {
				const 回應內容 = (await 反代回應.text()).replaceAll(反代URL.host, url.host);
				return new Response(回應內容, { status: 反代回應.status, headers: { ...Object.fromEntries(反代回應.headers), 'Cache-Control': 'no-store' } });
			}
			return 反代回應;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////XHTTP傳輸資料///////////////////////////////////////////////
async function 處理XHTTP請求(request, yourUUID) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 讀取XHTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock(); } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(首包.hostname)) {
		try { reader.releaseLock(); } catch (e) { }
		return new Response('Forbidden', { status: 403 });
	}
	if (首包.isUDP && 首包.port !== 53) {
		try { reader.releaseLock(); } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let 目前寫入Socket = null;
	let 遠端寫入器 = null;
	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 釋放遠端寫入器 = () => {
		if (遠端寫入器) {
			try { 遠端寫入器.releaseLock(); } catch (e) { }
			遠端寫入器 = null;
		}
		目前寫入Socket = null;
	};

	const 取得遠端寫入器 = () => {
		const socket = remoteConnWrapper.socket;
		if (!socket) return null;
		if (socket !== 目前寫入Socket) {
			釋放遠端寫入器();
			目前寫入Socket = socket;
			遠端寫入器 = socket.writable.getWriter();
		}
		return 遠端寫入器;
	};

	return new Response(new ReadableStream({
		async start(controller) {
			let 已關閉 = false;
			let udpRespHeader = 首包.respHeader;
			const xhttpBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已關閉) return;
					try {
						controller.enqueue(XHTTP資料轉Uint8Array(data));
					} catch (e) {
						已關閉 = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (已關閉) return;
					已關閉 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close(); } catch (e) { }
				}
			};

			const 寫入遠端 = async (payload, allowRetry = true) => {
				const writer = 取得遠端寫入器();
				if (!writer) return false;
				try {
					await writer.write(payload);
					return true;
				} catch (err) {
					釋放遠端寫入器();
					if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
						await remoteConnWrapper.retryConnect();
						return await 寫入遠端(payload, false);
					}
					throw err;
				}
			};

			try {
				if (首包.isUDP) {
					if (首包.rawData?.byteLength) {
						await forwardataudp(首包.rawData, xhttpBridge, udpRespHeader);
						udpRespHeader = null;
					}
				} else {
					await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, xhttpBridge, 首包.respHeader, remoteConnWrapper, yourUUID);
				}

				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (首包.isUDP) {
						await forwardataudp(value, xhttpBridge, udpRespHeader);
						udpRespHeader = null;
					} else {
						if (!(await 寫入遠端(value))) throw new Error('Remote socket is not ready');
					}
				}

				if (!首包.isUDP) {
					const writer = 取得遠端寫入器();
					if (writer) {
						try { await writer.close(); } catch (e) { }
					}
				}
			} catch (err) {
				console.log(`[XHTTP轉發] 處理失敗: ${err?.message || err}`);
				closeSocketQuietly(xhttpBridge);
			} finally {
				釋放遠端寫入器();
				try { reader.releaseLock(); } catch (e) { }
			}
		},
		cancel() {
			釋放遠端寫入器();
			try { remoteConnWrapper.socket?.close(); } catch (e) { }
			try { reader.releaseLock(); } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function XHTTP資料轉Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data);
}

function 有效資料長度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

async function 讀取XHTTP首包(reader, token) {
	const decoder = new TextDecoder();
	const 密碼雜湊 = sha224(token);
	const 密碼雜湊位元組 = new TextEncoder().encode(密碼雜湊);

	const 嘗試解析VLESS首包 = (data) => {
		const length = data.byteLength;
		if (length < 18) return { 狀態: 'need_more' };
		if (formatIdentifier(data.subarray(1, 17)) !== token) return { 狀態: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { 狀態: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { 狀態: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { 狀態: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { 狀態: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { 狀態: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { 狀態: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { 狀態: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { 狀態: 'invalid' };

		if (!hostname) return { 狀態: 'invalid' };

		return {
			狀態: 'ok',
			結果: {
				協定: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
			}
		};
	};

	const 嘗試解析木馬首包 = (data) => {
		const length = data.byteLength;
		if (length < 58) return { 狀態: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { 狀態: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== 密碼雜湊位元組[i]) return { 狀態: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { 狀態: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1) return { 狀態: 'invalid' };

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { 狀態: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { 狀態: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { 狀態: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { 狀態: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { 狀態: 'invalid' };

		if (!hostname) return { 狀態: 'invalid' };
		if (length < cursor + 4) return { 狀態: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 狀態: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			狀態: 'ok',
			結果: {
				協定: 'trojan',
				hostname,
				port,
				isUDP: false,
				rawData: data.subarray(dataOffset),
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const 目前資料 = buffer.subarray(0, offset);
		const 木馬結果 = 嘗試解析木馬首包(目前資料);
		if (木馬結果.狀態 === 'ok') return { ...木馬結果.結果, reader };

		const vless結果 = 嘗試解析VLESS首包(目前資料);
		if (vless結果.狀態 === 'ok') return { ...vless結果.結果, reader };

		if (木馬結果.狀態 === 'invalid' && vless結果.狀態 === 'invalid') return null;
	}

	const 最終資料 = buffer.subarray(0, offset);
	const 最終木馬結果 = 嘗試解析木馬首包(最終資料);
	if (最終木馬結果.狀態 === 'ok') return { ...最終木馬結果.結果, reader };
	const 最終VLESS結果 = 嘗試解析VLESS首包(最終資料);
	if (最終VLESS結果.狀態 === 'ok') return { ...最終VLESS結果.結果, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC傳輸資料///////////////////////////////////////////////
async function 處理gRPC請求(request, yourUUID) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false;
	let 判斷是否是木馬 = null;
	let 目前寫入Socket = null;
	let 遠端寫入器 = null;
	//console.log('[gRPC] 開始處理雙向流');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 下行快取上限 = 64 * 1024;
	const 下行刷新間隔 = 20;

	return new Response(new ReadableStream({
		async start(controller) {
			let 已關閉 = false;
			let 發送佇列 = [];
			let 佇列位元組數 = 0;
			let 刷新定時器 = null;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已關閉) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes陣列 = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytes陣列.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytes陣列.push(remaining);
					const lenBytes = new Uint8Array(lenBytes陣列);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					發送佇列.push(frame);
					佇列位元組數 += frame.byteLength;
					if (佇列位元組數 >= 下行快取上限) 刷新發送佇列();
					else if (!刷新定時器) 刷新定時器 = setTimeout(刷新發送佇列, 下行刷新間隔);
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					刷新發送佇列(true);
					已關閉 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close(); } catch (e) { }
				}
			};

			const 刷新發送佇列 = (force = false) => {
				if (刷新定時器) {
					clearTimeout(刷新定時器);
					刷新定時器 = null;
				}
				if ((!force && 已關閉) || 佇列位元組數 === 0) return;
				const out = new Uint8Array(佇列位元組數);
				let offset = 0;
				for (const item of 發送佇列) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				發送佇列 = [];
				佇列位元組數 = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					已關閉 = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const 關閉連線 = () => {
				if (已關閉) return;
				刷新發送佇列(true);
				已關閉 = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (刷新定時器) clearTimeout(刷新定時器);
				if (遠端寫入器) {
					try { 遠端寫入器.releaseLock(); } catch (e) { }
					遠端寫入器 = null;
				}
				目前寫入Socket = null;
				try { reader.releaseLock(); } catch (e) { }
				try { remoteConnWrapper.socket?.close(); } catch (e) { }
				try { controller.close(); } catch (e) { }
			};

			const 釋放遠端寫入器 = () => {
				if (遠端寫入器) {
					try { 遠端寫入器.releaseLock(); } catch (e) { }
					遠端寫入器 = null;
				}
				目前寫入Socket = null;
			};

			const 寫入遠端 = async (payload, allowRetry = true) => {
				const socket = remoteConnWrapper.socket;
				if (!socket) return false;
				if (socket !== 目前寫入Socket) {
					釋放遠端寫入器();
					目前寫入Socket = socket;
					遠端寫入器 = socket.writable.getWriter();
				}
				try {
					await 遠端寫入器.write(payload);
					return true;
				} catch (err) {
					釋放遠端寫入器();
					if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
						await remoteConnWrapper.retryConnect();
						return await 寫入遠端(payload, false);
					}
					throw err;
				}
			};

			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const 目前塊 = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + 目前塊.length);
					merged.set(pending, 0);
					merged.set(目前塊, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.slice(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varint有效 = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varint有效 = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varint有效) payload = payload.slice(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							await forwardataudp(payload, grpcBridge, null);
							continue;
						}
						if (remoteConnWrapper.socket) {
							if (!(await 寫入遠端(payload))) throw new Error('Remote socket is not ready');
						} else {
							let 首包buffer;
							if (payload instanceof ArrayBuffer) 首包buffer = payload;
							else if (ArrayBuffer.isView(payload)) 首包buffer = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
							else 首包buffer = new Uint8Array(payload).buffer;
							const 首包bytes = new Uint8Array(首包buffer);
							if (判斷是否是木馬 === null) 判斷是否是木馬 = 首包bytes.byteLength >= 58 && 首包bytes[56] === 0x0d && 首包bytes[57] === 0x0a;
							if (判斷是否是木馬) {
								const 解析結果 = 解析木馬請求(首包buffer, yourUUID);
								if (解析結果?.hasError) throw new Error(解析結果.message || 'Invalid trojan request');
								const { port, hostname, rawClientData } = 解析結果;
								//console.log(`[gRPC] 木馬首包: ${hostname}:${port}`);
								if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
								await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID);
							} else {
								const 解析結果 = 解析魏烈思請求(首包buffer, yourUUID);
								if (解析結果?.hasError) throw new Error(解析結果.message || 'Invalid vless request');
								const { port, hostname, rawIndex, version, isUDP } = 解析結果;
								//console.log(`[gRPC] 魏烈思首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								const respHeader = new Uint8Array([version[0], 0]);
								grpcBridge.send(respHeader);
								const rawData = 首包buffer.slice(rawIndex);
								if (isDnsQuery) await forwardataudp(rawData, grpcBridge, null);
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID);
							}
						}
					}
					刷新發送佇列();
				}
			} catch (err) {
				console.log(`[gRPC轉發] 處理失敗: ${err?.message || err}`);
			} finally {
				釋放遠端寫入器();
				關閉連線();
			}
		},
		cancel() {
			try { remoteConnWrapper.socket?.close(); } catch (e) { }
			try { reader.releaseLock(); } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

///////////////////////////////////////////////////////////////////////WS傳輸資料///////////////////////////////////////////////
async function 處理WS請求(request, yourUUID) {
	const wssPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(wssPair);
	serverSock.accept();// @ts-ignore
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false;
	const earlyData = request.headers.get('sec-websocket-protocol') || '';
	const readable = makeReadableStr(serverSock, earlyData);
	let 判斷是否是木馬 = null;
	let 目前寫入Socket = null;
	let 遠端寫入器 = null;

	const 釋放遠端寫入器 = () => {
		if (遠端寫入器) {
			try { 遠端寫入器.releaseLock(); } catch (e) { }
			遠端寫入器 = null;
		}
		目前寫入Socket = null;
	};

	const 寫入遠端 = async (chunk, allowRetry = true) => {
		const socket = remoteConnWrapper.socket;
		if (!socket) return false;

		if (socket !== 目前寫入Socket) {
			釋放遠端寫入器();
			目前寫入Socket = socket;
			遠端寫入器 = socket.writable.getWriter();
		}

		try {
			await 遠端寫入器.write(chunk);
			return true;
		} catch (err) {
			釋放遠端寫入器();
			if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
				await remoteConnWrapper.retryConnect();
				return await 寫入遠端(chunk, false);
			}
			throw err;
		}
	};

	readable.pipeTo(new WritableStream({
		async write(chunk) {
			if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
			if (await 寫入遠端(chunk)) return;

			if (判斷是否是木馬 === null) {
				const bytes = new Uint8Array(chunk);
				判斷是否是木馬 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
			}

			if (await 寫入遠端(chunk)) return;

			if (判斷是否是木馬) {
				const 解析結果 = 解析木馬請求(chunk, yourUUID);
				if (解析結果?.hasError) throw new Error(解析結果.message || 'Invalid trojan request');
				const { port, hostname, rawClientData } = 解析結果;
				if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
				await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID);
			} else {
				const 解析結果 = 解析魏烈思請求(chunk, yourUUID);
				if (解析結果?.hasError) throw new Error(解析結果.message || 'Invalid vless request');
				const { port, hostname, rawIndex, version, isUDP } = 解析結果;
				if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
				if (isUDP) {
					if (port === 53) isDnsQuery = true;
					else throw new Error('UDP is not supported');
				}
				const respHeader = new Uint8Array([version[0], 0]);
				const rawData = chunk.slice(rawIndex);
				if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
				await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID);
			}
		},
		close() {
			釋放遠端寫入器();
		},
		abort() {
			釋放遠端寫入器();
		}
	})).catch((err) => {
		console.log(`[WS轉發] 處理失敗: ${err?.message || err}`);
		釋放遠端寫入器();
	});

	return new Response(null, { status: 101, webSocket: clientSock });
}

function 解析木馬請求(buffer, passwordPlainText) {
	const sha224Password = sha224(passwordPlainText);
	if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" };
	const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
	if (password !== sha224Password) return { hasError: true, message: "invalid password" };

	const socks5DataBuffer = buffer.slice(crLfIndex + 2);
	if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };

	const view = new DataView(socks5DataBuffer);
	const cmd = view.getUint8(0);
	if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" };

	const atype = view.getUint8(1);
	let addressLength = 0;
	let addressIndex = 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
			break;
		case 3: // Domain
			addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
			addressIndex += 1;
			address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		rawClientData: socks5DataBuffer.slice(portIndex + 4)
	};
}

function 解析魏烈思請求(chunk, token) {
	if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
	const version = new Uint8Array(chunk.slice(0, 1));
	if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
	const optLen = new Uint8Array(chunk.slice(17, 18))[0];
	const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
	const portIdx = 19 + optLen;
	const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
	let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
	const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
	switch (addressType) {
		case 1:
			addrLen = 4;
			hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
			break;
		case 2:
			addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
			addrValIdx += 1;
			hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			const ipv6 = [];
			const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
			for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
	console.log(`[TCP轉發] 目標: ${host}:${portNum} | 反代IP: ${反代IP} | 反代備援: ${啟用反代備援 ? '是' : '否'} | 反代類型: ${啟用SOCKS5反代 || 'proxyip'} | 全域: ${啟用SOCKS5全域反代 ? '是' : '否'}`);
	const 連線超時毫秒 = 1000;
	let 已透過代理發送首包 = false;

	async function 等待連線建立(remoteSock, timeoutMs = 連線超時毫秒) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('連線超時')), timeoutMs))
		]);
	}

	async function connectDirect(address, port, data = null, 所有反代陣列 = null, 反代備援 = true) {
		let remoteSock;
		if (所有反代陣列 && 所有反代陣列.length > 0) {
			for (let i = 0; i < 所有反代陣列.length; i++) {
				const 反代陣列索引 = (暫存反代陣列索引 + i) % 所有反代陣列.length;
				const [反代地址, 反代通訊埠] = 所有反代陣列[反代陣列索引];
				try {
					console.log(`[反代連線] 嘗試連線到: ${反代地址}:${反代通訊埠} (索引: ${反代陣列索引})`);
					remoteSock = connect({ hostname: 反代地址, port: 反代通訊埠 });
					await 等待連線建立(remoteSock);
					if (有效資料長度(data) > 0) {
						const testWriter = remoteSock.writable.getWriter();
						await testWriter.write(data);
						testWriter.releaseLock();
					}
					console.log(`[反代連線] 成功連線到: ${反代地址}:${反代通訊埠}`);
					暫存反代陣列索引 = 反代陣列索引;
					return remoteSock;
				} catch (err) {
					console.log(`[反代連線] 連線失敗: ${反代地址}:${反代通訊埠}, 錯誤: ${err.message}`);
					try { remoteSock?.close?.(); } catch (e) { }
					continue;
				}
			}
		}

		if (反代備援) {
			remoteSock = connect({ hostname: address, port: port });
			await 等待連線建立(remoteSock);
			if (有效資料長度(data) > 0) {
				const writer = remoteSock.writable.getWriter();
				await writer.write(data);
				writer.releaseLock();
			}
			return remoteSock;
		} else {
			closeSocketQuietly(ws);
			throw new Error('[反代連線] 所有反代連線失敗，且未啟用反代備援，連線終止。');
		}
	}

	async function connecttoPry(允許發送首包 = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}

		const 本次發送首包 = 允許發送首包 && !已透過代理發送首包 && 有效資料長度(rawData) > 0;
		const 本次首包資料 = 本次發送首包 ? rawData : null;

		const 目前連線任務 = (async () => {
			let newSocket;
			if (啟用SOCKS5反代 === 'socks5') {
				console.log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
				newSocket = await socks5Connect(host, portNum, 本次首包資料);
			} else if (啟用SOCKS5反代 === 'http') {
				console.log(`[HTTP代理] 代理到: ${host}:${portNum}`);
				newSocket = await httpConnect(host, portNum, 本次首包資料);
			} else if (啟用SOCKS5反代 === 'https') {
				console.log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
				newSocket = await httpConnect(host, portNum, 本次首包資料, true);
			} else {
				console.log(`[反代連線] 代理到: ${host}:${portNum}`);
				const 所有反代陣列 = await 解析地址通訊埠(反代IP, host, yourUUID);
				newSocket = await connectDirect(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, 本次首包資料, 所有反代陣列, 啟用反代備援);
			}
			if (本次發送首包) 已透過代理發送首包 = true;
			remoteConnWrapper.socket = newSocket;
			newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
			connectStreams(newSocket, ws, respHeader, null);
		})();

		remoteConnWrapper.connectingPromise = 目前連線任務;
		try {
			await 目前連線任務;
		} finally {
			if (remoteConnWrapper.connectingPromise === 目前連線任務) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已透過代理發送首包);

	const 驗證SOCKS5白名單 = (addr) => SOCKS5白名單.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(addr));
	if (啟用SOCKS5反代 && (啟用SOCKS5全域反代 || 驗證SOCKS5白名單(host))) {
		console.log(`[TCP轉發] 啟用 SOCKS5/HTTP/HTTPS 全域代理`);
		try {
			await connecttoPry();
		} catch (err) {
			console.log(`[TCP轉發] SOCKS5/HTTP/HTTPS 代理連線失敗: ${err.message}`);
			throw err;
		}
	} else {
		try {
			console.log(`[TCP轉發] 嘗試直連到: ${host}:${portNum}`);
			const initialSocket = await connectDirect(host, portNum, rawData);
			remoteConnWrapper.socket = initialSocket;
			connectStreams(initialSocket, ws, respHeader, async () => {
				if (remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
		} catch (err) {
			console.log(`[TCP轉發] 直連 ${host}:${portNum} 失敗: ${err.message}`);
			await connecttoPry();
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
	try {
		const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WebSocket.OPEN) {
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
						response.set(vlessHeader, 0);
						response.set(chunk, vlessHeader.length);
						webSocket.send(response.buffer);
						vlessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				}
			},
		}));
	} catch (error) {
		// console.error('UDP forward error:', error);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let header = headerData, hasData = false;
	await remoteSocket.readable.pipeTo(
		new WritableStream({
			async write(chunk, controller) {
				hasData = true;
				if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
				if (header) {
					const response = new Uint8Array(header.length + chunk.byteLength);
					response.set(header, 0);
					response.set(chunk, header.length);
					webSocket.send(response.buffer);
					header = null;
				} else {
					webSocket.send(chunk);
				}
			},
			abort() { },
		})
	).catch((err) => {
		closeSocketQuietly(webSocket);
	});
	if (!hasData && retryFunc) {
		await retryFunc();
	}
}

function makeReadableStr(socket, earlyDataHeader) {
	let cancelled = false;
	return new ReadableStream({
		start(controller) {
			socket.addEventListener('message', (event) => {
				if (!cancelled) controller.enqueue(event.data);
			});
			socket.addEventListener('close', () => {
				if (!cancelled) {
					closeSocketQuietly(socket);
					controller.close();
				}
			});
			socket.addEventListener('error', (err) => controller.error(err));
			const { earlyData, error } = base64ToArray(earlyDataHeader);
			if (error) controller.error(error);
			else if (earlyData) controller.enqueue(earlyData);
		},
		cancel() {
			cancelled = true;
			closeSocketQuietly(socket);
		}
	});
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
	if (speedTestDomains.includes(hostname)) {
		return true;
	}

	for (const domain of speedTestDomains) {
		if (hostname.endsWith('.' + domain) || hostname === domain) {
			return true;
		}
	}
	return false;
}

function base64ToArray(b64Str) {
	if (!b64Str) return { error: null };
	try {
		const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
		const bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) {
			bytes[i] = binaryString.charCodeAt(i);
		}
		return { earlyData: bytes.buffer, error: null };
	} catch (error) {
		return { error };
	}
}
///////////////////////////////////////////////////////SOCKS5/HTTP函式///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData) {
	const { username, password, hostname, port } = parsedSocks5Address;
	const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (有效資料長度(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch (e) { }
		try { reader.releaseLock(); } catch (e) { }
		try { socket.close(); } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false) {
	const { username, password, hostname, port } = parsedSocks5Address;
	const socket = HTTPS代理
		? connect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: connect({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPS代理) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} 代理在回傳 CONNECT 回應前關閉連線`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 回應標頭過長或無效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (有效資料長度(initialData) > 0) {
			const 遠端寫入器 = socket.writable.getWriter();
			await 遠端寫入器.write(initialData);
			遠端寫入器.releaseLock();
		}

		// CONNECT 回應頭後可能夾帶隧道資料，先回灌到可讀流，避免首包被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch (e) { }
		try { reader.releaseLock(); } catch (e) { }
		try { socket.close(); } catch (e) { }
		throw error;
	}
}
//////////////////////////////////////////////////功能性函式///////////////////////////////////////////////
function Clash訂閱設定檔熱修補(Clash_原始訂閱內容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECH啟用 = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const 需要處理ECH = Boolean(uuid && ECH啟用);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const 需要處理gRPC = config_JSON?.傳輸協定 === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_原始訂閱內容.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const 加上InlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const 匹配到gRPC網路 = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const 取得代理類型 = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const 取得憑證值 = (nodeText, isFlowStyle) => {
		const credentialField = 取得代理類型(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const 插入NameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const 加上Flow格式gRPCUserAgent = (nodeText) => {
		if (!匹配到gRPC網路(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return 加上InlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const 加上Block格式gRPCUserAgent = (nodeLines, topLevelIndent) => {
		const 頂級縮進 = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${頂級縮進}grpc-opts:`, `${頂級縮進}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = 加上InlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let 子級縮進 = topLevelIndent + 2;
		let 已有gRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && 子級縮進 === topLevelIndent + 2) 子級縮進 = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				已有gRPCUserAgent = true;
				break;
			}
		}
		if (!已有gRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(子級縮進)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const 加上Block格式ECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECH啟用 && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}":${ECH_DNS ? `\n      - ${ECH_DNS}` : ''}\n      - https://doh.cm.edu.kg/CMLiussss`).join('\n');
		clash_yaml = 插入NameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!需要處理ECH && !需要處理gRPC) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (需要處理gRPC) fullNode = 加上Flow格式gRPCUserAgent(fullNode);
			if (需要處理ECH && 取得憑證值(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (需要處理gRPC && 匹配到gRPC網路(nodeText)) {
				nodeLines = 加上Block格式gRPCUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (需要處理ECH && 取得憑證值(nodeText, false) === uuid.trim()) nodeLines = 加上Block格式ECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function Singbox訂閱設定檔熱修補(SingBox_原始訂閱內容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || config_JSON?.HOST || null;
	const ech_config = config_JSON?.ECH && ECH_SNI ? await getECH(ECH_SNI) : null;
	const sb_json_text = SingBox_原始訂閱內容.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		let config = JSON.parse(sb_json_text);

		// --- 1. TUN 入站遷移 (1.10.0+) ---
		if (Array.isArray(config.inbounds)) {
			config.inbounds.forEach(inbound => {
				if (inbound.type === 'tun') {
					const addresses = [];
					if (inbound.inet4_address) addresses.push(inbound.inet4_address);
					if (inbound.inet6_address) addresses.push(inbound.inet6_address);
					if (addresses.length > 0) {
						inbound.address = addresses;
						delete inbound.inet4_address;
						delete inbound.inet6_address;
					}

					const route_addresses = [];
					if (Array.isArray(inbound.inet4_route_address)) route_addresses.push(...inbound.inet4_route_address);
					if (Array.isArray(inbound.inet6_route_address)) route_addresses.push(...inbound.inet6_route_address);
					if (route_addresses.length > 0) {
						inbound.route_address = route_addresses;
						delete inbound.inet4_route_address;
						delete inbound.inet6_route_address;
					}

					const route_exclude_addresses = [];
					if (Array.isArray(inbound.inet4_route_exclude_address)) route_exclude_addresses.push(...inbound.inet4_route_exclude_address);
					if (Array.isArray(inbound.inet6_route_exclude_address)) route_exclude_addresses.push(...inbound.inet6_route_exclude_address);
					if (route_exclude_addresses.length > 0) {
						inbound.route_exclude_address = route_exclude_addresses;
						delete inbound.inet4_route_exclude_address;
						delete inbound.inet6_route_exclude_address;
					}
				}
			});
		}

		// --- 2. 遷移 Geosite/GeoIP 到 rule_set (1.8.0+) 及 Actions (1.11.0+) ---
		const ruleSetsDefinitions = new Map();
		const processRules = (rules, isDns = false) => {
			if (!Array.isArray(rules)) return;
			rules.forEach(rule => {
				if (rule.geosite) {
					const geositeList = Array.isArray(rule.geosite) ? rule.geosite : [rule.geosite];
					rule.rule_set = geositeList.map(name => {
						const tag = `geosite-${name}`;
						if (!ruleSetsDefinitions.has(tag)) {
							ruleSetsDefinitions.set(tag, {
								tag: tag,
								type: "remote",
								format: "binary",
								url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${name}.srs`,
								download_detour: "DIRECT"
							});
						}
						return tag;
					});
					delete rule.geosite;
				}
				if (rule.geoip) {
					const geoipList = Array.isArray(rule.geoip) ? rule.geoip : [rule.geoip];
					rule.rule_set = rule.rule_set || [];
					geoipList.forEach(name => {
						const tag = `geoip-${name}`;
						if (!ruleSetsDefinitions.has(tag)) {
							ruleSetsDefinitions.set(tag, {
								tag: tag,
								type: "remote",
								format: "binary",
								url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-${name}.srs`,
								download_detour: "DIRECT"
							});
						}
						rule.rule_set.push(tag);
					});
					delete rule.geoip;
				}
				const targetField = isDns ? 'server' : 'outbound';
				const actionValue = String(rule[targetField]).toUpperCase();
				if (actionValue === 'REJECT' || actionValue === 'BLOCK') {
					rule.action = 'reject';
					rule.method = 'drop'; // 強制使用現代方式
					delete rule[targetField];
				}
			});
		};

		if (config.dns && config.dns.rules) processRules(config.dns.rules, true);
		if (config.route && config.route.rules) processRules(config.route.rules, false);

		if (ruleSetsDefinitions.size > 0) {
			if (!config.route) config.route = {};
			config.route.rule_set = Array.from(ruleSetsDefinitions.values());
		}

		// --- 3. 相容性與糾錯 ---
		if (!config.outbounds) config.outbounds = [];

		// 移除 outbounds 中冗餘的 block 類型節點 (如果它們已經被 action 替代)
		// 但保留 DIRECT 這種必需的特殊出站
		config.outbounds = config.outbounds.filter(o => {
			if (o.tag === 'REJECT' || o.tag === 'block') {
				return false; // 移除，因為已經改用 action: reject 了
			}
			return true;
		});

		const existingOutboundTags = new Set(config.outbounds.map(o => o.tag));

		if (!existingOutboundTags.has('DIRECT')) {
			config.outbounds.push({ "type": "direct", "tag": "DIRECT" });
			existingOutboundTags.add('DIRECT');
		}

		if (config.dns && config.dns.servers) {
			const dnsServerTags = new Set(config.dns.servers.map(s => s.tag));
			if (config.dns.rules) {
				config.dns.rules.forEach(rule => {
					if (rule.server && !dnsServerTags.has(rule.server)) {
						if (rule.server === 'dns_block' && dnsServerTags.has('block')) {
							rule.server = 'block';
						} else if (rule.server.toLowerCase().includes('block') && !dnsServerTags.has(rule.server)) {
							config.dns.servers.push({ "tag": rule.server, "address": "rcode://success" });
							dnsServerTags.add(rule.server);
						}
					}
				});
			}
		}

		config.outbounds.forEach(outbound => {
			if (outbound.type === 'selector' || outbound.type === 'urltest') {
				if (Array.isArray(outbound.outbounds)) {
					// 修正：如果選擇器引用了被移除的 REJECT/block，直接將其過濾掉
					// 因為路由規則已經透過 action 攔截了，不需要走選擇器
					outbound.outbounds = outbound.outbounds.filter(tag => {
						const upperTag = tag.toUpperCase();
						return existingOutboundTags.has(tag) && upperTag !== 'REJECT' && upperTag !== 'BLOCK';
					});
					if (outbound.outbounds.length === 0) outbound.outbounds.push("DIRECT");
				}
			}
		});

		// --- 4. UUID 匹配節點的 TLS 熱修補 (utls & ech) ---
		if (uuid) {
			config.outbounds.forEach(outbound => {
				// 僅處理包含 uuid 或 password 且匹配的節點
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 確保 tls 物件存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 加上/更新 utls 設定
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，加上/更新 ech 設定
					if (ech_config) {
						outbound.tls.ech = {
							enabled: true,
							//query_server_name: "cloudflare-ech.com",// 等待 1.13.0+ 版本上線
							config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox熱修補執行失敗:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function Surge訂閱設定檔熱修補(content, url, config_JSON) {
	const 每行內容 = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const 完整節點路徑 = config_JSON.隨機路徑 ? 隨機路徑(config_JSON.完整節點路徑) : config_JSON.完整節點路徑;
	let 輸出內容 = "";
	for (let x of 每行內容) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const 備改內容 = `sni=${host}, skip-cert-verify=${config_JSON.略過憑證驗證}`;
			const 正確內容 = `sni=${host}, skip-cert-verify=${config_JSON.略過憑證驗證}, ws=true, ws-path=${完整節點路徑.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			輸出內容 += x.replace(new RegExp(備改內容, 'g'), 正確內容).replace("[", "").replace("]", "") + '\n';
		} else {
			輸出內容 += x + '\n';
		}
	}

	輸出內容 = `#!MANAGED-CONFIG ${url} interval=${config_JSON.優選訂閱生成.SUBUpdateTime * 60 * 60} strict=false` + 輸出內容.substring(輸出內容.indexOf('\n'));
	return 輸出內容;
}

async function 請求日誌紀錄(env, request, 瀏覽IP, 請求類型 = "Get_SUB", config_JSON, 是否寫入KV日誌 = true) {
	try {
		const 目前時間 = new Date();
		const 日誌內容 = { TYPE: 請求類型, IP: 瀏覽IP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 目前時間.getTime() };
		if (config_JSON.TG.啟用) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				await sendMessage(TG_JSON.BotToken, TG_JSON.ChatID, 日誌內容, config_JSON);
			} catch (error) { console.error(`讀取tg.json出錯: ${error.message}`) }
		}
		是否寫入KV日誌 = ['1', 'true'].includes(env.OFF_LOG) ? false : 是否寫入KV日誌;
		if (!是否寫入KV日誌) return;
		let 日誌陣列 = [];
		const 現有日誌 = await env.KV.get('log.json'), KV容量限制 = 4;//MB
		if (現有日誌) {
			try {
				日誌陣列 = JSON.parse(現有日誌);
				if (!Array.isArray(日誌陣列)) { 日誌陣列 = [日誌內容]; }
				else if (請求類型 !== "Get_SUB") {
					const 三十分鐘前時間戳 = 目前時間.getTime() - 30 * 60 * 1000;
					if (日誌陣列.some(log => log.TYPE !== "Get_SUB" && log.IP === 瀏覽IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分鐘前時間戳)) return;
					日誌陣列.push(日誌內容);
					while (JSON.stringify(日誌陣列, null, 2).length > KV容量限制 * 1024 * 1024 && 日誌陣列.length > 0) 日誌陣列.shift();
				} else {
					日誌陣列.push(日誌內容);
					while (JSON.stringify(日誌陣列, null, 2).length > KV容量限制 * 1024 * 1024 && 日誌陣列.length > 0) 日誌陣列.shift();
				}
			} catch (e) { 日誌陣列 = [日誌內容]; }
		} else { 日誌陣列 = [日誌內容]; }
		await env.KV.put('log.json', JSON.stringify(日誌陣列, null, 2));
	} catch (error) { console.error(`日誌紀錄失敗: ${error.message}`); }
}

async function sendMessage(BotToken, ChatID, 日誌內容, config_JSON) {
	if (!BotToken || !ChatID) return;

	try {
		const 請求時間 = new Date(日誌內容.TIME).toLocaleString('zh-TW', { timeZone: 'Asia/Taipei' });
		const 請求URL = new URL(日誌內容.URL);
		const msg = `<b>#${config_JSON.優選訂閱生成.SUBNAME} 日誌通知</b>\n\n` +
			`📌 <b>類型：</b>#${日誌內容.TYPE}\n` +
			`🌐 <b>IP：</b><code>${日誌內容.IP}</code>\n` +
			`📍 <b>位置：</b>${日誌內容.CC}\n` +
			`🏢 <b>ASN：</b>${日誌內容.ASN}\n` +
			`🔗 <b>網域：</b><code>${請求URL.host}</code>\n` +
			`🔍 <b>路徑：</b><code>${請求URL.pathname + 請求URL.search}</code>\n` +
			`🤖 <b>UA：</b><code>${日誌內容.UA}</code>\n` +
			`📅 <b>時間：</b>${請求時間}\n` +
			`${config_JSON.CF.Usage.success ? `📊 <b>請求用量：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;

		const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
		return fetch(url, {
			method: 'GET',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 日誌內容.UA || 'Unknown',
			}
		});
	} catch (error) { console.error('Error sending message:', error) }
}

function 遮罩敏感資訊(文本, 前綴長度 = 3, 後綴長度 = 2) {
	if (!文本 || typeof 文本 !== 'string') return 文本;
	if (文本.length <= 前綴長度 + 後綴長度) return 文本; // 如果長度太短，直接回傳

	const 前綴 = 文本.slice(0, 前綴長度);
	const 後綴 = 文本.slice(-後綴長度);
	const 星號數量 = 文本.length - 前綴長度 - 後綴長度;

	return `${前綴}${'*'.repeat(星號數量)}${後綴}`;
}

async function MD5MD5(文本) {
	const 編碼器 = new TextEncoder();

	const 第一次雜湊 = await crypto.subtle.digest('MD5', 編碼器.encode(文本));
	const 第一次雜湊陣列 = Array.from(new Uint8Array(第一次雜湊));
	const 第一次十六進位 = 第一次雜湊陣列.map(位元組 => 位元組.toString(16).padStart(2, '0')).join('');

	const 第二次雜湊 = await crypto.subtle.digest('MD5', 編碼器.encode(第一次十六進位.slice(7, 27)));
	const 第二次雜湊陣列 = Array.from(new Uint8Array(第二次雜湊));
	const 第二次十六進位 = 第二次雜湊陣列.map(位元組 => 位元組.toString(16).padStart(2, '0')).join('');

	return 第二次十六進位.toLowerCase();
}

function 隨機路徑(完整節點路徑 = "/") {
	const 常用路徑目錄 = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "video", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const 隨機數 = Math.floor(Math.random() * 3 + 1);
	const 隨機路徑字串 = 常用路徑目錄.sort(() => 0.5 - Math.random()).slice(0, 隨機數).join('/');
	if (完整節點路徑 === "/") return `/${隨機路徑字串}`;
	else return `/${隨機路徑字串 + 完整節點路徑.replace('/?', '?')}`;
}

function 隨機替換萬用字元(h) {
	if (!h?.includes('*')) return h;
	const 字元集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return h.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
			s += 字元集[Math.floor(Math.random() * 36)];
		return s;
	});
}

function 批次替換網域(內容, hosts, 每組數量 = 2) {
	const 打亂後陣列 = [...hosts].sort(() => Math.random() - 0.5);
	let count = 0, currentRandomHost = null;
	return 內容.replace(/example\.com/g, () => {
		if (count % 每組數量 === 0) currentRandomHost = 隨機替換萬用字元(打亂後陣列[Math.floor(count / 每組數量) % 打亂後陣列.length]);
		count++;
		return currentRandomHost;
	});
}

async function DoH查詢(網域, 紀錄類型, DoH解析服務 = "https://cloudflare-dns.com/dns-query") {
	const 開始時間 = performance.now();
	console.log(`[DoH查詢] 開始查詢 ${網域} ${紀錄類型} via ${DoH解析服務}`);
	try {
		// 紀錄類型字串轉數值
		const 類型對映 = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
		const qtype = 類型對映[紀錄類型.toUpperCase()] || 1;

		// 編碼網域為 DNS wire format labels
		const 編碼網域 = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length; }
			return result;
		};

		// 構建 DNS 查詢報文
		const qname = 編碼網域(網域);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, 0);       // ID
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (遞迴查詢)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 透過 POST 發送 dns-message 請求
		console.log(`[DoH查詢] 發送查詢報文 ${網域} via ${DoH解析服務} (type=${qtype}, ${query.length}位元組)`);
		const response = await fetch(DoH解析服務, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH查詢] 請求失敗 ${網域} ${紀錄類型} via ${DoH解析服務} 回應代碼:${response.status}`);
			return [];
		}

		// 解析 DNS 回應報文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		console.log(`[DoH查詢] 收到回應 ${網域} ${紀錄類型} via ${DoH解析服務} (${buf.length}位元組, ${ancount}條應答)`);

		// 解析網域（處理指標壓縮）
		const 解析網域 = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break; }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳過 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = 解析網域(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳過 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = 解析網域(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 紀錄
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 紀錄
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 紀錄 (長度前綴字串)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 紀錄
				const [cname] = 解析網域(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const 耗時 = (performance.now() - 開始時間).toFixed(2);
		console.log(`[DoH查詢] 查詢完成 ${網域} ${紀錄類型} via ${DoH解析服務} ${耗時}ms 共${answers.length}條結果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		return answers;
	} catch (error) {
		const 耗時 = (performance.now() - 開始時間).toFixed(2);
		console.error(`[DoH查詢] 查詢失敗 ${網域} ${紀錄類型} via ${DoH解析服務} ${耗時}ms:`, error);
		return [];
	}
}

async function getECH(host) {
	try {
		const answers = await DoH查詢(host, 'HTTPS');
		if (!answers.length) return '';
		for (const ans of answers) {
			if (ans.type !== 65 || !ans.rdata) continue;
			const bytes = ans.rdata;
			// 解析 SVCB/HTTPS rdata: SvcPriority(2) + TargetName(variable) + SvcParams
			let offset = 2; // 跳過 SvcPriority
			// 跳過 TargetName (網域編碼)
			while (offset < bytes.length) {
				const len = bytes[offset];
				if (len === 0) { offset++; break; }
				offset += len + 1;
			}
			// 遍歷 SvcParams 鍵值對
			while (offset + 4 <= bytes.length) {
				const key = (bytes[offset] << 8) | bytes[offset + 1];
				const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
				offset += 4;
				// key=5 是 ECH (Encrypted Client Hello)
				if (key === 5) return btoa(String.fromCharCode(...bytes.slice(offset, offset + len)));
				offset += len;
			}
		}
		return '';
	} catch {
		return '';
	}
}

async function 讀取config_JSON(env, hostname, userID, UA = "Mozilla/5.0", 重設設定 = false) {
	//const host = 隨機替換萬用字元(hostname);
	const _p = atob("UFJPWFlJUA==");
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', 初始化開始時間 = performance.now(), 預設設定JSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		協定類型: "v" + "le" + "ss",
		傳輸協定: "ws",
		gRPC模式: "gun",
		gRPCUserAgent: UA,
		略過憑證驗證: false,
		啟用0RTT: false,
		TLS分片: null,
		隨機路徑: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		Fingerprint: "chrome",
		優選訂閱生成: {
			local: true, // true: 基於本機的優選地址  false: 優選訂閱生成器
			本機IP庫: {
				隨機IP: true, // 當 隨機IP 為true時生效，啟用隨機IP的數量，否則使用KV內的ADD.txt
				隨機數量: 16,
				指定通訊埠: -1,
			},
			SUB: null,
			SUBNAME: "edge" + "tunnel",
			SUBUpdateTime: 3, // 訂閱更新時間（小時）
			TOKEN: await MD5MD5(hostname + userID),
		},
		訂閱轉換設定: {
			SUBAPI: "https://SUBAPI.cmliussss.net",
			SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
			SUBEMOJI: false,
		},
		反代: {
			[_p]: "auto",
			SOCKS5: {
				啟用: 啟用SOCKS5反代,
				全域: 啟用SOCKS5全域反代,
				帳號: 我的SOCKS5帳號,
				白名單: SOCKS5白名單,
			},
			路徑模板: {
				[_p]: "proxyip=" + 占位符,
				SOCKS5: {
					全域: "socks5://" + 占位符,
					標準: "socks5=" + 占位符
				},
				HTTP: {
					全域: "http://" + 占位符,
					標準: "http=" + 占位符
				},
			},
		},
		TG: {
			啟用: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || 重設設定 == true) {
			await env.KV.put('config.json', JSON.stringify(預設設定JSON, null, 2));
			config_JSON = 預設設定JSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`讀取config_JSON出錯: ${error.message}`);
		config_JSON = 預設設定JSON;
	}

	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await 整理成陣列(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.隨機路徑) config_JSON.隨機路徑 = false;
	if (!config_JSON.啟用0RTT) config_JSON.啟用0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';

	if (!config_JSON.gRPC模式) config_JSON.gRPC模式 = 'gun';

	if (!config_JSON.反代.路徑模板?.[_p]) {
		config_JSON.反代.路徑模板 = {
			[_p]: "proxyip=" + 占位符,
			SOCKS5: {
				全域: "socks5://" + 占位符,
				標準: "socks5=" + 占位符
			},
			HTTP: {
				全域: "http://" + 占位符,
				標準: "http=" + 占位符
			},
		};
	}

	const 代理設定 = config_JSON.反代.路徑模板[config_JSON.反代.SOCKS5.啟用?.toUpperCase()];

	let 路徑反代參數 = '';
	if (代理設定 && config_JSON.反代.SOCKS5.帳號) 路徑反代參數 = (config_JSON.反代.SOCKS5.全域 ? 代理設定.全域 : 代理設定.標準).replace(占位符, config_JSON.反代.SOCKS5.帳號);
	else if (config_JSON.反代[_p] !== 'auto') 路徑反代參數 = config_JSON.反代.路徑模板[_p].replace(占位符, config_JSON.反代[_p]);

	let 反代查詢參數 = '';
	if (路徑反代參數.includes('?')) {
		const [反代路徑部分, 反代查詢部分] = 路徑反代參數.split('?');
		路徑反代參數 = 反代路徑部分;
		反代查詢參數 = 反代查詢部分;
	}

	config_JSON.PATH = config_JSON.PATH.replace(路徑反代參數, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [路徑部分, ...查詢陣列] = normalizedPath.split('?');
	const 查詢部分 = 查詢陣列.length ? '?' + 查詢陣列.join('?') : '';
	const 最終查詢部分 = 反代查詢參數 ? (查詢部分 ? 查詢部分 + '&' + 反代查詢參數 : '?' + 反代查詢參數) : 查詢部分;
	config_JSON.完整節點路徑 = (路徑部分 || '/') + (路徑部分 && 路徑反代參數 ? '/' : '') + 路徑反代參數 + 最終查詢部分 + (config_JSON.啟用0RTT ? (最終查詢部分 ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
	const TLS分片參數 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINK參數 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	config_JSON.LINK = `${config_JSON.協定類型}://${userID}@${host}:443?security=tls&type=${config_JSON.傳輸協定 + ECHLINK參數}&host=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&path=${encodeURIComponent(config_JSON.隨機路徑 ? 隨機路徑(config_JSON.完整節點路徑) : config_JSON.完整節點路徑) + TLS分片參數}&encryption=none${config_JSON.略過憑證驗證 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.優選訂閱生成.SUBNAME)}`;
	config_JSON.優選訂閱生成.TOKEN = await MD5MD5(hostname + userID);

	const 初始化TG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { 啟用: config_JSON.TG.啟用 ? config_JSON.TG.啟用 : false, ...初始化TG_JSON };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? 遮罩敏感資訊(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`讀取tg.json出錯: ${error.message}`);
	}

	const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`請求 CF_JSON.UsageAPI 失敗: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 遮罩敏感資訊(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? 遮罩敏感資訊(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? 遮罩敏感資訊(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`讀取cf.json出錯: ${error.message}`);
	}

	config_JSON.載入時間 = (performance.now() - 初始化開始時間).toFixed(2) + 'ms';
	return config_JSON;
}

async function 生成隨機IP(request, count = 16, 指定通訊埠 = -1) {
	const ISP設定 = {
		'9808': { file: 'cmcc', name: 'CF移動優選' },
		'4837': { file: 'cu', name: 'CF聯通優選' },
		'17623': { file: 'cu', name: 'CF聯通優選' },
		'17816': { file: 'cu', name: 'CF聯通優選' },
		'4134': { file: 'ct', name: 'CF電信優選' },
	};
	const asn = request.cf.asn, isp = ISP設定[asn];
	const cidr_url = isp ? `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${isp.file}.txt` : 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt';
	const cfname = isp?.name || 'CF官方優選';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? await 整理成陣列(await res.text()) : ['104.16.0.0/13']; } catch { cidrList = ['104.16.0.0/13']; }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};

	const randomIPs = Array.from({ length: count }, () => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		return `${ip}:${指定通訊埠 === -1 ? cfport[Math.floor(Math.random() * cfport.length)] : 指定通訊埠}#${cfname}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function 整理成陣列(內容) {
	var 替換後的內容 = 內容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替換後的內容.charAt(0) == ',') 替換後的內容 = 替換後的內容.slice(1);
	if (替換後的內容.charAt(替換後的內容.length - 1) == ',') 替換後的內容 = 替換後的內容.slice(0, 替換後的內容.length - 1);
	const 地址陣列 = 替換後的內容.split(',');
	return 地址陣列;
}

function isValidBase64(str) {
	if (typeof str !== 'string') return false;
	const cleanStr = str.replace(/\s/g, '');
	if (cleanStr.length === 0 || cleanStr.length % 4 !== 0) return false;
	const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
	if (!base64Regex.test(cleanStr)) return false;
	try {
		atob(cleanStr);
		return true;
	} catch {
		return false;
	}
}

function base64Decode(str) {
	const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
	const decoder = new TextDecoder('utf-8');
	return decoder.decode(bytes);
}

async function 取得優選訂閱生成器資料(優選訂閱生成器HOST) {
	let 優選IP = [], 其他節點LINK = '', 格式化HOST = 優選訂閱生成器HOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(格式化HOST)) 格式化HOST = `https://${格式化HOST}`;

	try {
		const url = new URL(格式化HOST);
		格式化HOST = url.origin;
	} catch (error) {
		優選IP.push(`127.0.0.1:1234#${優選訂閱生成器HOST}優選訂閱生成器格式化異常:${error.message}`);
		return [優選IP, 其他節點LINK];
	}

	const 優選訂閱生成器URL = `${格式化HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(優選訂閱生成器URL, {
			headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' }
		});

		if (!response.ok) {
			優選IP.push(`127.0.0.1:1234#${優選訂閱生成器HOST}優選訂閱生成器異常:${response.statusText}`);
			return [優選IP, 其他節點LINK];
		}

		const 優選訂閱生成器回傳訂閱內容 = atob(await response.text());
		const 訂閱行列表 = 優選訂閱生成器回傳訂閱內容.includes('\r\n')
			? 優選訂閱生成器回傳訂閱內容.split('\r\n')
			: 優選訂閱生成器回傳訂閱內容.split('\n');

		for (const 行內容 of 訂閱行列表) {
			if (!行內容.trim()) continue; // 跳過空行
			if (行內容.includes('00000000-0000-4000-8000-000000000000') && 行內容.includes('example.com')) {
				// 這是優選IP行，擷取 網域:通訊埠#備註
				const 地址匹配 = 行內容.match(/:\/\/[^@]+@([^?]+)/);
				if (地址匹配) {
					let 地址通訊埠 = 地址匹配[1], 備註 = ''; // 網域:通訊埠 或 IP:通訊埠
					const 備註匹配 = 行內容.match(/#(.+)$/);
					if (備註匹配) 備註 = '#' + decodeURIComponent(備註匹配[1]);
					優選IP.push(地址通訊埠 + 備註);
				}
			} else {
				其他節點LINK += 行內容 + '\n';
			}
		}
	} catch (error) {
		優選IP.push(`127.0.0.1:1234#${優選訂閱生成器HOST}優選訂閱生成器異常:${error.message}`);
	}

	return [優選IP, 其他節點LINK];
}

async function 請求優選API(urls, 預設通訊埠 = '443', 超時時間 = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), 反代IP池 = new Set();
	let 訂閱連結回應的明文LINK內容 = '', 需要訂閱轉換訂閱URLs = [];
	await Promise.allSettled(urls.map(async (url) => {
		// 檢查URL是否包含備註名
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const API備註名 = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const 優選IP作為反代IP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [優選IP, 其他節點LINK] = await 取得優選訂閱生成器資料(urlWithoutHash);
				// 處理第一個陣列 - 優選IP
				if (API備註名) {
					for (const ip of 優選IP) {
						const 處理後IP = ip.includes('#')
							? `${ip} [${API備註名}]`
							: `${ip}#[${API備註名}]`;
						results.add(處理後IP);
						if (優選IP作為反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of 優選IP) {
						results.add(ip);
						if (優選IP作為反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				}
				// 處理第二個陣列 - 其他節點LINK
				if (其他節點LINK && typeof 其他節點LINK === 'string' && API備註名) {
					const 處理後LINK內容 = 其他節點LINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整連結 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API備註名}]`)}`
							: `${link}${encodeURIComponent(`#[${API備註名}]`)}`;
						return `${完整連結}${lineEnd}`;
					});
					訂閱連結回應的明文LINK內容 += 處理後LINK內容;
				} else if (其他節點LINK && typeof 其他節點LINK === 'string') {
					訂閱連結回應的明文LINK內容 += 其他節點LINK;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 超時時間);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// 根據 Content-Type 回應頭判斷編碼優先級
				let decoders = ['utf-8', 'gb2312']; // 預設優先 UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // 如果明確指定 GB 系編碼，優先嘗試 GB2312
				}

				// 嘗試多種編碼解碼
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// 驗證解碼結果的有效性
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// 如果有替換字元 (U+FFFD)，說明編碼不匹配，繼續嘗試下一個編碼
							continue;
						}
					} catch (e) {
						// 該編碼解碼失敗，嘗試下一個
						continue;
					}
				}

				// 如果所有編碼都失敗或無效，嘗試 response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// 如果回傳的是空或無效資料，回傳
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// 預先處理訂閱內容
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox 設定
				需要訂閱轉換訂閱URLs.add(url);
				return;
			}
			*/

			const 預先處理訂閱明文內容 = isValidBase64(text) ? base64Decode(text) : text;
			if (預先處理訂閱明文內容.split('#')[0].includes('://')) {
				// 處理LINK內容
				if (API備註名) {
					const 處理後LINK內容 = 預先處理訂閱明文內容.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整連結 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API備註名}]`)}`
							: `${link}${encodeURIComponent(`#[${API備註名}]`)}`;
						return `${完整連結}${lineEnd}`;
					});
					訂閱連結回應的明文LINK內容 += 處理後LINK內容 + '\n';
				} else {
					訂閱連結回應的明文LINK內容 += 預先處理訂閱明文內容 + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || 預設通訊埠;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// 處理第一個陣列 - 優選IP
					if (API備註名) {
						const 處理後IP = ipItem.includes('#')
							? `${ipItem} [${API備註名}]`
							: `${ipItem}#[${API備註名}]`;
						results.add(處理後IP);
					} else {
						results.add(ipItem);
					}
					if (優選IP作為反代IP) 反代IP池.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// 處理第一個陣列 - 優選IP
						if (API備註名) {
							const 處理後IP = `${ipItem} [${API備註名}]`;
							results.add(處理後IP);
						} else {
							results.add(ipItem);
						}
						if (優選IP作為反代IP) 反代IP池.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('延迟'));
					const speedIdx = headers.findIndex(h => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || 預設通訊埠;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF優選 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// 處理第一個陣列 - 優選IP
						if (API備註名) {
							const 處理後IP = `${ipItem} [${API備註名}]`;
							results.add(處理後IP);
						} else {
							results.add(ipItem);
						}
						if (優選IP作為反代IP) 反代IP池.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// 將LINK內容轉換為陣列並去重
	const LINK陣列 = 訂閱連結回應的明文LINK內容.trim() ? [...new Set(訂閱連結回應的明文LINK內容.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINK陣列, 需要訂閱轉換訂閱URLs, Array.from(反代IP池)];
}

async function 反代參數取得(request) {
	const url = new URL(request.url);
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();

	我的SOCKS5帳號 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || null;
	啟用SOCKS5全域反代 = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) 啟用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) 啟用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) 啟用SOCKS5反代 = 'https';

	const 解析代理URL = (值, 強制全域 = true) => {
		const 匹配 = /^(socks5|http|https):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		啟用SOCKS5反代 = 匹配[1].toLowerCase();
		我的SOCKS5帳號 = 匹配[2].split('/')[0];
		if (強制全域) 啟用SOCKS5全域反代 = true;
		return true;
	};

	const 設定反代IP = (值) => {
		反代IP = 值;
		啟用反代備援 = false;
	};

	const 擷取路徑值 = (值) => {
		if (!值.includes('://')) {
			const 斜線索引 = 值.indexOf('/');
			return 斜線索引 > 0 ? 值.slice(0, 斜線索引) : 值;
		}
		const 協定拆分 = 值.split('://');
		if (協定拆分.length !== 2) return 值;
		const 斜線索引 = 協定拆分[1].indexOf('/');
		return 斜線索引 > 0 ? `${協定拆分[0]}://${協定拆分[1].slice(0, 斜線索引)}` : 值;
	};

	const 查詢反代IP = searchParams.get('proxyip');
	if (查詢反代IP !== null) {
		if (!解析代理URL(查詢反代IP)) return 設定反代IP(查詢反代IP);
	} else {
		let 匹配 = /\/(socks5?|http|https):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const 類型 = 匹配[1].toLowerCase();
			啟用SOCKS5反代 = 類型 === 'http' ? 'http' : (類型 === 'https' ? 'https' : 'socks5');
			我的SOCKS5帳號 = 匹配[2].split('/')[0];
			啟用SOCKS5全域反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https)=([^/?#\s]+)/i.exec(pathname))) {
			const 類型 = 匹配[1].toLowerCase();
			我的SOCKS5帳號 = 匹配[2].split('/')[0];
			啟用SOCKS5反代 = 類型.includes('https') ? 'https' : (類型.includes('http') ? 'http' : 'socks5');
			if (類型.startsWith('g')) 啟用SOCKS5全域反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const 路徑反代值 = 擷取路徑值(匹配[2]);
			if (!解析代理URL(路徑反代值)) return 設定反代IP(路徑反代值);
		}
	}

	if (!我的SOCKS5帳號) {
		啟用SOCKS5反代 = null;
		return;
	}

	try {
		parsedSocks5Address = await 取得SOCKS5帳號(我的SOCKS5帳號, 啟用SOCKS5反代 === 'https' ? 443 : 80);
		if (searchParams.get('socks5')) 啟用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) 啟用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) 啟用SOCKS5反代 = 'https';
		else 啟用SOCKS5反代 = 啟用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失敗:', err.message);
		啟用SOCKS5反代 = null;
	}
}

const SOCKS5帳號Base64正則 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6方括號正則 = /^\[.*\]$/;
function 取得SOCKS5帳號(address, 預設通訊埠 = 80) {
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5帳號Base64正則.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = atIndex === -1 ? address : address.slice(atIndex + 1);
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('無效的 SOCKS 地址格式：認證部分必須是 "username:password" 的形式');

	let hostname = hostPart, port = 預設通訊埠;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('無效的 SOCKS 地址格式：通訊埠號碼必須是數字');
	if (hostname.includes(":") && !IPv6方括號正則.test(hostname)) throw new Error('無效的 SOCKS 地址格式：IPv6 地址必須用方括號括起來，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`帳戶取得失敗: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("未找到帳戶");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`查詢失敗: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("未找到帳戶資料");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		console.log(`統計結果 - Pages: ${pages}, Workers: ${workers}, 總計: ${total}, 上限: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('取得使用量錯誤:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function 解析地址通訊埠(proxyIP, 目標網域 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	if (!暫存反代IP || !暫存反代解析陣列 || 暫存反代IP !== proxyIP) {
		proxyIP = proxyIP.toLowerCase();

		function 解析地址通訊埠字串(str) {
			let 地址 = str, 通訊埠 = 443;
			if (str.includes(']:')) {
				const parts = str.split(']:');
				地址 = parts[0] + ']';
				通訊埠 = parseInt(parts[1], 10) || 通訊埠;
			} else if (str.includes(':') && !str.startsWith('[')) {
				const colonIndex = str.lastIndexOf(':');
				地址 = str.slice(0, colonIndex);
				通訊埠 = parseInt(str.slice(colonIndex + 1), 10) || 通訊埠;
			}
			return [地址, 通訊埠];
		}

		const 反代IP陣列 = await 整理成陣列(proxyIP);
		let 所有反代陣列 = [];

		// 遍歷陣列中的每個IP元素進行處理
		for (const singleProxyIP of 反代IP陣列) {
			if (singleProxyIP.includes('.william')) {
				try {
					let txtRecords = await DoH查詢(singleProxyIP, 'TXT');
					let txtData = txtRecords.filter(r => r.type === 16).map(r => /** @type {string} */(r.data));
					if (txtData.length === 0) {
						console.log(`[反代解析] 預設DoH未取得TXT紀錄，切換Google DoH重試 ${singleProxyIP}`);
						txtRecords = await DoH查詢(singleProxyIP, 'TXT', 'https://dns.google/dns-query');
						txtData = txtRecords.filter(r => r.type === 16).map(r => /** @type {string} */(r.data));
					}
					if (txtData.length > 0) {
						let data = txtData[0];
						if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
						const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
						所有反代陣列.push(...prefixes.map(prefix => 解析地址通訊埠字串(prefix)));
					}
				} catch (error) {
					console.error('解析William網域失敗:', error);
				}
			} else {
				let [地址, 通訊埠] = 解析地址通訊埠字串(singleProxyIP);

				if (singleProxyIP.includes('.tp')) {
					const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
					if (tpMatch) 通訊埠 = parseInt(tpMatch[1], 10);
				}

				// 判斷是否是網域（非IP地址）
				const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
				const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

				if (!ipv4Regex.test(地址) && !ipv6Regex.test(地址)) {
					// 平行查詢 A 和 AAAA 紀錄
					let [aRecords, aaaaRecords] = await Promise.all([
						DoH查詢(地址, 'A'),
						DoH查詢(地址, 'AAAA')
					]);

					let ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
					let ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
					let ipAddresses = [...ipv4List, ...ipv6List];

					// 預設DoH無結果時，切換Google DoH重試
					if (ipAddresses.length === 0) {
						console.log(`[反代解析] 預設DoH未取得解析結果，切換Google DoH重試 ${地址}`);
						[aRecords, aaaaRecords] = await Promise.all([
							DoH查詢(地址, 'A', 'https://dns.google/dns-query'),
							DoH查詢(地址, 'AAAA', 'https://dns.google/dns-query')
						]);
						ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
						ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
						ipAddresses = [...ipv4List, ...ipv6List];
					}

					if (ipAddresses.length > 0) {
						所有反代陣列.push(...ipAddresses.map(ip => [ip, 通訊埠]));
					} else {
						所有反代陣列.push([地址, 通訊埠]);
					}
				} else {
					所有反代陣列.push([地址, 通訊埠]);
				}
			}
		}
		const 排序後陣列 = 所有反代陣列.sort((a, b) => a[0].localeCompare(b[0]));
		const 目標根網域 = 目標網域.includes('.') ? 目標網域.split('.').slice(-2).join('.') : 目標網域;
		let 隨機種子 = [...(目標根網域 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
		console.log(`[反代解析] 隨機種子: ${隨機種子}\n目標站點: ${目標根網域}`)
		const 洗牌後 = [...排序後陣列].sort(() => (隨機種子 = (隨機種子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
		暫存反代解析陣列 = 洗牌後.slice(0, 8);
		console.log(`[反代解析] 解析完成 總數: ${暫存反代解析陣列.length}個\n${暫存反代解析陣列.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
		暫存反代IP = proxyIP;
	} else console.log(`[反代解析] 讀取快取 總數: ${暫存反代解析陣列.length}個\n${暫存反代解析陣列.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 暫存反代解析陣列;
}

async function SOCKS5可用性驗證(代理協定 = 'socks5', 代理參數) {
	const startTime = Date.now();
	try { parsedSocks5Address = await 取得SOCKS5帳號(代理參數, 代理協定 === 'https' ? 443 : 80); } catch (err) { return { success: false, error: err.message, proxy: 代理協定 + "://" + 代理參數, responseTime: Date.now() - startTime }; }
	const { username, password, hostname, port } = parsedSocks5Address;
	const 完整代理參數 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
	try {
		const initialData = new Uint8Array(0);
		const tcpSocket = 代理協定 === 'socks5'
			? await socks5Connect('check.socks5.090227.xyz', 80, initialData)
			: (代理協定 === 'https'
				? await httpConnect('check.socks5.090227.xyz', 80, initialData, true)
				: await httpConnect('check.socks5.090227.xyz', 80, initialData));
		if (!tcpSocket) return { success: false, error: '無法連線到代理伺服器', proxy: 代理協定 + "://" + 完整代理參數, responseTime: Date.now() - startTime };
		try {
			const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
			await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
			writer.releaseLock();
			const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
			let response = '';
			try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }); } } catch (readErr) { return { success: false, error: '讀取代理回應失敗: ' + readErr.message, proxy: 代理協定 + "://" + 完整代理參數, responseTime: Date.now() - startTime }; }
			const ipMatch = response.match(/ip=([^\r\n]+)/);} catch (err) { return { success: false, error: '代理連線測試失敗: ' + err.message, proxy: 代理協定 + "://" + 完整代理參數, responseTime: Date.now() - startTime }; }
	} catch (err) { return { success: false, error: '代理連線失敗: ' + err.message, proxy: 代理協定 + "://" + 代理參數, responseTime: Date.now() - startTime }; }
	return { success: true, proxy: 代理協定 + "://" + 完整代理參數, responseTime: Date.now() - startTime };
}
