// Maintained & updated by soroushse7o — https://github.com/soroushse7o/
// Original project: edgetunnel by cmliu — https://github.com/cmliu/edgetunnel
//
// Install Wizard for edgetunnel — single-file Cloudflare Worker (UI + stateless API).
// It creates a KV namespace, binds it as `KV`, sets ADMIN / KEY automatically and deploys the script.
// Nothing is stored: the token is used only for the requests made while installing.
// ویزارد نصب edgetunnel — یک Worker تک‌فایل. ساخت KV، بایند به نام KV، ست‌کردن ADMIN و KEY و استقرار، همه خودکار.

const API = "https://api.cloudflare.com/client/v4";

// Script that gets installed. Change this URL if you want the wizard to install your own fork.
// آدرس اسکریپتی که نصب می‌شود. برای نصب فورک خودتان همین آدرس را عوض کنید.
const SOURCE_URLS = [
  "https://raw.githubusercontent.com/soroushse7o/edgetunnel/refs/heads/feat/i18n-en-fa/_worker.js",
];

// Name of the KV binding the script expects (env.KV).
const KV_BINDING = "KV";

// Placement Hint choices shown in the wizard: [value, English label, Persian label].
// Format is {provider}:{cloud-region}. "" = no hint (Cloudflare default).
// گزینه‌های Placement Hint در ویزارد: [مقدار، برچسب انگلیسی، برچسب فارسی]. مقدار خالی = بدون Hint (پیش‌فرض کلادفلر).
const PLACEMENTS = [
  ["", "Default (no hint)", "پیش‌فرض (بدون Hint)"],
  ["azure:italynorth", "Italy — Azure Italy North", "ایتالیا — Azure Italy North"],
  ["gcp:europe-west8", "Italy — GCP Milan", "ایتالیا — GCP میلان"],
  ["azure:westeurope", "Netherlands — Azure West Europe", "هلند — Azure West Europe"],
  ["azure:germanywestcentral", "Germany — Azure Germany West Central", "آلمان — Azure Germany West Central"],
  ["aws:eu-central-1", "Germany — AWS Frankfurt", "آلمان — AWS فرانکفورت"],
  ["azure:swedencentral", "Sweden — Azure Sweden Central", "سوئد — Azure Sweden Central"],
  ["azure:francecentral", "France — Azure France Central", "فرانسه — Azure France Central"],
  ["aws:eu-west-1", "Ireland — AWS Ireland", "ایرلند — AWS ایرلند"],
];
const PLACEMENT_VALUES = PLACEMENTS.map((x) => x[0]);

class ApiError extends Error {
  constructor(code, status = 400, detail = "") {
    super(code);
    this.code = code;
    this.status = status;
    this.detail = String(detail || "").slice(0, 300);
  }
}

// ---------- helpers ----------

const LOWER = "abcdefghijklmnopqrstuvwxyz0123456789";
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function randomString(length, alphabet) {
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (b < limit && out.length < length) out += alphabet[b % alphabet.length];
    }
  }
  return out;
}

// Neutral random project/worker name.
const NAME_A = ["amber", "blue", "calm", "dawn", "ember", "frost", "gold", "jade", "lunar", "maple", "north", "olive", "pearl", "quiet", "river", "silver", "terra", "violet", "willow", "zen"];
const NAME_B = ["app", "site", "note", "page", "board", "desk", "lab", "hub", "space", "studio", "shop", "blog", "docs", "tool"];
function pick(list) {
  return list[crypto.getRandomValues(new Uint32Array(1))[0] % list.length];
}
function neutralName() {
  return `${pick(NAME_A)}-${pick(NAME_B)}-${randomString(6, LOWER)}`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

async function cf(path, token, { method = "GET", json: body, form } = {}) {
  const headers = { authorization: "Bearer " + token };
  let payload;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  } else if (form) {
    payload = form;
  }
  let res, data;
  try {
    res = await fetch(API + path, { method, headers, body: payload, signal: AbortSignal.timeout(30000) });
    data = await res.json();
  } catch {
    throw new ApiError("NETWORK", 502);
  }
  if (res.ok && data.success) return data.result;
  const first = (data.errors && data.errors[0]) || {};
  const code =
    res.status === 401 ? "TOKEN_INVALID" :
    res.status === 403 ? "PERMISSION" :
    res.status === 429 ? "RATE_LIMIT" : "CF_ERROR";
  throw new ApiError(code, res.status, first.message);
}

async function fetchSource(urls) {
  for (const url of urls) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
      if (!res.ok) continue;
      const text = await res.text();
      if (text.length > 1000 && !text.trimStart().startsWith("<")) return text;
    } catch {
      /* try next source */
    }
  }
  throw new ApiError("SOURCE_FETCH", 502);
}

// ---------- KV ----------

async function createKV(token, accountId, title) {
  const ns = await cf(`/accounts/${accountId}/storage/kv/namespaces`, token, { method: "POST", json: { title } });
  if (!ns || !ns.id) throw new ApiError("CF_ERROR", 502, "KV namespace was not created");
  return ns.id;
}

async function deleteKV(token, accountId, id) {
  try {
    await cf(`/accounts/${accountId}/storage/kv/namespaces/${id}`, token, { method: "DELETE" });
  } catch {
    /* best-effort cleanup */
  }
}

// ---------- deploy ----------

async function uploadWorker(token, accountId, name, code, kvId, vars, placement) {
  const form = new FormData();
  form.append(
    "metadata",
    new Blob(
      [JSON.stringify({
        main_module: "worker.js",
        compatibility_date: "2025-01-01",
        bindings: [
          ...Object.entries(vars).map(([k, v]) => ({ type: "plain_text", name: k, text: v })),
          { type: "kv_namespace", name: KV_BINDING, namespace_id: kvId },
        ],
        ...(placement ? { placement: { region: placement } } : {}),
      })],
      { type: "application/json" }
    ),
    "metadata.json"
  );
  form.append("worker.js", new Blob([code], { type: "application/javascript+module" }), "worker.js");
  await cf(`/accounts/${accountId}/workers/scripts/${name}`, token, { method: "PUT", form });
}

async function deployWorkers(token, accountId, name, code, kvId, vars, placement) {
  let applied = placement;
  try {
    await uploadWorker(token, accountId, name, code, kvId, vars, placement);
  } catch (e) {
    // A rejected placement hint must not break the install: retry once without it.
    if (placement && e instanceof ApiError && e.code === "CF_ERROR" && /placement/i.test(e.detail)) {
      applied = "";
      await uploadWorker(token, accountId, name, code, kvId, vars, "");
    } else {
      throw e;
    }
  }

  // account-level workers.dev subdomain (create one if the account has none)
  let sub = "";
  try {
    sub = (await cf(`/accounts/${accountId}/workers/subdomain`, token)).subdomain || "";
  } catch (e) {
    if (!(e instanceof ApiError) || (e.status !== 404 && e.code !== "CF_ERROR")) throw e;
  }
  for (let i = 0; !sub && i < 3; i++) {
    const candidate = "w" + randomString(10, LOWER);
    try {
      sub = (await cf(`/accounts/${accountId}/workers/subdomain`, token, { method: "PUT", json: { subdomain: candidate } })).subdomain;
    } catch (e) {
      if (!(e instanceof ApiError) || e.code !== "CF_ERROR" || i === 2) throw e;
    }
  }
  await cf(`/accounts/${accountId}/workers/scripts/${name}/subdomain`, token, {
    method: "POST",
    json: { enabled: true, previews_enabled: false },
  });
  return { host: `${name}.${sub}.workers.dev`, placement: applied };
}

async function deployPages(token, accountId, name, code, kvId, vars, placement) {
  const envVars = Object.fromEntries(Object.entries(vars).map(([k, v]) => [k, { type: "plain_text", value: v }]));
  const kvBinding = { [KV_BINDING]: { namespace_id: kvId } };
  const project = await cf(`/accounts/${accountId}/pages/projects`, token, {
    method: "POST",
    json: {
      name,
      production_branch: "main",
      deployment_configs: {
        production: { env_vars: envVars, kv_namespaces: kvBinding },
        preview: { kv_namespaces: kvBinding },
      },
    },
  });
  let applied = "";
  try {
    // Best-effort: placement hint for Pages Functions. A rejection here must not break the install.
    if (placement) {
      try {
        await cf(`/accounts/${accountId}/pages/projects/${name}`, token, {
          method: "PATCH",
          json: { deployment_configs: {
            production: { placement: { region: placement }, env_vars: envVars, kv_namespaces: kvBinding },
            preview: { placement: { region: placement }, kv_namespaces: kvBinding },
          } },
        });
        applied = placement;
      } catch {
        /* placement is an optimization; continue without it */
      }
    }
    const form = new FormData();
    form.append("manifest", "{}");
    form.append("branch", "main");
    form.append("_worker.js", new Blob([code], { type: "application/javascript" }), "_worker.js");
    await cf(`/accounts/${accountId}/pages/projects/${name}/deployments`, token, { method: "POST", form });
  } catch (e) {
    try { await cf(`/accounts/${accountId}/pages/projects/${name}`, token, { method: "DELETE" }); } catch { /* cleanup */ }
    throw e;
  }
  return { host: (project && project.subdomain) || `${name}.pages.dev`, placement: applied };
}

// ---------- install flow ----------

async function install(token, method, adminPassword, placement) {
  try {
    const verified = await cf("/user/tokens/verify", token);
    if (!verified || verified.status !== "active") throw new ApiError("TOKEN_INVALID", 401);
  } catch (e) {
    if (e instanceof ApiError && [400, 401, 403].includes(e.status)) throw new ApiError("TOKEN_INVALID", 401);
    throw e;
  }

  const accounts = await cf("/accounts", token);
  if (!accounts || !accounts.length) throw new ApiError("NO_ACCOUNT", 404);
  const accountId = accounts[0].id;

  const code = await fetchSource(SOURCE_URLS);

  // credentials: generated per install, never stored
  const admin = adminPassword || randomString(16, ALNUM);
  const key = randomString(16, ALNUM);
  const name = neutralName();
  const vars = { ADMIN: admin, KEY: key };

  // 1) create the KV namespace  2) bind it as KV  3) deploy with ADMIN / KEY
  const kvId = await createKV(token, accountId, `${name}-kv`);
  let deployed;
  try {
    deployed = method === "pages"
      ? await deployPages(token, accountId, name, code, kvId, vars, placement)
      : await deployWorkers(token, accountId, name, code, kvId, vars, placement);
  } catch (e) {
    await deleteKV(token, accountId, kvId); // do not leave an orphan namespace behind
    throw e;
  }

  const host = deployed.host;
  return {
    panel: `https://${host}/admin`,
    sub: `https://${host}/${key}`,
    placement: deployed.placement,
    admin,
    key,
    name,
  };
}

async function handleInstall(request, url) {
  if (request.method !== "POST") return json({ ok: false, code: "BAD_REQUEST" }, 405);
  const origin = request.headers.get("origin");
  if (origin && origin !== url.origin) return json({ ok: false, code: "FORBIDDEN" }, 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, code: "BAD_REQUEST" }, 400);
  }
  const token = String(body.token || "").trim();
  if (!token) return json({ ok: false, code: "TOKEN_EMPTY" }, 400);
  if (!/^[A-Za-z0-9_-]{20,120}$/.test(token)) return json({ ok: false, code: "TOKEN_INVALID" }, 400);
  if (!["workers", "pages"].includes(body.method)) return json({ ok: false, code: "BAD_REQUEST" }, 400);

  const adminPassword = String(body.admin || "").trim();
  if (adminPassword && !/^[\x21-\x7e]{6,64}$/.test(adminPassword)) return json({ ok: false, code: "PASSWORD_INVALID" }, 400);

  const placement = String(body.placement || "");
  if (!PLACEMENT_VALUES.includes(placement)) return json({ ok: false, code: "BAD_REQUEST" }, 400);

  try {
    return json({ ok: true, ...(await install(token, body.method, adminPassword, placement)) });
  } catch (e) {
    if (e instanceof ApiError) return json({ ok: false, code: e.code, detail: e.detail }, e.status);
    return json({ ok: false, code: "UNKNOWN" }, 500);
  }
}

// ---------- page ----------

const HTML = `<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>edgetunnel Install Wizard</title>
<style>
:root{--bg1:#0a1633;--bg2:#12306b;--card:#070f24;--line:#2d4a8f;--acc:#5b8cff;--fg:#e8eefc;--mute:#8fa3cc;--ok:#3ddc97;--err:#ff6b6b;--warn:#ffc857}
*{box-sizing:border-box}
@font-face{font-family:V;src:local("Vazirmatn"),local("Vazirmatn UI")}
html,body{margin:0;min-height:100%}
body{background:linear-gradient(180deg,var(--bg1),var(--bg2));color:var(--fg);font:16px/1.9 V,Tahoma,system-ui,-apple-system,"Segoe UI",sans-serif;padding:max(16px,env(safe-area-inset-top)) 16px max(24px,env(safe-area-inset-bottom))}
main{max-width:560px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
h1{font-size:1.5rem;margin:0}
.lang{background:none;border:1px solid var(--line);color:var(--fg);border-radius:999px;padding:4px 14px;font:inherit;cursor:pointer}
ol{padding-inline-start:1.4em;margin:12px 0 24px}
li{margin:6px 0}
a{color:var(--acc);cursor:pointer;text-decoration:none}
.field{position:relative;display:flex;align-items:center;background:var(--card);border-radius:18px;padding:0 14px;margin-bottom:14px;border:1px solid transparent}
.field:focus-within{border-color:var(--line)}
.field svg{flex:none;width:22px;height:22px;stroke:var(--mute);fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.field input,.field select{flex:1;min-width:0;background:none;border:0;outline:0;color:var(--fg);font:inherit;padding:16px 10px}
.field input[dir=ltr]{text-align:start}
.field select{appearance:none;-webkit-appearance:none;cursor:pointer}
.field select option{background:#0b1b3a;color:var(--fg)}
.eye{background:none;border:0;padding:6px;cursor:pointer;display:flex}
.install{display:block;margin:10px auto 22px;background:transparent;color:var(--acc);border:2px solid var(--acc);border-radius:16px;padding:10px 34px;font:inherit;font-weight:700;cursor:pointer}
.install:disabled{opacity:.5;cursor:default}
.status{background:var(--card);border-radius:18px;padding:16px 18px;min-height:96px}
.st{display:flex;align-items:center;gap:12px;font-family:ui-monospace,Menlo,Consolas,monospace}
.dots{display:flex;gap:5px;direction:ltr}
.dots i{width:14px;height:14px;border-radius:50%;background:var(--acc);opacity:.45}
.dots i:nth-child(2){opacity:.75}.dots i:nth-child(3){opacity:1}
.deploying .dots i{background:var(--warn);animation:p 1s infinite}
.deploying .dots i:nth-child(2){animation-delay:.2s}.deploying .dots i:nth-child(3){animation-delay:.4s}
.success .dots i{background:var(--ok);opacity:1}
.error .dots i{background:var(--err);opacity:1}
@keyframes p{50%{opacity:.2}}
.msg{margin-top:10px;color:var(--mute);font-size:.92rem;word-break:break-word}
.error .msg{color:var(--err)}
.res{margin-top:12px;font-size:.92rem}
.res .lbl{color:var(--mute)}
.res code{display:block;direction:ltr;text-align:left;background:#0d1a38;border-radius:10px;padding:8px 10px;margin:4px 0 10px;word-break:break-all;font-size:.85rem}
.copy{background:var(--acc);color:#fff;border:0;border-radius:10px;padding:4px 14px;font:inherit;cursor:pointer}
.links{margin:0 0 4px;font-size:.92rem}
.note{margin-top:16px;text-align:center;color:var(--mute);font-size:.82rem}
.hidden{display:none}
</style>
</head>
<body>
<main>
<header><h1 id="title"></h1><button class="lang" id="lang" type="button"></button></header>
<p class="links"><a href="https://github.com/soroushse7o/" target="_blank" rel="noopener noreferrer" id="tgh1"></a> · <a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener noreferrer" id="tgh2"></a></p>
<ol id="steps"></ol>
<form id="f" autocomplete="off">
<label class="field">
<svg viewBox="0 0 24 24"><circle cx="7.5" cy="12" r="3.5"/><path d="M11 12h10M17 12v3M20 12v2"/></svg>
<input id="token" type="password" dir="ltr" spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off">
<button class="eye" id="eye" type="button"><svg viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button>
</label>
<label class="field"><svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
<input id="admin" type="text" dir="ltr" spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off" maxlength="64"></label>
<label class="field"><svg viewBox="0 0 24 24"><path d="M6 21v-7M6 14l-3-3M6 14l3-3M18 3v7M18 10l-3 3M18 10l3 3M12 4v16"/></svg>
<select id="method"><option value="workers">Cloudflare Workers</option><option value="pages">Cloudflare Pages</option></select></label>
<label class="field"><svg viewBox="0 0 24 24"><path d="M12 21s-7-6.2-7-11.5a7 7 0 0 1 14 0C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/></svg>
<select id="placement"></select></label>
<button class="install" id="go" type="submit"></button>
</form>
<div class="status" id="status">
<div class="st"><span class="dots"><i></i><i></i><i></i></span><span id="stext"></span></div>
<div class="msg hidden" id="smsg"></div>
<div class="res hidden" id="res">
<div class="lbl" id="lpanel"></div><code id="panel"></code>
<div class="lbl" id="ladmin"></div><code id="adminOut"></code>
<div class="lbl" id="lsub"></div><code id="sub"></code>
<div class="lbl" id="lplc"></div><code id="plcOut"></code>
<button class="copy" id="copy" type="button"></button>
</div>
</div>
<p class="note" id="note"></p>
<p class="note"><a href="https://github.com/soroushse7o/" target="_blank" rel="noopener noreferrer" id="gh1"></a> · <a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener noreferrer" id="gh2"></a></p>
</main>
<script>
(function(){
var TOKEN_URL='https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22page%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22user_details%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=edgetunnel-wizard';
var PL=__PLACEMENTS__;
var SIGNUP_URL='https://dash.cloudflare.com/sign-up';
var L={
en:{title:"edgetunnel Install Wizard",lang:"فارسی",
s1:'<a data-l="signup">Sign up</a> for a Cloudflare account and verify it.',
s2:'<a data-l="token">Create a token</a>, press <b>Continue to summary</b>, then <b>Create Token</b> and copy it.',
s3:"Paste it here, optionally set an admin password (random if empty), choose the installation method and placement, then install.",
s4:"One click creates a <b>KV namespace</b>, binds it as <b>KV</b>, sets <b>ADMIN</b> and <b>KEY</b>, and deploys edgetunnel. You get the admin panel link and password. Nothing is saved on any server.",
ph:"Cloudflare API Token",phadmin:"Admin password (optional, random if empty)",eye:"Show / hide token",install:"Install",
standby:"Standby",deploying:"Deploying...",success:"Success",error:"Error",
panel:"Admin panel",admin:"Admin password (ADMIN)",sub:"Quick subscription (KEY)",plc:"Placement Hint",plcv:"Placement",plcnone:"Default (no hint)",plcfail:"Default (hint was not accepted)",copy:"Copy",copied:"Copied",
note:"Nothing is stored. Your token is only used for this install, directly against Cloudflare.",
gh1:"GitHub page",gh2:"edgetunnel on GitHub",
e_TOKEN_EMPTY:"Enter your Cloudflare API token.",
e_TOKEN_INVALID:"The token is invalid or expired. Create a new one with the link in step 2.",
e_PERMISSION:"The token does not have enough permissions (Workers, KV and Pages must be Edit). Create it with the link in step 2.",
e_NETWORK:"Network error: could not reach Cloudflare. Try again.",
e_RATE_LIMIT:"Too many requests. Wait a moment and try again.",
e_NO_ACCOUNT:"No Cloudflare account was found for this token.",
e_SOURCE_FETCH:"Could not download the script from GitHub. Try again later.",
e_PASSWORD_INVALID:"The admin password must be 6 to 64 visible characters without spaces.",
e_CF_ERROR:"Cloudflare returned an error.",
e_BAD_REQUEST:"Invalid request.",e_FORBIDDEN:"Invalid request.",e_UNKNOWN:"Unknown error."},
fa:{title:"ویزارد نصب edgetunnel",lang:"English",
s1:'<a data-l="signup">ثبت‌نام</a> در Cloudflare و تأیید حساب.',
s2:'<a data-l="token">ساخت توکن</a>؛ روی <b>Continue to summary</b> و سپس <b>Create Token</b> بزنید و توکن را کپی کنید.',
s3:"توکن را اینجا بچسبانید، در صورت تمایل رمز مدیریت را تعیین کنید (خالی = رندوم)، روش نصب و Placement را انتخاب کنید و نصب را بزنید.",
s4:"با یک کلیک، یک <b>KV namespace</b> ساخته و با نام <b>KV</b> بایند می‌شود، متغیرهای <b>ADMIN</b> و <b>KEY</b> ست می‌شوند و edgetunnel نصب می‌شود. لینک پنل مدیریت و رمز را می‌گیرید. هیچ اطلاعاتی روی هیچ سروری ذخیره نمی‌شود.",
ph:"توکن API کلادفلر",phadmin:"رمز مدیریت (اختیاری، خالی = رندوم)",eye:"نمایش / مخفی کردن توکن",install:"نصب",
standby:"آماده‌باش",deploying:"در حال نصب...",success:"موفق",error:"خطا",
panel:"پنل مدیریت",admin:"رمز مدیریت (ADMIN)",sub:"اشتراک سریع (KEY)",plc:"Placement Hint",plcv:"Placement",plcnone:"پیش‌فرض (بدون Hint)",plcfail:"پیش‌فرض (Hint پذیرفته نشد)",copy:"کپی",copied:"کپی شد",
note:"هیچ داده‌ای ذخیره نمی‌شود. توکن فقط برای همین نصب و مستقیم با کلادفلر استفاده می‌شود.",
gh1:"پیج گیت‌هاب",gh2:"edgetunnel در گیت‌هاب",
e_TOKEN_EMPTY:"توکن API کلادفلر را وارد کنید.",
e_TOKEN_INVALID:"توکن نامعتبر یا منقضی است. با لینک مرحله ۲ یک توکن جدید بسازید.",
e_PERMISSION:"دسترسی توکن کافی نیست (Workers، KV و Pages باید Edit باشند). آن را با لینک مرحله ۲ بسازید.",
e_NETWORK:"خطای شبکه: ارتباط با کلادفلر برقرار نشد. دوباره تلاش کنید.",
e_RATE_LIMIT:"تعداد درخواست‌ها زیاد است. کمی صبر کنید و دوباره تلاش کنید.",
e_NO_ACCOUNT:"حسابی برای این توکن پیدا نشد.",
e_SOURCE_FETCH:"دریافت اسکریپت از GitHub ناموفق بود. بعداً دوباره تلاش کنید.",
e_PASSWORD_INVALID:"رمز مدیریت باید ۶ تا ۶۴ کاراکتر قابل‌نمایش و بدون فاصله باشد.",
e_CF_ERROR:"کلادفلر خطا برگرداند.",
e_BAD_REQUEST:"درخواست نامعتبر است.",e_FORBIDDEN:"درخواست نامعتبر است.",e_UNKNOWN:"خطای ناشناخته."}
};
var $=function(i){return document.getElementById(i)};
var lang="en";
var st="standby",errRes=null,result=null,busy=false;
function t(k){return L[lang][k]}
function errText(r){var m=t("e_"+r.code)||t("e_UNKNOWN");return r.detail?m+" ("+r.detail+")":m}
function render(){
 var h=document.documentElement;h.lang=lang;h.dir=lang==="fa"?"rtl":"ltr";
 $("title").textContent=t("title");$("lang").textContent=t("lang");
 $("steps").innerHTML="<li>"+t("s1")+"</li><li>"+t("s2")+"</li><li>"+t("s3")+"</li><li>"+t("s4")+"</li>";
 var as=$("steps").querySelectorAll("a");
 for(var i=0;i<as.length;i++){as[i].href=as[i].getAttribute("data-l")==="token"?TOKEN_URL:SIGNUP_URL;as[i].target="_blank";as[i].rel="noopener noreferrer"}
 var sel=$("placement"),cur=sel.value;sel.innerHTML="";
 for(var j=0;j<PL.length;j++){var o=document.createElement("option");o.value=PL[j][0];o.textContent=t("plcv")+": "+PL[j][lang==="fa"?2:1];sel.appendChild(o)}
 sel.value=cur;
 $("token").placeholder=t("ph");$("admin").placeholder=t("phadmin");$("eye").setAttribute("aria-label",t("eye"));
 $("go").textContent=t("install");$("note").textContent=t("note");
 $("gh1").textContent=t("gh1");$("gh2").textContent=t("gh2");$("tgh1").textContent=t("gh1");$("tgh2").textContent=t("gh2");
 $("status").className="status "+st;$("stext").textContent=t(st);
 var m=$("smsg");
 if(st==="error"&&errRes){m.textContent=errText(errRes);m.classList.remove("hidden")}else m.classList.add("hidden");
 var r=$("res");
 if(st==="success"&&result){
  r.classList.remove("hidden");
  $("lpanel").textContent=t("panel");$("panel").textContent=result.panel;
  $("ladmin").textContent=t("admin");$("adminOut").textContent=result.admin;
  $("lsub").textContent=t("sub");$("sub").textContent=result.sub;
  $("lplc").textContent=t("plc");$("plcOut").textContent=result.placement||(result.requested?t("plcfail"):t("plcnone"));
  $("copy").textContent=t("copy");
 }else r.classList.add("hidden");
}
$("lang").onclick=function(){lang=lang==="fa"?"en":"fa";render()};
$("eye").onclick=function(){var i=$("token");i.type=i.type==="password"?"text":"password"};
$("copy").onclick=function(){
 if(!result)return;
 navigator.clipboard.writeText(result.panel+"\\n"+result.admin+"\\n"+result.sub).then(function(){
  $("copy").textContent=t("copied");setTimeout(function(){$("copy").textContent=t("copy")},1500)});
};
$("f").onsubmit=function(e){
 e.preventDefault();
 if(busy)return;
 var token=$("token").value.trim();
 if(!token){st="error";errRes={code:"TOKEN_EMPTY"};render();return}
 busy=true;$("go").disabled=true;st="deploying";errRes=null;result=null;render();
 fetch("/api/install",{method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({token:token,method:$("method").value,admin:$("admin").value.trim(),placement:$("placement").value})})
 .then(function(r){return r.json()})
 .then(function(d){
  if(d.ok){st="success";result={panel:d.panel,admin:d.admin,sub:d.sub,placement:d.placement,requested:!!$("placement").value}}
  else{st="error";errRes=d}
 })
 .catch(function(){st="error";errRes={code:"NETWORK"}})
 .then(function(){busy=false;$("go").disabled=false;render()});
};
render();
})();
</script>
</body>
</html>`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/api/install") return handleInstall(request, url);
    if (url.pathname === "/") {
      return new Response(HTML.replace("__PLACEMENTS__", JSON.stringify(PLACEMENTS)), {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "content-security-policy":
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        },
      });
    }
    return new Response("Not found", { status: 404 });
  },
};
