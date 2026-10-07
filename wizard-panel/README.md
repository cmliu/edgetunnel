# edgetunnel Install Wizard

**Languages / زبان‌ها:** [English](#english) | [فارسی](#persian)

> English first, Persian (فارسی) below. / ابتدا انگلیسی، سپس فارسی در ادامه.

Maintained & updated by [soroushse7o](https://github.com/soroushse7o/) · Original project: [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)

---

<a id="english"></a>

## English

A small, single-file Cloudflare Worker that installs
[edgetunnel](https://github.com/cmliu/edgetunnel) on your own Cloudflare account in one click.
You paste an API token, pick the installation method and an optional placement region, press **Install**,
and the wizard does the rest: it creates a **KV namespace**, binds it as **`KV`**, sets the required
**variables** (`ADMIN` and `KEY`) and deploys the script. You get the admin panel link and password.

### Features

- Four-step guided page, bilingual with RTL support. **English is the default**, Persian is the second language.
- Install as **Cloudflare Workers** or **Cloudflare Pages**.
- **Automatic KV setup:** creates a namespace and binds it with the variable name `KV` (the name edgetunnel expects).
- **Automatic variables:**
  - `ADMIN`: admin panel password. Random 16 characters, or your own (6 to 64 visible characters, no spaces).
  - `KEY`: random 16-character key, used as the quick-subscription path (`/<KEY>`).
- **Placement Hint selector** with Europe-focused regions (see the table below).
- Clean rollback: if the install fails after the KV namespace was created, the namespace (and, for Pages, the half-created project) is deleted again.
- Status bar: Standby, Deploying, Success, Error, with clear error messages (invalid token, missing permissions, network error, rate limit, and more).
- No dependencies, no build step, no database.

### What the wizard does

1. Verifies the API token and picks the first account it can access.
2. Downloads the edgetunnel script from the URL list at the top of the file.
3. Generates the `ADMIN` password (unless you typed one) and the `KEY`.
4. Creates a KV namespace named `<project-name>-kv`.
5. Deploys the script with the `ADMIN` and `KEY` variables, the `KV` binding and the chosen placement hint:
   - **Workers:** uploads the module, enables the `workers.dev` route (and creates the account's `workers.dev` subdomain if it has none).
   - **Pages:** creates the project with the variables and the KV binding (production and preview), then uploads the script as `_worker.js`.
6. Shows the result:

| Output | Example |
| :--- | :--- |
| Admin panel | `https://<name>.<subdomain>.workers.dev/admin` (or `.pages.dev`) |
| Admin password (`ADMIN`) | the random or custom password |
| Quick subscription (`KEY`) | `https://<name>.<subdomain>.workers.dev/<KEY>` |
| Placement Hint | the applied region, or "Default" |

> `UUID` is intentionally **not** set. Setting it would lock the UUID, and the panel could no longer change it. The panel generates its own UUID.

### Placement Hint

Placement Hints run your Worker in the Cloudflare data center with the lowest latency to the cloud region you choose.
The format is `{provider}:{region}`. The default option sends no hint.

| Option | Value |
| :--- | :--- |
| Default (no hint) | *(none)* |
| Italy, Azure Italy North | `azure:italynorth` |
| Italy, GCP Milan | `gcp:europe-west8` |
| Netherlands, Azure West Europe | `azure:westeurope` |
| Netherlands, GCP Eemshaven | `gcp:europe-west4` |
| Germany, Azure Germany West Central | `azure:germanywestcentral` |
| Germany, AWS Frankfurt | `aws:eu-central-1` |
| Finland, GCP Finland | `gcp:europe-north1` |
| Sweden, Azure Sweden Central | `azure:swedencentral` |
| France, Azure France Central | `azure:francecentral` |
| Ireland, AWS Ireland | `aws:eu-west-1` |
| United Kingdom, GCP London | `gcp:europe-west2` |

- The server only accepts values from this list (`PLACEMENTS` at the top of the file). Add or remove entries there.
- Workers: if Cloudflare rejects the hint, the wizard retries the upload once **without** it, and the result shows "Default (hint was not accepted)".
- Pages: the hint is applied best-effort. If the API rejects it, the install still succeeds.

### Privacy

- The wizard stores nothing: no KV, no database and no logging of its own.
- Your token is used only for the requests made during that install, directly against the Cloudflare API, and is never returned to the page.
- The `ADMIN` password and `KEY` are shown once on screen and live only in the variables of the Worker/Pages project that was created on your account. They are stored as plain-text variables, so you can read them later in the Cloudflare dashboard.
- Deploy the wizard on **your own** account if you want full control. Never paste a token into a wizard you do not trust.

### Files

| File | Role |
| :--- | :--- |
| `_worker.js` | The whole wizard (page + API). This is the file to deploy. (Rename `edgetunnel_wizard_worker.js` to `_worker.js` for Pages.) |
| `README.md` | This document. |

### Deploy the wizard

**Option A: Cloudflare Pages with Git (recommended)**

1. Cloudflare dashboard, Workers & Pages, Create, Pages, Connect to Git, choose this repository.
2. Framework preset: `None`. Build command: empty. Build output directory: `/`.
3. Save and Deploy. Open the `*.pages.dev` address.

**Option B: Cloudflare Workers (copy and paste)**

1. Workers & Pages, Create, Create Worker, Deploy the default, then Edit code.
2. Replace everything with the content of the wizard file, then Deploy.

### Usage

1. Sign up for a Cloudflare account and verify it.
2. Open **Create a token** on the wizard page, then **Continue to summary**, **Create Token**, and copy the token.
3. Paste the token. Optionally type an admin password (leave it empty for a random one).
4. Choose Workers or Pages, choose a placement, and press **Install**.
5. When the status turns to **Success**, open the **Admin panel** link and log in with the **Admin password**.

### API token permissions

The token link on the page pre-selects: Workers Scripts (edit), Workers KV Storage (edit), Pages (edit), DNS (edit), User Details (read).
The wizard uses Workers Scripts, Workers KV Storage, Pages and User Details. DNS is selected for convenience but is not used yet.
If you create the token by hand, give it at least the first three (edit) and User Details (read).

### Troubleshooting

| Message | What to do |
| :--- | :--- |
| Token invalid or expired | Create a new token with the link in step 2. |
| Not enough permissions | The token needs Workers Scripts, Workers KV Storage and Pages set to **Edit**. |
| Could not download the script | GitHub was unreachable. Try again, or change `SOURCE_URLS`. |
| Password invalid | Use 6 to 64 visible characters without spaces, or leave the field empty. |
| Cloudflare returned an error | The detail text in brackets is Cloudflare's own message. |

### Notes

- The installed script is downloaded from `SOURCE_URLS` at the top of the file. It points to the upstream `cmliu/edgetunnel` by default. Change the URL to use your own fork or a fixed commit.
- `KV_BINDING` (default `KV`) must match the binding name used by the installed script.
- The panel is at `/admin`. Opening the root address shows the script's disguise page (the `URL` variable, `nginx` by default).
- Workers mode: for a more reliable connection, bind a custom domain as described in the main project. Pages mode works with a custom CNAME domain as well.
- If the token can access several accounts, the first account is used.
- You can delete the token on the Cloudflare dashboard after installation.

### Credits

- edgetunnel: original project by [cmliu](https://github.com/cmliu/edgetunnel)
- Wizard, localization and updates: [soroushse7o](https://github.com/soroushse7o/)

---

<a id="persian"></a>

<div dir="rtl">

## فارسی

یک Worker کوچک و تک‌فایل برای کلادفلر که [edgetunnel](https://github.com/cmliu/edgetunnel) را با یک کلیک روی حساب کلادفلر خودتان نصب می‌کند.
توکن API را می‌چسبانید، روش نصب و (در صورت تمایل) ریجن Placement را انتخاب می‌کنید و **نصب** را می‌زنید؛ بقیه‌ی کارها را wizard انجام می‌دهد:
یک **KV namespace** می‌سازد، آن را با نام **`KV`** بایند می‌کند، **متغیرهای** لازم (`ADMIN` و `KEY`) را تنظیم می‌کند و اسکریپت را دپلوی می‌کند.
در پایان لینک پنل مدیریت و رمز آن را می‌گیرید.

### امکانات

- صفحه‌ی چهار مرحله‌ای، دوزبانه با پشتیبانی از راست‌به‌چپ. **زبان پیش‌فرض انگلیسی** است و فارسی زبان دوم.
- نصب به‌صورت **Cloudflare Workers** یا **Cloudflare Pages**.
- **راه‌اندازی خودکار KV:** یک namespace می‌سازد و با نام متغیر `KV` بایند می‌کند (همان نامی که edgetunnel انتظار دارد).
- **متغیرهای خودکار:**
  - `ADMIN`: رمز پنل مدیریت. ۱۶ کاراکتر تصادفی، یا رمز دلخواه شما (۶ تا ۶۴ کاراکتر قابل‌نمایش و بدون فاصله).
  - `KEY`: کلید تصادفی ۱۶ کاراکتری که مسیر اشتراک سریع (`/<KEY>`) است.
- **انتخاب Placement Hint** با ریجن‌های اروپایی (جدول پایین را ببینید).
- بازگشت تمیز: اگر نصب بعد از ساخت KV شکست بخورد، namespace ساخته‌شده (و در Pages، پروژه‌ی نیمه‌کاره) دوباره حذف می‌شود.
- نوار وضعیت: آماده‌باش، در حال نصب، موفق، خطا، همراه با پیام‌های روشن (توکن نامعتبر، دسترسی ناکافی، خطای شبکه، محدودیت نرخ و غیره).
- بدون وابستگی، بدون build و بدون دیتابیس.

### wizard چه کار می‌کند

1. توکن API را بررسی می‌کند و اولین حسابی را که به آن دسترسی دارد انتخاب می‌کند.
2. اسکریپت edgetunnel را از فهرست آدرس‌های بالای فایل دانلود می‌کند.
3. رمز `ADMIN` (اگر خودتان وارد نکرده باشید) و `KEY` را می‌سازد.
4. یک KV namespace با نام `<project-name>-kv` می‌سازد.
5. اسکریپت را با متغیرهای `ADMIN` و `KEY`، بایندینگ `KV` و Placement Hint انتخابی دپلوی می‌کند:
   - **Workers:** ماژول را آپلود می‌کند، مسیر `workers.dev` را فعال می‌کند (و اگر حساب subdomain نداشته باشد یکی می‌سازد).
   - **Pages:** پروژه را همراه با متغیرها و بایندینگ KV (production و preview) می‌سازد و سپس اسکریپت را به‌عنوان `_worker.js` آپلود می‌کند.
6. نتیجه را نشان می‌دهد:

| خروجی | نمونه |
| :--- | :--- |
| پنل مدیریت | `https://<name>.<subdomain>.workers.dev/admin` (یا `.pages.dev`) |
| رمز مدیریت (`ADMIN`) | رمز تصادفی یا دلخواه |
| اشتراک سریع (`KEY`) | `https://<name>.<subdomain>.workers.dev/<KEY>` |
| Placement Hint | ریجن اعمال‌شده، یا «پیش‌فرض» |

> متغیر `UUID` عمداً **ست نمی‌شود**. تنظیم آن، UUID را قفل می‌کند و پنل دیگر نمی‌تواند آن را تغییر دهد. پنل خودش UUID می‌سازد.

### Placement Hint

Placement Hint باعث می‌شود Worker شما در دیتاسنتر کلادفلری اجرا شود که کمترین تأخیر را تا ریجن ابری انتخابی دارد.
قالب آن `{provider}:{region}` است. گزینه‌ی پیش‌فرض هیچ Hint‌ای نمی‌فرستد.

| گزینه | مقدار |
| :--- | :--- |
| پیش‌فرض (بدون Hint) | *(بدون مقدار)* |
| ایتالیا، Azure Italy North | `azure:italynorth` |
| ایتالیا، GCP میلان | `gcp:europe-west8` |
| هلند، Azure West Europe | `azure:westeurope` |
| هلند، GCP ایمس‌هاون | `gcp:europe-west4` |
| آلمان، Azure Germany West Central | `azure:germanywestcentral` |
| آلمان، AWS فرانکفورت | `aws:eu-central-1` |
| فنلاند، GCP فنلاند | `gcp:europe-north1` |
| سوئد، Azure Sweden Central | `azure:swedencentral` |
| فرانسه، Azure France Central | `azure:francecentral` |
| ایرلند، AWS ایرلند | `aws:eu-west-1` |
| بریتانیا، GCP لندن | `gcp:europe-west2` |

- سرور فقط مقادیر همین فهرست را می‌پذیرد (`PLACEMENTS` بالای فایل). برای اضافه یا حذف گزینه همان‌جا را ویرایش کنید.
- Workers: اگر کلادفلر Hint را رد کند، wizard یک بار آپلود را **بدون** آن تکرار می‌کند و در نتیجه «پیش‌فرض (Hint پذیرفته نشد)» نشان داده می‌شود.
- Pages: اعمال Hint تلاشی (best-effort) است. اگر API آن را رد کند، نصب بازهم موفق می‌شود.

### حریم خصوصی

- خودِ wizard هیچ چیزی ذخیره نمی‌کند: نه KV، نه دیتابیس و نه لاگ.
- توکن شما فقط برای درخواست‌های همان نصب و مستقیم با API کلادفلر استفاده می‌شود و هرگز به صفحه برنمی‌گردد.
- رمز `ADMIN` و `KEY` یک‌بار روی صفحه نمایش داده می‌شوند و فقط در متغیرهای Worker یا Pages که روی حساب شما ساخته شده می‌مانند. این متغیرها به‌صورت متن ساده ذخیره می‌شوند، بنابراین بعداً می‌توانید آن‌ها را در داشبورد کلادفلر ببینید.
- اگر کنترل کامل می‌خواهید، wizard را روی حساب **خودتان** دپلوی کنید و هرگز توکن را در wizard غیرقابل‌اعتماد وارد نکنید.

### فایل‌ها

| فایل | نقش |
| :--- | :--- |
| `_worker.js` | کل wizard (صفحه و API). همین فایل دپلوی می‌شود. (برای Pages نام `edgetunnel_wizard_worker.js` را به `_worker.js` تغییر دهید.) |
| `README.md` | همین راهنما. |

### دپلوی wizard

**روش الف: Cloudflare Pages با Git (پیشنهادی)**

1. داشبورد کلادفلر، Workers & Pages، Create، Pages، Connect to Git و انتخاب همین ریپو.
2. Framework preset: ‏`None`، Build command: خالی، Build output directory: ‏`/`.
3. Save and Deploy و باز کردن آدرس `*.pages.dev`.

**روش ب: Cloudflare Workers (کپی و پیست)**

1. Workers & Pages، Create، Create Worker، Deploy و سپس Edit code.
2. همه‌ی محتوا را با محتوای فایل wizard جایگزین کنید و Deploy بزنید.

### نحوه‌ی استفاده

1. در Cloudflare ثبت‌نام کنید و حساب را تأیید کنید.
2. در صفحه‌ی wizard روی **Create a token** (ساخت توکن) بزنید، سپس **Continue to summary** و **Create Token** و توکن را کپی کنید.
3. توکن را بچسبانید. در صورت تمایل یک رمز مدیریت وارد کنید (خالی = رمز تصادفی).
4. Workers یا Pages را انتخاب کنید، یک Placement انتخاب کنید و **نصب** را بزنید.
5. وقتی وضعیت **موفق** شد، لینک **پنل مدیریت** را باز کنید و با **رمز مدیریت** وارد شوید.

### دسترسی‌های توکن

لینک ساخت توکن در صفحه این دسترسی‌ها را از قبل انتخاب می‌کند: Workers Scripts (edit)، Workers KV Storage (edit)، Pages (edit)، DNS (edit) و User Details (read).
wizard از Workers Scripts، Workers KV Storage، Pages و User Details استفاده می‌کند. دسترسی DNS برای راحتی انتخاب شده ولی فعلاً استفاده نمی‌شود.
اگر توکن را دستی می‌سازید، حداقل سه دسترسی اول (edit) و User Details (read) را بدهید.

### عیب‌یابی

| پیام | کار لازم |
| :--- | :--- |
| توکن نامعتبر یا منقضی است | با لینک مرحله‌ی ۲ توکن جدید بسازید. |
| دسترسی کافی نیست | توکن باید Workers Scripts، Workers KV Storage و Pages را روی **Edit** داشته باشد. |
| دریافت اسکریپت ناموفق بود | GitHub در دسترس نبود. دوباره تلاش کنید یا `SOURCE_URLS` را عوض کنید. |
| رمز نامعتبر است | ۶ تا ۶۴ کاراکتر قابل‌نمایش و بدون فاصله وارد کنید، یا فیلد را خالی بگذارید. |
| کلادفلر خطا برگرداند | متن داخل پرانتز پیام خود کلادفلر است. |

### نکته‌ها

- اسکریپت نصب‌شونده از `SOURCE_URLS` بالای فایل دانلود می‌شود. به‌صورت پیش‌فرض به پروژه‌ی اصلی `cmliu/edgetunnel` اشاره می‌کند. برای استفاده از فورک خودتان یا یک commit ثابت، آدرس را عوض کنید.
- مقدار `KV_BINDING` (پیش‌فرض `KV`) باید با نام بایندینگی که اسکریپت نصب‌شونده استفاده می‌کند یکی باشد.
- پنل در مسیر `/admin` است. باز کردن آدرس اصلی، صفحه‌ی مخفی‌سازی اسکریپت را نشان می‌دهد (متغیر `URL`، به‌صورت پیش‌فرض `nginx`).
- حالت Workers: برای اتصال پایدارتر، طبق پروژه‌ی اصلی یک دامنه‌ی سفارشی بایند کنید. حالت Pages هم با دامنه‌ی سفارشی CNAME کار می‌کند.
- اگر توکن به چند حساب دسترسی داشته باشد، اولین حساب استفاده می‌شود.
- بعد از نصب می‌توانید توکن را از داشبورد کلادفلر حذف کنید.

### تشکر

- edgetunnel: پروژه‌ی اصلی از [cmliu](https://github.com/cmliu/edgetunnel)
- wizard، بومی‌سازی و به‌روزرسانی‌ها: [soroushse7o](https://github.com/soroushse7o/)

</div>
