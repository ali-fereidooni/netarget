// netarget panel. Server data is inserted with textContent only (never innerHTML).
"use strict";

const LAYERS = ["registration", "nameservers", "zone", "reachability", "web"];
const LAYER_ICON = { registration: "i-id", nameservers: "i-servers", zone: "i-records", reachability: "i-radar", web: "i-window" };

const STRINGS = {
  en: {
    tagline: "Domain troubleshooting", newCheck: "New check", serverCheck: "Server check",
    nodes: "Measurement nodes", noNodes: "No node is online.",
    titleNew: "Check a domain", subNew: "Registration, name servers, DNS, reachability and the web server, in order.",
    titleResult: "Check result", titleReport: "Shared report",
    inputLabel: "Domain or URL", check: "Check", checking: "Checking…", try: "Try:",
    copyLink: "Copy link", copied: "Copied", permaLink: "Permanent link",
    introH: "What gets checked",
    layer: { registration: "Registration", nameservers: "Name servers", zone: "DNS zone", reachability: "Reachability", web: "Website load" },
    layerHelp: {
      registration: "Registered? Expiry, holds and registrar status (RDAP, WHOIS).",
      nameservers: "The delegation at the TLD, and whether each name server answers.",
      zone: "Records, mail authentication (SPF, DMARC, DKIM) and DNSSEC.",
      reachability: "Ping and TCP 80/443 from every measurement node.",
      web: "What is in front of the site, a request matrix from every node, page resources, and a rule-based verdict with fixes.",
    },
    state: { PENDING: "Waiting", RUNNING: "Checking", OK: "OK", WARN: "Warning", FAIL: "Failed", SKIPPED: "Skipped" },
    rootCause: "Root cause", evidence: "Evidence", alsoCause: "Also a cause", symptoms: "Explained by the root cause, not separate problems",
    fixes: "What to do, in order", details: "Details", raw: "Raw JSON", skipped: "Skipped",
    started: "Started", via: "via", nodesWord: "nodes", nodeWord: "node",
    traceroute: "Traceroute", runTrace: "Run traceroute", tracing: "Tracing…", traceFailed: "Traceroute failed",
    hop: "Hop", ip: "IP", asn: "ASN", operator: "Operator", raw2: "Line",
    waitFinish: "Wait for the check to finish first.",
    permaDone: "Permanent link (24 hours) copied:", reportBanner: "Shared report captured {t} — read-only, kept for 24 hours.",
    lost: "Connection lost, reconnecting…",
    footer: "Copy link keeps a result for 30 minutes; a permanent link keeps it for 24 hours.",
    themeDark: "Switch to light theme", themeLight: "Switch to dark theme",
    advanced: "Advanced: test the origin server directly",
    originLabel: "Origin server IP (optional)",
    originWarn: "Only enter the IP of an origin server you own or are allowed to test. The check connects to it directly, with the site's host name, to tell a CDN problem from an origin problem.",
    w: {
      verdict: "Website load verdict", confidence: "Confidence", symptomOf: "This is a symptom of an earlier problem — fix that first:",
      originTested: "Origin tested directly at", fingerprints: "What is in front of the site", causes: "Likely causes",
      fixes: "Fix steps", serverType: "Server type", auto: "Auto", verify: "How to verify", cannot: "What this check cannot see from outside",
      matrix: "Request matrix", request: "Request", differs: "differs", resources: "Page resources", time: "Time", issues: "Issues",
      copy: "Copy", noCDN: "none detected",
      kind: { cdn: "CDN/WAF", server: "Server", platform: "Platform" },
      level: { high: "high", medium: "medium", low: "low" },
      lik: { high: "likely", medium: "possible", low: "less likely" },
      layer: { none: "No problem found", dns: "DNS", cdn: "CDN / WAF", network: "Network", tls: "TLS / certificate", server: "Web server", application: "Application", content: "Page content" },
      issue: { failed: "failed", slow: "slow", mixed_content: "mixed content", wrong_mime: "wrong type", blocked_mime: "blocked (nosniff)", uncompressed: "uncompressed", weak_cache: "weak caching", cors: "CORS", blocked: "blocked (internal host)" },
    },
    t: {
      field: "Field", value: "Value", source: "Source", registrar: "Registrar", created: "Created", expires: "Expires", daysLeft: "Days left",
      epp: "EPP status", regNS: "Name servers (registry)", ns: "Name server", status: "Status", aa: "AA", serial: "SOA serial", rtt: "RTT ms",
      glue: "Glue", name: "Name", type: "Type", ttl: "TTL", node: "Node", sent: "Sent", recv: "Recv", loss: "Loss", rttmm: "RTT min/avg/max",
      note: "Note", url: "URL", server: "Server", total: "Total ms", final: "Final URL", result: "Result", check: "Check", start: "Start URL",
      delegation: "Delegation from {p}, asked {s}", zoneNS: "NS records inside the zone:", queried: "Queried:", email: "Mail authentication",
      dnssec: "DNSSEC", prop: "Public resolvers compared", perNode: "Per node", tls: "TLS certificate", protocol: "Protocol",
      subject: "Subject", issuer: "Issuer", valid: "Valid", match: "Hostname match", chain: "Chain", sans: "Names (SAN)", yes: "yes", no: "NO",
    },
    renderFailed: "Could not show the details.",
    err: {
      invalid_body: "The request could not be read. Reload the page and try again.",
      invalid_id: "This link is not valid.",
      rate_limited: "Too many requests — try again in a minute.",
      origin_not_allowed: "The origin IP can only be used with the website test.",
      check_running: "A check from your address is already running — wait for it to finish.",
      busy: "The server is busy — please try again shortly.",
      check_not_found: "This check was not found or has expired — please run it again.",
      still_running: "The check is still running.",
      streaming_unsupported: "Live progress is not available here.",
      too_many_streams: "Too many progress views are open from your address.",
      too_many_viewers: "Too many people are watching this check right now.",
      no_check_for_trace: "Run a check first; traceroute targets come from its results.",
      ip_not_in_check: "This IP address was not found by the check.",
      unknown_node: "Unknown measurement node.",
      agent_unreachable: "The measurement node is not reachable.",
      request_running: "Another request from your address is still running.",
      perma_rate_limited: "Too many permanent links requested — try again later.",
      perma_unavailable: "Permanent links are not available right now.",
      perma_expired: "This result is too old to make permanent — please run the check again.",
      report_too_large: "This report is too large to keep as a permanent link.",
      perma_save_failed: "The permanent link could not be saved.",
      perma_full: "Too many shared links are active right now — please try again later.",
      report_not_found: "This report was not found or has expired.",
      report_unreadable: "This stored report cannot be read.",
      no_traceroute: "Traceroute is not available on this node.",
      origin_not_ip: "The origin must be an IP address, e.g. 93.184.215.14.",
      origin_zone: "The origin IP must not include an IPv6 zone.",
      origin_private: "The origin must be a public IP address (not private, local or reserved).",
      domain_empty: "Please enter a domain name.",
      domain_ip: "IP addresses are not supported — enter a domain name such as example.com.",
      domain_local: "Local or reserved names (localhost, .local, .internal…) cannot be checked.",
      domain_invalid: "This does not look like a valid domain name.",
      domain_no_tld: "Enter a full domain including its extension, e.g. example.com.",
      domain_public_suffix: "This is a public suffix (like a TLD), not a domain you can register.",
      network: "Could not reach the server. Check your connection and try again.",
      http: "The server returned an error. Please try again.",
    },
  },
  fa: {
    tagline: "عیب‌یابی دامنه", newCheck: "بررسی جدید", serverCheck: "بررسی سرور",
    nodes: "گره‌های اندازه‌گیری", noNodes: "هیچ گره‌ای آنلاین نیست.",
    titleNew: "بررسی دامنه", subNew: "ثبت دامنه، نیم‌سرورها، DNS، دسترس‌پذیری و وب‌سرور، به ترتیب.",
    titleResult: "نتیجهٔ بررسی", titleReport: "گزارش اشتراکی",
    inputLabel: "دامنه یا آدرس", check: "بررسی", checking: "در حال بررسی…", try: "امتحان کنید:",
    copyLink: "کپی لینک", copied: "کپی شد", permaLink: "لینک دائمی",
    introH: "چه چیزهایی بررسی می‌شود",
    layer: { registration: "ثبت دامنه", nameservers: "نیم‌سرورها", zone: "زون DNS", reachability: "دسترس‌پذیری", web: "بارگذاری سایت" },
    layerHelp: {
      registration: "ثبت شده است؟ تاریخ انقضا، تعلیق‌ها و وضعیت رجیسترار (RDAP و WHOIS).",
      nameservers: "تفویض در TLD و اینکه هر نیم‌سرور پاسخ می‌دهد یا نه.",
      zone: "رکوردها، احراز هویت ایمیل (SPF، DMARC، DKIM) و DNSSEC.",
      reachability: "پینگ و TCP روی پورت‌های 80 و 443 از همهٔ گره‌ها.",
      web: "شناسایی CDN و سرور، ماتریس درخواست از همهٔ گره‌ها، منابع صفحه و تشخیص مبتنی بر قواعد با راه‌حل.",
    },
    state: { PENDING: "در انتظار", RUNNING: "در حال بررسی", OK: "سالم", WARN: "هشدار", FAIL: "خطا", SKIPPED: "رد شد" },
    rootCause: "علت اصلی", evidence: "شواهد", alsoCause: "علت دیگر", symptoms: "این خطاها نتیجهٔ همان علت اصلی‌اند، نه مشکل جداگانه",
    fixes: "کارهایی که باید انجام دهید، به ترتیب", details: "جزئیات", raw: "JSON خام", skipped: "رد شد",
    started: "شروع", via: "از", nodesWord: "گره", nodeWord: "گره",
    traceroute: "مسیریابی (Traceroute)", runTrace: "اجرای Traceroute", tracing: "در حال مسیریابی…", traceFailed: "مسیریابی ناموفق بود",
    hop: "گام", ip: "IP", asn: "ASN", operator: "اپراتور", raw2: "خروجی",
    waitFinish: "صبر کنید تا بررسی تمام شود.",
    permaDone: "لینک دائمی (۲۴ ساعت) کپی شد:", reportBanner: "گزارش اشتراکی ثبت‌شده در {t} — فقط‌خواندنی، به مدت ۲۴ ساعت.",
    lost: "اتصال قطع شد، در حال اتصال دوباره…",
    footer: "«کپی لینک» نتیجه را ۳۰ دقیقه نگه می‌دارد؛ لینک دائمی ۲۴ ساعت.",
    themeDark: "تغییر به تم روشن", themeLight: "تغییر به تم تیره",
    advanced: "پیشرفته: بررسی مستقیم سرور اصلی (Origin)",
    originLabel: "IP سرور اصلی (اختیاری)",
    originWarn: "فقط IP سروری را وارد کنید که مالک آن هستید یا اجازهٔ بررسی‌اش را دارید. این بررسی مستقیماً با نام میزبان سایت به آن وصل می‌شود تا مشکل CDN از مشکل سرور اصلی جدا شود.",
    w: {
      verdict: "نتیجهٔ بارگذاری سایت", confidence: "اطمینان", symptomOf: "این نتیجهٔ یک مشکل در مرحلهٔ قبل است — اول آن را رفع کنید:",
      originTested: "سرور اصلی مستقیماً بررسی شد در", fingerprints: "چه چیزی جلوی سایت است", causes: "علت‌های محتمل",
      fixes: "مراحل رفع مشکل", serverType: "نوع سرور", auto: "خودکار", verify: "روش بررسی", cannot: "آنچه این بررسی از بیرون نمی‌بیند",
      matrix: "ماتریس درخواست‌ها", request: "درخواست", differs: "متفاوت", resources: "منابع صفحه", time: "زمان", issues: "مشکلات",
      copy: "کپی", noCDN: "شناسایی نشد",
      kind: { cdn: "CDN/WAF", server: "سرور", platform: "پلتفرم" },
      level: { high: "بالا", medium: "متوسط", low: "پایین" },
      lik: { high: "محتمل", medium: "ممکن", low: "کم‌احتمال" },
      layer: { none: "مشکلی پیدا نشد", dns: "DNS", cdn: "CDN / WAF", network: "شبکه", tls: "TLS / گواهی", server: "وب‌سرور", application: "برنامه", content: "محتوای صفحه" },
      issue: { failed: "خطا", slow: "کند", mixed_content: "محتوای مختلط", wrong_mime: "نوع نادرست", blocked_mime: "مسدود (nosniff)", uncompressed: "بدون فشرده‌سازی", weak_cache: "کش ضعیف", cors: "CORS", blocked: "مسدود (میزبان داخلی)" },
    },
    t: {
      field: "مورد", value: "مقدار", source: "منبع", registrar: "رجیسترار", created: "تاریخ ثبت", expires: "تاریخ انقضا", daysLeft: "روزهای باقی‌مانده",
      epp: "وضعیت EPP", regNS: "نیم‌سرورها (رجیستری)", ns: "نیم‌سرور", status: "وضعیت", aa: "AA", serial: "سریال SOA", rtt: "تأخیر (ms)",
      glue: "Glue", name: "نام", type: "نوع", ttl: "TTL", node: "گره", sent: "ارسال", recv: "دریافت", loss: "اتلاف", rttmm: "تأخیر کمینه/میانگین/بیشینه",
      note: "توضیح", url: "آدرس", server: "سرور", total: "کل (ms)", final: "آدرس نهایی", result: "نتیجه", check: "بررسی", start: "آدرس شروع",
      delegation: "تفویض از {p}، پرسیده‌شده از {s}", zoneNS: "رکوردهای NS داخل زون:", queried: "منبع پرس‌وجو:", email: "احراز هویت ایمیل",
      dnssec: "DNSSEC", prop: "مقایسهٔ ریزالورهای عمومی", perNode: "به تفکیک گره", tls: "گواهی TLS", protocol: "پروتکل",
      subject: "موضوع", issuer: "صادرکننده", valid: "اعتبار", match: "تطابق نام میزبان", chain: "زنجیره", sans: "نام‌ها (SAN)", yes: "بله", no: "خیر",
    },
    renderFailed: "نمایش جزئیات ممکن نشد.",
    err: {
      invalid_body: "درخواست قابل خواندن نبود. صفحه را دوباره بارگذاری کنید و دوباره تلاش کنید.",
      invalid_id: "این پیوند معتبر نیست.",
      rate_limited: "تعداد درخواست‌ها بیش از حد است — یک دقیقهٔ دیگر دوباره تلاش کنید.",
      origin_not_allowed: "IP مبدأ فقط در آزمون وب‌سایت قابل استفاده است.",
      check_running: "یک بررسی از نشانی شما در حال اجراست — صبر کنید تا تمام شود.",
      busy: "سرور مشغول است — کمی بعد دوباره تلاش کنید.",
      check_not_found: "این بررسی پیدا نشد یا منقضی شده است — دوباره اجرایش کنید.",
      still_running: "بررسی هنوز در حال اجراست.",
      streaming_unsupported: "نمایش زندهٔ پیشرفت در اینجا در دسترس نیست.",
      too_many_streams: "تعداد صفحه‌های بازِ نمایش پیشرفت از نشانی شما بیش از حد است.",
      too_many_viewers: "در حال حاضر افراد زیادی این بررسی را تماشا می‌کنند.",
      no_check_for_trace: "ابتدا یک بررسی اجرا کنید؛ مقصدهای Traceroute از نتایج آن می‌آیند.",
      ip_not_in_check: "این نشانی IP در نتایج بررسی نبود.",
      unknown_node: "گره اندازه‌گیری ناشناخته است.",
      agent_unreachable: "گره اندازه‌گیری در دسترس نیست.",
      request_running: "درخواست دیگری از نشانی شما هنوز در حال اجراست.",
      perma_rate_limited: "درخواست پیوند دائمی بیش از حد است — بعداً دوباره تلاش کنید.",
      perma_unavailable: "پیوند دائمی در حال حاضر در دسترس نیست.",
      perma_expired: "این نتیجه برای ساختن پیوند دائمی قدیمی است — بررسی را دوباره اجرا کنید.",
      report_too_large: "این گزارش برای نگهداری به‌صورت پیوند دائمی بیش از حد بزرگ است.",
      perma_save_failed: "ذخیرهٔ پیوند دائمی ناموفق بود.",
      perma_full: "در حال حاضر پیوندهای اشتراکیِ فعال زیادی وجود دارد — بعداً دوباره تلاش کنید.",
      report_not_found: "این گزارش پیدا نشد یا منقضی شده است.",
      report_unreadable: "این گزارشِ ذخیره‌شده قابل خواندن نیست.",
      no_traceroute: "Traceroute روی این گره در دسترس نیست.",
      origin_not_ip: "مبدأ باید یک نشانی IP باشد، مثلاً 93.184.215.14.",
      origin_zone: "IP مبدأ نباید ناحیهٔ IPv6 (zone) داشته باشد.",
      origin_private: "مبدأ باید یک نشانی IP عمومی باشد (نه خصوصی، محلی یا رزروشده).",
      domain_empty: "لطفاً نام دامنه را وارد کنید.",
      domain_ip: "نشانی IP پشتیبانی نمی‌شود — نام دامنه‌ای مانند example.com وارد کنید.",
      domain_local: "نام‌های محلی یا رزروشده (مانند localhost و ‎.local و ‎.internal) قابل بررسی نیستند.",
      domain_invalid: "این یک نام دامنهٔ معتبر به نظر نمی‌رسد.",
      domain_no_tld: "دامنه را کامل و همراه پسوندش وارد کنید، مثلاً example.com.",
      domain_public_suffix: "این یک پسوند عمومی (مانند TLD) است، نه دامنه‌ای که بتوان ثبت کرد.",
      network: "اتصال به سرور برقرار نشد. اتصال اینترنت را بررسی کنید و دوباره تلاش کنید.",
      http: "سرور خطا برگرداند. دوباره تلاش کنید.",
    },
  },
};

const $ = (id) => document.getElementById(id);
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) { /* private mode */ } },
};

// Farsi is the default; a viewer's saved choice wins.
let lang = store.get("dd.lang", "fa") === "en" ? "en" : "fa";
let current = { requestId: null, reportId: null, report: null, readOnly: false, es: null, layers: {} };
let nodeCache = [];
// The sidebar no longer lists recent checks; drop what older versions stored.
try { localStorage.removeItem("dd.recent"); } catch (_) { /* private mode */ }

function T(key) {
  const parts = key.split(".");
  let v = STRINGS[lang];
  for (const p of parts) v = v == null ? undefined : v[p];
  if (v == null) { v = STRINGS.en; for (const p of parts) v = v == null ? undefined : v[p]; }
  return v == null ? key : v;
}
function fmt(s, vars) { return s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] == null ? "" : vars[k])); }

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

const SVGNS = "http://www.w3.org/2000/svg";
function icon(id, cls) {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", "icon" + (cls ? " " + cls : ""));
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", "#" + id);
  s.append(u);
  return s;
}
const STATUS_ICON = { OK: "i-ok", WARN: "i-warn", FAIL: "i-fail", SKIPPED: "i-skip" };
const SEV_ICON = { fail: "i-fail", warn: "i-warn", info: "i-info" };

function table(headers, rows, opts) {
  const o = opts || {};
  const head = el("tr", {}, headers.map((h, i) => el("th", { class: o.ltr && o.ltr[i] ? "ltr" : null, text: h })));
  const tb = el("tbody");
  rows.forEach((r) => tb.append(el("tr", {}, r.map((c, i) => {
    const cls = [o.classes && o.classes[i] ? o.classes[i](c) : "", o.ltr && o.ltr[i] ? "ltr" : ""].join(" ").trim();
    return el("td", { class: cls || null, dir: o.ltr && o.ltr[i] ? "ltr" : null, text: c == null ? "" : String(c) });
  }))));
  return el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, head), tb));
}

// ---------- chrome: language, theme ----------

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((n) => { n.textContent = T(n.dataset.i18n); });
  document.querySelectorAll("[data-lang]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
  renderIntro();
  renderNodes();
  setTitle();
  updateThemeLabel();
  if (current.report) renderReport(current.report);
  else if (current.requestId) { LAYERS.forEach((l) => setCard(l, current.layers[l] || { status: "PENDING" })); renderPipeline(); }
}

// Only an explicit choice is remembered (dd.themeChoice). The old dd.theme key
// was written on every load, so it says nothing about what the viewer wanted.
function applyTheme(theme, remember) {
  document.documentElement.dataset.theme = theme;
  if (remember) store.set("dd.themeChoice", theme);
  updateThemeLabel();
}
function updateThemeLabel() {
  const dark = document.documentElement.dataset.theme !== "light";
  $("theme").setAttribute("aria-label", dark ? T("themeDark") : T("themeLight"));
  $("theme").title = $("theme").getAttribute("aria-label");
}

function setTitle() {
  const key = current.reportId ? "titleReport" : current.requestId ? "titleResult" : "titleNew";
  $("page-title").textContent = T(key);
  $("page-sub").hidden = !!current.requestId || !!current.reportId;
  $("intro").hidden = !!current.requestId || !!current.reportId;
}

function renderIntro() {
  $("intro-steps").replaceChildren(...LAYERS.map((l) => el("li", {}, icon(LAYER_ICON[l]), el("strong", { text: T("layer." + l) }), el("span", { text: T("layerHelp." + l) }))));
}

// ---------- sidebar: nodes ----------

async function loadNodes() {
  try { nodeCache = await api("/api/nodes"); } catch (_) { nodeCache = []; }
  renderNodes();
  return nodeCache;
}
function renderNodes() {
  const ul = $("nodelist");
  if (!nodeCache.length) { ul.replaceChildren(el("li", {}, el("span", { class: "node" }, el("span", { class: "dot" }), el("span", { text: T("noNodes") })))); return; }
  ul.replaceChildren(...nodeCache.map((n) => el("li", {}, el("span", { class: "node" },
    el("span", { class: "dot live" }), el("span", { class: "name", text: n.name }), el("span", { class: "sub", text: n.location })))));
}

// ---------- API ----------

// APIError carries the server's stable error code so the message can be shown
// in the page language; the English server text is kept as a fallback.
class APIError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

async function api(path, opts) {
  // X-Error-Envelope: the CDN in front of the site replaces 4xx/5xx responses
  // with its own page, so the server sends API errors as 200 + {error, code}.
  const o = Object.assign({}, opts);
  o.headers = Object.assign({ "X-Error-Envelope": "1" }, o.headers || {});
  let resp;
  try { resp = await fetch(path, o); } catch (_) { throw new APIError("network"); }
  const ct = resp.headers.get("Content-Type") || "";
  const body = ct.includes("json") ? await resp.json().catch(() => null) : await resp.text();
  const failed = !resp.ok || resp.headers.get("X-Api-Status") || (body && typeof body === "object" && body.error && body.code);
  if (failed) throw new APIError((body && body.code) || "http", body && body.error);
  return body;
}
// errText turns an error into a message in the current language.
function errText(e) {
  if (!e) return "";
  if (e.code) {
    if (lang === "en" && e.message && e.message !== e.code) return e.message; // server text has the detail
    const t = T("err." + e.code);
    if (t !== "err." + e.code) return t;
  }
  return e.message || T("err.http");
}
function showError(msg) { $("error").textContent = msg || ""; $("error").hidden = !msg; }
function banner(msg) { $("banner").textContent = msg || ""; $("banner").hidden = !msg; }

// ---------- pipeline and cards ----------

function overallClass(rep) {
  const d = rep && rep.diagnosis;
  if (!d) return "";
  if (d.healthy) return "OK";
  return (rep.layers || []).some((l) => l.status === "FAIL") ? "FAIL" : "WARN";
}

function renderPipeline() {
  $("pipeline").replaceChildren(...LAYERS.map((l) => {
    const r = current.layers[l] || { status: "PENDING" };
    const st = r.status || "PENDING";
    const done = ["OK", "WARN", "FAIL", "SKIPPED"].includes(st);
    const ic = STATUS_ICON[st] && st !== "OK" ? STATUS_ICON[st] : LAYER_ICON[l];
    return el("li", { class: st + (done ? " done" : "") },
      el("a", { href: "#card-" + l },
        el("span", { class: "step-node" }, icon(ic)),
        el("span", { class: "step-label", text: T("layer." + l) }),
        el("span", { class: "step-state", text: T("state." + st) })));
  }));
}

function resetCards() {
  current.layers = {};
  $("cards").replaceChildren(...LAYERS.map((l) => card(l, { status: "PENDING" })));
  $("diagnosis").hidden = true;
  renderPipeline();
}

function card(layer, r) {
  const st = r.status || "PENDING";
  const pill = el("span", { class: "pill " + st }, T("state." + st));
  const title = el("div", { class: "card-title" }, el("h3", { text: T("layer." + layer) }),
    r.summary && st !== "PENDING" && st !== "RUNNING" ? el("span", { class: "summary", dir: "auto", text: r.summary }) : el("span", { class: "skeleton" }));
  const box = el("article", { class: "card " + st, id: "card-" + layer },
    el("div", { class: "card-head" }, el("span", { class: "card-icon" }, icon(LAYER_ICON[layer])), title, pill));
  if (layer === "web" && r.details && r.details.verdict) box.append(webPanel(r.details));
  if (r.findings && r.findings.length) {
    box.append(el("ul", { class: "findings" }, r.findings.map((f) => el("li", { class: f.severity },
      icon(SEV_ICON[f.severity] || "i-info"),
      el("span", { class: "msg", dir: "auto" }, f.message, el("span", { class: "code", dir: "ltr", text: f.code })),
      f.evidence ? el("span", { class: "ev", dir: "ltr", text: f.evidence }) : null))));
  }
  if (r.details || r.skip_reason) box.append(detailsFor(layer, r));
  return box;
}

function setCard(layer, r) {
  current.layers[layer] = r;
  const old = $("card-" + layer);
  const n = card(layer, r);
  if (old) old.replaceWith(n); else $("cards").append(n);
  renderPipeline();
}

const ms = (v) => (v ? v.toFixed(0) : "");
const D = (k) => T("t." + k);

function detailsFor(layer, r) {
  const d = r.details || {};
  const body = [];
  try {
    if (layer === "registration" && d.info) {
      const i = d.info;
      body.push(table([D("field"), D("value")], [
        [D("source"), `${i.source} (${i.server || ""})`], [D("registrar"), i.registrar || "—"],
        [D("created"), (i.created || "").slice(0, 10)], [D("expires"), (i.expires || "").slice(0, 10)],
        [D("daysLeft"), d.days_left ?? "—"], [D("epp"), (i.status || []).join(", ") || "—"],
        [D("regNS"), (i.nameservers || []).join(", ")],
      ], { ltr: [false, true] }));
    }
    if (layer === "nameservers" && d.servers) {
      if (d.delegation) body.push(el("p", { class: "muted", text: fmt(D("delegation"), { p: d.delegation.parent, s: d.delegation.parent_server }) }));
      const rows = [];
      d.servers.forEach((s) => (s.probes || []).forEach((p) => rows.push([s.name, p.ip, p.status, p.aa ? D("yes") : "—", p.serial || "", p.rtt_ms ? p.rtt_ms.toFixed(1) : "", p.asn ? `${p.asn} ${p.as_name || ""}` : "", s.in_bailiwick ? ((s.glue || []).length ? "glue" : "missing") : "n/a"])));
      d.servers.filter((s) => !(s.probes || []).length).forEach((s) => rows.push([s.name, "—", "no address", "", "", "", "", ""]));
      body.push(table([D("ns"), D("ip"), D("status"), D("aa"), D("serial"), D("rtt"), "ASN", D("glue")], rows,
        { classes: [null, null, (v) => "s-" + v], ltr: [true, true, true, false, true, true, true, true] }));
      if (d.child_ns && d.child_ns.length) body.push(el("p", { class: "muted" }, D("zoneNS") + " ", el("span", { dir: "ltr", text: d.child_ns.join(", ") })));
    }
    if (layer === "zone" && d.records) {
      body.push(el("p", { class: "muted" }, D("queried") + " ", el("span", { dir: "auto", text: d.queried_server })));
      body.push(table([D("name"), D("type"), D("ttl"), D("value")], d.records.map((x) => [x.name, x.type, x.ttl, x.value]),
        { classes: [null, null, null, () => "val"], ltr: [true, true, true, true] }));
      if (d.email) {
        body.push(el("h4", { text: D("email") }));
        body.push(table([D("check"), D("result")], [
          ["SPF", d.email.spf.record ? `${d.email.spf.record} (${d.email.spf.lookups} DNS lookups)` : "—"],
          ["DMARC", d.email.dmarc.record || "—"],
          ["DKIM", (d.email.dkim_selectors_found || []).join(", ") || "—"],
        ], { classes: [null, () => "val"], ltr: [true, true] }));
      }
      if (d.dnssec) {
        body.push(el("h4", { text: D("dnssec") }));
        body.push(el("ul", { class: "symptoms", dir: "ltr" }, (d.dnssec.chain || []).map((s) => el("li", { text: s }))));
      }
      if (d.propagation) {
        body.push(el("h4", { text: D("prop") }));
        const rows = [];
        d.propagation.forEach((g) => {
          rows.push([g.type, "reference", (g.authoritative || []).join(", ") || "(none)", g.consistent ? "consistent" : "DIFFERS"]);
          (g.values || []).forEach((v) => rows.push(["", `${v.count}: ${v.resolvers.join(", ")}`, v.value, ""]));
          Object.entries(g.errors || {}).forEach(([k, v]) => rows.push(["", k, "error: " + v, ""]));
        });
        body.push(table([D("type"), D("source"), D("value"), ""], rows, { classes: [null, null, () => "val", (v) => "s-" + v], ltr: [true, true, true, true] }));
      }
    }
    if (layer === "reachability" && d.rows) {
      body.push(table([D("node"), D("ip"), D("sent"), D("recv"), D("loss"), D("rttmm"), "TCP 80", "TCP 443", D("status"), D("note")],
        d.rows.map((x) => x.status === "n/a" || x.status === "error"
          ? [`${x.node} (${x.location})`, x.ip, "—", "—", "—", "—", "—", "—", x.status, x.note || ""]
          : [`${x.node} (${x.location})`, x.ip, x.sent, x.received, x.loss.toFixed(0) + "%", x.sent ? `${x.rtt_min}/${x.rtt_avg}/${x.rtt_max}` : (x.ping_error || "—"), x.tcp_80, x.tcp_443, x.status, x.note || ""]),
        { classes: [null, null, null, null, null, null, (v) => "s-" + v, (v) => "s-" + v, (v) => "s-" + v], ltr: [false, true, true, true, true, true, true, true, true, false] }));
      if (!current.readOnly && current.requestId && (d.targets || []).length) body.push(traceUI(d.targets));
    }
    if (layer === "web" && (d.matrix || []).length) body.push(...webEvidenceTables(d));
    if (layer === "web" && d.chains) {
      d.chains.forEach((c) => {
        body.push(el("h4", { dir: "ltr", text: c.start + (c.loop ? "  (redirect loop)" : "") }));
        body.push(table([D("url"), D("ip"), D("status"), D("server"), "DNS", "Connect", "TLS", "TTFB", D("total"), "CDN"],
          c.hops.map((h) => [h.url, h.ip || "", h.error_kind ? "error: " + h.error_kind : `${h.status} ${h.status_text || ""}`, h.server || "",
            ms(h.timing.dns_ms), ms(h.timing.connect_ms), ms(h.timing.tls_ms), ms(h.timing.ttfb_ms), ms(h.timing.total_ms), h.cdn || ""]),
          { ltr: Array(10).fill(true) }));
      });
      Object.entries(d.tls || {}).forEach(([host, t]) => {
        body.push(el("h4", {}, D("tls") + ": ", el("span", { dir: "ltr", text: host })));
        body.push(table([D("field"), D("value")], [
          [D("protocol"), `${t.version} ${t.cipher}`], [D("subject"), t.subject], [D("issuer"), t.issuer],
          [D("valid"), `${t.not_before.slice(0, 10)} → ${t.not_after.slice(0, 10)} (${t.days_left})`],
          [D("match"), t.hostname_match ? D("yes") : D("no")], [D("chain"), t.chain_valid ? "valid" : (t.chain_error || "invalid")],
          [D("sans"), (t.sans || []).join(", ")],
        ], { classes: [null, (v) => (v === D("no") ? "s-error" : "")], ltr: [false, true] }));
      });
      if ((d.nodes || []).length) {
        body.push(el("h4", { text: D("perNode") }));
        body.push(table([D("node"), D("start"), D("final"), D("result"), D("total")],
          d.nodes.map((n) => [n.node, n.url, n.final_url || "", n.error_kind || n.status, n.total_ms ? n.total_ms.toFixed(0) : ""]),
          { ltr: [false, true, true, true, true] }));
      }
    }
  } catch (e) { body.push(el("p", { class: "alert", text: T("renderFailed") })); }
  if (r.skip_reason) body.push(el("p", {}, T("skipped") + ": ", el("span", { dir: "auto", text: r.skip_reason })));
  body.push(el("details", { class: "more" }, el("summary", {}, icon("i-chevron"), T("raw")), el("pre", { text: JSON.stringify(r, null, 2) })));
  return el("details", { class: "more" }, el("summary", {}, icon("i-chevron"), T("details")), el("div", { class: "detail-body" }, body));
}

// ---------- website load ----------

const SERVER_CHOICES = ["auto", "apache", "nginx", "litespeed", "iis"];
const SERVER_KINDS = new Set(["apache", "nginx", "litespeed", "iis", "caddy"]);
let serverPref = SERVER_CHOICES.includes(store.get("dd.server", "auto")) ? store.get("dd.server", "auto") : "auto";

function detectedServer(d) {
  const s = d.fingerprints && d.fingerprints.server && d.fingerprints.server[0];
  return s && s.level !== "low" ? s.id : "";
}

// Snippets to show: the chosen (or detected) server plus non-server targets
// such as Cloudflare, firewall or WordPress. With nothing known, show all.
function snippetEntries(snippets, d) {
  const all = Object.entries(snippets || {}).sort(([a], [b]) => a.localeCompare(b));
  const srv = serverPref === "auto" ? detectedServer(d) : serverPref;
  if (!srv) return all;
  const picked = all.filter(([k]) => k === srv || !SERVER_KINDS.has(k));
  return picked.length ? picked : all;
}

function fpChips(d) {
  const fp = d.fingerprints || {};
  const chips = [];
  const add = (kind, det) => chips.push(el("span", { class: "fp-chip " + det.level, title: (det.evidence || []).join("\n") },
    el("span", { class: "fp-kind", text: T("w.kind." + kind) }), det.name, el("span", { class: "fp-level", text: T("w.level." + det.level) })));
  (fp.cdn || []).slice(0, 2).forEach((x) => add("cdn", x));
  if (fp.no_cdn && !(fp.cdn || []).length) chips.push(el("span", { class: "fp-chip none" }, el("span", { class: "fp-kind", text: T("w.kind.cdn") }), T("w.noCDN")));
  (fp.server || []).slice(0, 1).forEach((x) => add("server", x));
  (fp.platform || []).slice(0, 2).forEach((x) => add("platform", x));
  return chips;
}

function copyBtn(text) {
  const b = el("button", { type: "button", class: "btn ghost small copy-snippet" }, icon("i-link"), T("w.copy"));
  b.addEventListener("click", async () => { if (await copy(text)) { b.lastChild.textContent = T("copied"); setTimeout(() => (b.lastChild.textContent = T("w.copy")), 1200); } });
  return b;
}

function webPanel(d) {
  const v = d.verdict;
  const cls = v.layer === "none" ? "ok" : (current.layers.web && current.layers.web.status === "WARN" ? "warn" : "fail");
  const head = el("div", { class: "verdict-head" },
    el("span", { class: "layer-badge " + cls }, T("w.layer." + v.layer)),
    el("span", { class: "conf" }, T("w.confidence") + ": " + T("w.level." + v.level) + ` (${Math.round(v.confidence * 100)}%)`));
  const panel = el("section", { class: "verdict " + cls, "aria-label": T("w.verdict") }, head,
    el("p", { class: "verdict-text", dir: "auto", text: v.text }));
  if (v.symptom_of) panel.append(el("p", { class: "symptom-note" }, T("w.symptomOf") + " ", el("code", { text: v.symptom_of })));
  if (d.origin_ip) panel.append(el("p", { class: "muted small-note" }, T("w.originTested") + " ", el("code", { text: d.origin_ip })));
  const chips = fpChips(d);
  if (chips.length) panel.append(el("div", { class: "fp-row", "aria-label": T("w.fingerprints") }, chips));
  if ((v.evidence || []).length) {
    panel.append(el("h4", { text: T("evidence") }), el("ul", { class: "ev-list" }, v.evidence.map((e) => el("li", { dir: "ltr", text: e }))));
  }
  if ((v.causes || []).length) {
    panel.append(el("h4", { text: T("w.causes") }), el("ul", { class: "causes" }, v.causes.map((c) =>
      el("li", {}, el("span", { class: "lik " + c.likelihood, text: T("w.lik." + c.likelihood) }), el("span", { dir: "auto", text: c.text })))));
  }
  if ((v.fixes || []).length) {
    const seg = el("div", { class: "seg server-seg", role: "group", "aria-label": T("w.serverType") }, SERVER_CHOICES.map((s) => {
      const label = s === "auto" ? `${T("w.auto")}${detectedServer(d) ? " (" + detectedServer(d) + ")" : ""}` : { apache: "Apache", nginx: "nginx", litespeed: "LiteSpeed", iis: "IIS" }[s];
      const b = el("button", { type: "button", "aria-pressed": String(serverPref === s), text: label });
      b.addEventListener("click", () => { serverPref = s; store.set("dd.server", s); setCard("web", current.layers.web); });
      return b;
    }));
    const steps = el("ol", { class: "fix-steps" }, v.fixes.map((f) => {
      const li = el("li", {}, el("strong", { dir: "auto", text: f.step }));
      if (f.why) li.append(el("p", { class: "muted", dir: "auto", text: f.why }));
      snippetEntries(f.snippets, d).forEach(([k, s]) => li.append(el("div", { class: "snippet" },
        el("div", { class: "snippet-head" }, el("span", { text: k }), copyBtn(s)), el("pre", { text: s }))));
      li.append(el("p", { class: "verify" }, el("span", { class: "diag-label", text: T("w.verify") }), el("span", { dir: "auto", text: f.verify })));
      if (f.warning) li.append(el("p", { class: "warn-note", dir: "auto", text: f.warning }));
      return li;
    }));
    panel.append(el("div", { class: "fix-head" }, el("h4", { text: T("w.fixes") }), seg), steps);
  }
  (v.warnings || []).forEach((w) => panel.append(el("p", { class: "warn-note", dir: "auto", text: w })));
  if ((v.cannot_determine || []).length) {
    panel.append(el("h4", { text: T("w.cannot") }), el("ul", { class: "cannot" }, v.cannot_determine.map((x) => el("li", { dir: "auto", text: x }))));
  }
  return panel;
}

function webEvidenceTables(d) {
  const out = [];
  out.push(el("h4", { text: T("w.matrix") }));
  out.push(table([D("node"), T("w.request"), D("final"), D("result"), "Proto", "TTFB", D("total"), ""],
    d.matrix.map((r) => [r.node, r.label, r.final_url || "", r.loop ? "redirect loop" : (r.error_kind || r.status), r.proto || "",
      ms(r.ttfb_ms), ms(r.total_ms), r.diff ? T("w.differs") : ""]),
    { classes: [null, null, null, (v) => (/^[23]/.test(String(v)) ? "s-ok" : "s-error"), null, null, null, (v) => (v ? "s-icmp_blocked" : "")], ltr: [false, true, true, true, true, true, true, false] }));
  const res = d.resources;
  if (res && (res.resources || []).length) {
    out.push(el("h4", { text: `${T("w.resources")} (${res.page.checked}/${res.page.found})` }));
    const max = Math.max(1, ...res.resources.map((x) => x.total_ms || 0));
    const rows = res.resources.map((x) => {
      const bar = el("span", { class: "wf-bar" + ((x.issues || []).includes("failed") ? " bad" : (x.issues || []).includes("slow") ? " slow" : "") });
      bar.style.width = Math.max(2, Math.round(((x.total_ms || 0) / max) * 100)) + "%"; // CSSOM, allowed by the CSP
      return el("tr", {},
        el("td", { text: x.kind }),
        el("td", { class: "val", dir: "ltr", text: x.url }),
        el("td", { class: /^[23]/.test(String(x.status)) ? "s-ok" : "s-error", text: x.error_kind || x.status || "" }),
        el("td", { class: "wf" }, el("span", { class: "wf-track" }, bar), el("span", { class: "wf-ms", text: ms(x.total_ms) })),
        el("td", { text: (x.issues || []).map((i) => T("w.issue." + i)).join(", ") }));
    });
    out.push(el("div", { class: "table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, [D("type"), D("url"), D("status"), T("w.time"), T("w.issues")].map((h) => el("th", { text: h })))),
      el("tbody", {}, rows))));
  }
  return out;
}

// ---------- traceroute ----------

function traceUI(targets) {
  const nodeSel = el("select", { "aria-label": T("t.node") }, nodeCache.map((n) => el("option", { value: n.id, text: `${n.name} (${n.location})` })));
  const ipSel = el("select", { "aria-label": T("ip"), dir: "ltr" }, targets.map((t) => el("option", { value: t, text: t })));
  const out = el("div");
  const btn = el("button", { type: "button", class: "btn ghost small" }, icon("i-route"), T("runTrace"));
  btn.addEventListener("click", () => {
    btn.disabled = true;
    out.replaceChildren(el("p", { class: "muted", text: T("tracing") }));
    const rows = [];
    const q = new URLSearchParams({ id: current.requestId, node: nodeSel.value, ip: ipSel.value });
    const es = new EventSource("/api/traceroute?" + q);
    const render = (msg) => {
      out.replaceChildren(table([T("hop"), T("ip"), T("asn"), T("operator"), T("raw2")], rows, { ltr: [true, true, true, false, true] }));
      if (msg) out.append(el("p", { class: "muted", text: msg }));
    };
    es.addEventListener("hop", (ev) => { const h = JSON.parse(ev.data); rows.push([h.hop || "", h.ip || "", h.asn || "", h.as_name || "", h.line]); render(); });
    es.addEventListener("done", () => { es.close(); btn.disabled = false; render(); });
    es.addEventListener("error", (ev) => {
      es.close(); btn.disabled = false;
      let msg = T("traceFailed");
      try { const d = JSON.parse(ev.data); msg = errText(new APIError(d.code, d.error)); } catch (_) { /* transport error */ }
      render(msg);
    });
  });
  return el("div", {}, el("h4", { text: T("traceroute") }), el("div", { class: "trace" }, nodeSel, ipSel, btn), out);
}

// ---------- diagnosis ----------

function renderDiagnosis(rep) {
  const d = rep.diagnosis;
  const box = $("diagnosis");
  if (!d) { box.hidden = true; return; }
  const cls = overallClass(rep);
  box.className = "widget diagnosis " + { OK: "ok", WARN: "warn", FAIL: "fail" }[cls];
  const body = el("div", { class: "diag-body" });
  if (d.root_cause) {
    body.append(el("p", {}, el("span", { class: "diag-label", text: T("rootCause") }), el("span", { dir: "auto", text: d.root_cause.explanation })));
    if (d.root_cause.evidence) body.append(el("div", {}, el("span", { class: "diag-label", text: T("evidence") }), el("code", { class: "evidence", dir: "ltr", text: d.root_cause.evidence })));
  }
  (d.other_causes || []).forEach((c) => body.append(el("p", {}, el("span", { class: "diag-label", text: T("alsoCause") }), el("span", { dir: "auto", text: c.explanation }))));
  if ((d.symptoms || []).length) {
    body.append(el("div", {}, el("span", { class: "diag-label", text: T("symptoms") }),
      el("ul", { class: "symptoms" }, d.symptoms.map((s) => el("li", { dir: "auto", text: s.message })))));
  }
  if ((d.fixes || []).length) {
    body.append(el("div", {}, el("span", { class: "diag-label", text: T("fixes") }),
      el("ol", { class: "fixes" }, d.fixes.map((f) => el("li", {},
        el("span", { class: "prio p" + f.priority, text: "P" + f.priority }),
        el("strong", { dir: "auto", text: f.title }),
        el("span", { dir: "auto", text: f.action }))))));
  }
  box.replaceChildren(el("span", { class: "diag-icon" }, icon(STATUS_ICON[cls] || "i-info")), el("h3", { dir: "auto", text: d.headline }), body);
  box.hidden = false;
}

// ---------- flows ----------

function showResult(domain) {
  $("result").hidden = false;
  $("actions").hidden = false;
  $("title").textContent = domain.unicode && domain.unicode !== domain.name ? `${domain.unicode} (${domain.name})` : domain.name;
  if (!$("domain").value) $("domain").value = domain.name;
  setTitle();
}

function setMeta(rep) {
  const parts = [];
  if (rep.started_at) parts.push(`${T("started")} ${new Date(rep.started_at).toLocaleString(lang === "fa" ? "fa-IR" : undefined)}`);
  const n = (rep.nodes || []).length;
  if (n) parts.push(`${T("via")} ${n} ${n === 1 ? T("nodeWord") : T("nodesWord")}`);
  $("meta").textContent = parts.join(" · ");
}

function setExports() {
  const id = current.requestId, rid = current.reportId;
  $("exp-json").href = rid ? `/api/report?id=${rid}&download=1` : `/api/check/${id}?download=1`;
  $("exp-md").href = rid ? `/api/report?id=${rid}&format=md&download=1` : `/api/check/${id}?format=md&download=1`;
  $("perma").hidden = current.readOnly;
}

function renderReport(rep) {
  current.report = rep;
  showResult(rep.domain);
  setMeta(rep);
  const byLayer = Object.fromEntries((rep.layers || []).map((l) => [l.layer, l]));
  current.layers = {};
  LAYERS.forEach((l) => setCard(l, byLayer[l] || { status: "PENDING" }));
  renderDiagnosis(rep);
  setExports();
}

function stream(id) {
  if (current.es) current.es.close();
  current = { requestId: id, reportId: null, report: null, readOnly: false, es: null, layers: {} };
  resetCards();
  setExports();
  setTitle();
  banner("");
  $("go").disabled = true;
  const es = new EventSource(`/api/check/${id}?stream=1`);
  current.es = es;
  es.addEventListener("request_id", (ev) => showResult(JSON.parse(ev.data).domain));
  es.addEventListener("layer_start", (ev) => { const e = JSON.parse(ev.data); setCard(e.layer, { status: "RUNNING" }); });
  es.addEventListener("layer_done", (ev) => { const e = JSON.parse(ev.data); setCard(e.layer, e.result); });
  es.addEventListener("done", (ev) => {
    es.close();
    $("go").disabled = false;
    const rep = JSON.parse(ev.data).report;
    renderReport(rep);
  });
  es.onerror = () => {
    es.close();
    $("go").disabled = false;
    api(`/api/check/${id}`).then((rep) => {
      if (rep.status === "done") renderReport(rep); else { banner(T("lost")); setTimeout(() => stream(id), 2000); }
    }).catch((e) => showError(errText(e)));
  };
}

async function startCheck(domain) {
  showError("");
  try {
    // With an origin IP the check goes to the Website Load endpoint, which
    // adds the origin-direct comparison; the server validates the address.
    const originIp = ($("origin").value || "").trim();
    const path = originIp ? "/api/web-diagnose" : "/api/check";
    const payload = originIp ? { domain, originIp } : { domain };
    const r = await api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    history.pushState(null, "", "/c/" + r.request_id);
    stream(r.request_id);
    showResult(r.domain);
  } catch (e) { showError(errText(e)); }
}

async function loadPermanent(id) {
  try {
    const st = await api("/api/report?id=" + encodeURIComponent(id));
    current = { requestId: st.data.request_id, reportId: id, report: null, readOnly: true, es: null, layers: {} };
    renderReport(st.data);
    banner(fmt(T("reportBanner"), { t: new Date(st.captured_at).toLocaleString(lang === "fa" ? "fa-IR" : undefined) }));
  } catch (e) { showError(errText(e)); setTitle(); }
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (_) { window.prompt(T("copyLink"), text); return false; }
}

// ---------- wiring ----------

$("form").addEventListener("submit", (ev) => { ev.preventDefault(); if (!$("go").disabled) startCheck($("domain").value); });
document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => { $("domain").value = b.dataset.example; $("domain").focus(); }));
document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => { lang = b.dataset.lang; store.set("dd.lang", lang); applyLang(); }));
$("theme").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light", true));
$("copy").addEventListener("click", async () => {
  const url = current.reportId ? `${location.origin}/r/${current.reportId}` : `${location.origin}/c/${current.requestId}`;
  if (await copy(url)) {
    const label = $("copy").querySelector("span");
    label.textContent = T("copied");
    setTimeout(() => { label.textContent = T("copyLink"); }, 1500);
  }
});
$("perma").addEventListener("click", async () => {
  if (!current.report || current.report.status !== "done") { showError(T("waitFinish")); return; }
  try {
    const r = await api("/api/report/promote", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ request_id: current.requestId }) });
    const url = location.origin + r.url;
    await copy(url);
    banner(T("permaDone") + " " + url);
  } catch (e) { showError(errText(e)); }
});
window.addEventListener("popstate", () => location.reload());

(function init() {
  // ?lang=fa / ?theme=light override (and remember) the viewer's choice.
  const qs = new URLSearchParams(location.search);
  if (qs.get("lang") === "fa" || qs.get("lang") === "en") { lang = qs.get("lang"); store.set("dd.lang", lang); }
  if (qs.get("theme") === "light" || qs.get("theme") === "dark") store.set("dd.themeChoice", qs.get("theme"));
  try { localStorage.removeItem("dd.theme"); } catch (_) { /* private mode */ }
  applyTheme(store.get("dd.themeChoice", "light") === "dark" ? "dark" : "light"); // light by default
  applyLang();
  loadNodes();
  const m = location.pathname.match(/^\/(c|r)\/([0-9a-f]{40})$/);
  if (m && m[1] === "c") stream(m[2]);
  else if (m && m[1] === "r") loadPermanent(m[2]);
  else $("domain").focus();
})();
