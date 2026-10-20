// netarget server-accessibility page. Server data is inserted with
// textContent only (never innerHTML). Self-contained: this feature can be
// removed by deleting servercheck.html + servercheck.js and the /server-check
// route — the rest of the panel is untouched.
"use strict";

const STRINGS = {
  en: {
    tagline: "Server check", domainCheck: "Domain check",
    title: "Server accessibility check",
    sub: "Identity, reachability from the measurement nodes, and which service ports answer.",
    inputLabel: "Server IP address or hostname", check: "Check", checking: "Checking…",
    authorize: "I own this server or am authorized to check it.",
    ports: "Checks the standard service ports, plus the extra port if you enter one.",
    extraPort: "Extra port (optional)", custom: "custom", portsWord: "ports",
    badPort: "The extra port must be a number from 1 to 65535.",
    footer: "Read-only checks: ping, TCP connect, reverse DNS and public registry data. No login, nothing is run on the server.",
    needAuth: "Please confirm you are authorized to check this target.",
    identity: "Identity", ping: "Reachability (ping)", services: "Service ports",
    ip: "IP", ptr: "Reverse DNS", asn: "ASN", operator: "Operator", network: "Network",
    org: "Organization", country: "Country", abuse: "Abuse contact",
    node: "Node", location: "Location", loss: "Loss", rtt: "RTT min/avg/max (ms)", status: "Status", note: "Note",
    port: "Port", service: "Service", state: "State", latency: "Latency (ms)", nodesOpen: "Open from", tls: "TLS / HTTP",
    none: "none", themeDark: "Switch to light theme", themeLight: "Switch to dark theme",
    st: { ok: "reachable", icmp_blocked: "ICMP blocked, TCP answers", down: "no response", error: "node error", "n/a": "not applicable",
          open: "open", closed: "closed", filtered: "filtered", mixed: "open (some nodes)", unknown: "not tested" },
    net: "Could not reach the server. Check your connection and try again.",
    err: {
      sa_empty: "Enter a server IP address or hostname.",
      sa_too_long: "That target is too long.",
      sa_invalid: "This does not look like a valid IP address or hostname.",
      sa_private: "That address is private, loopback or reserved and cannot be checked.",
      sa_reserved: "Local or reserved names (localhost, .local, .internal…) cannot be checked.",
      sa_no_ip: "The hostname does not resolve to any public IP address.",
      sa_unauthorized: "Please confirm you are authorized to check this target.",
      sa_disabled: "The server check is not enabled on this instance.",
      sa_bad_port: "The extra port must be a number from 1 to 65535.",
      sa_port_off: "Custom ports are not enabled on this instance.",
      rate_limited: "Too many requests — try again in a minute.",
      request_running: "Another request from your address is still running.",
      busy: "The server is busy — please try again shortly.",
      too_many_streams: "Too many progress views are open from your address.",
    },
  },
  fa: {
    tagline: "بررسی سرور", domainCheck: "بررسی دامنه",
    title: "بررسی دسترس‌پذیری سرور",
    sub: "شناسهٔ سرور، دسترس‌پذیری از گره‌های اندازه‌گیری و اینکه کدام پورت‌های سرویس پاسخ می‌دهند.",
    inputLabel: "آی‌پی یا نام میزبان سرور", check: "بررسی", checking: "در حال بررسی…",
    authorize: "مالک این سرور هستم یا اجازهٔ بررسی آن را دارم.",
    ports: "پورت‌های استاندارد سرویس را بررسی می‌کند، به‌علاوهٔ پورت اضافه اگر وارد کنید.",
    extraPort: "پورت اضافه (اختیاری)", custom: "سفارشی", portsWord: "پورت‌ها",
    badPort: "پورت اضافه باید عددی بین ۱ تا ۶۵۵۳۵ باشد.",
    footer: "بررسی‌ها فقط‌خواندنی‌اند: پینگ، اتصال TCP، DNS معکوس و دادهٔ عمومی رجیستری. هیچ ورودی یا اجرای فرمانی روی سرور انجام نمی‌شود.",
    needAuth: "لطفاً تأیید کنید که اجازهٔ بررسی این هدف را دارید.",
    identity: "شناسه", ping: "دسترس‌پذیری (پینگ)", services: "پورت‌های سرویس",
    ip: "آی‌پی", ptr: "DNS معکوس", asn: "ASN", operator: "اپراتور", network: "شبکه",
    org: "سازمان", country: "کشور", abuse: "تماس سوءاستفاده",
    node: "گره", location: "موقعیت", loss: "اتلاف", rtt: "RTT کمینه/میانگین/بیشینه (ms)", status: "وضعیت", note: "یادداشت",
    port: "پورت", service: "سرویس", state: "وضعیت", latency: "تأخیر (ms)", nodesOpen: "باز از", tls: "TLS / HTTP",
    none: "ندارد", themeDark: "تم روشن", themeLight: "تم تیره",
    st: { ok: "دسترس‌پذیر", icmp_blocked: "ICMP مسدود، TCP پاسخ می‌دهد", down: "بدون پاسخ", error: "خطای گره", "n/a": "نامربوط",
          open: "باز", closed: "بسته", filtered: "فیلترشده", mixed: "باز (برخی گره‌ها)", unknown: "بررسی‌نشده" },
    net: "اتصال به سرور ممکن نشد. اتصال خود را بررسی و دوباره تلاش کنید.",
    err: {
      sa_empty: "یک آی‌پی یا نام میزبان وارد کنید.",
      sa_too_long: "این هدف بیش از حد طولانی است.",
      sa_invalid: "این یک آی‌پی یا نام میزبان معتبر به نظر نمی‌رسد.",
      sa_private: "این نشانی خصوصی، لوپ‌بک یا رزرو‌شده است و قابل بررسی نیست.",
      sa_reserved: "نام‌های محلی یا رزرو‌شده (localhost، ‎.local،‏ ‎.internal‏…) قابل بررسی نیستند.",
      sa_no_ip: "این نام میزبان به هیچ آی‌پی عمومی تبدیل نمی‌شود.",
      sa_unauthorized: "لطفاً تأیید کنید که اجازهٔ بررسی این هدف را دارید.",
      sa_disabled: "بررسی سرور روی این نمونه فعال نیست.",
      sa_bad_port: "پورت اضافه باید عددی بین ۱ تا ۶۵۵۳۵ باشد.",
      sa_port_off: "پورت سفارشی روی این نمونه فعال نیست.",
      rate_limited: "درخواست‌های بیش از حد — یک دقیقهٔ دیگر تلاش کنید.",
      request_running: "درخواست دیگری از نشانی شما هنوز در حال اجراست.",
      busy: "سرور شلوغ است — کمی بعد دوباره تلاش کنید.",
      too_many_streams: "نماهای پیشرفت بیش از حدی از نشانی شما باز است.",
    },
  },
};

const params = new URLSearchParams(location.search);
let lang = params.get("lang") === "en" ? "en" : (params.get("lang") === "fa" ? "fa" : "fa");
let theme = params.get("theme") === "dark" ? "dark" : (params.get("theme") === "light" ? "light" : "light");

function T(path) {
  const parts = path.split(".");
  let v = STRINGS[lang];
  for (const p of parts) v = v && v[p];
  if (v == null) { v = STRINGS.en; for (const p of parts) v = v && v[p]; }
  return v == null ? path : v;
}
const $ = (id) => document.getElementById(id);

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
function icon(id) {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", "icon");
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", "#" + id);
  s.append(u);
  return s;
}

function table(headers, rows, ltr) {
  const head = el("tr", {}, headers.map((h, i) => el("th", { class: ltr && ltr[i] ? "ltr" : null, text: h })));
  const tb = el("tbody");
  rows.forEach((r) => tb.append(el("tr", {}, r.map((c, i) => {
    const cell = (c && typeof c === "object" && "text" in c) ? c : { text: c };
    const cls = [cell.class || "", ltr && ltr[i] ? "ltr" : ""].join(" ").trim();
    return el("td", { class: cls || null, dir: ltr && ltr[i] ? "ltr" : null, text: cell.text == null ? "" : String(cell.text) });
  }))));
  return el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, head), tb));
}

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((n) => { n.textContent = T(n.dataset.i18n); });
  document.querySelectorAll("[data-lang]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
}
function applyTheme() {
  document.documentElement.dataset.theme = theme;
  $("theme").setAttribute("aria-label", theme === "dark" ? T("themeDark") : T("themeLight"));
}

function showError(msg) { $("error").textContent = msg || ""; $("error").hidden = !msg; }
function banner(msg) { $("banner").textContent = msg || ""; $("banner").hidden = !msg; }

const PING_CLASS = { ok: "s-ok", icmp_blocked: "s-icmp", down: "s-down", error: "s-error", "n/a": "s-filtered" };
const PORT_CLASS = { open: "s-open", mixed: "s-open", closed: "s-closed", filtered: "s-filtered", unknown: "s-filtered" };

function fmtDate(s) { return s ? String(s).slice(0, 10) : ""; }

function renderIdentity(d) {
  const card = el("section", { class: "card" }, el("div", { class: "card-head" }, icon("i-id"), el("h3", { class: "card-title", text: T("identity") })));
  if (d.host) card.append(el("p", { class: "muted", dir: "ltr", text: d.host }));
  (d.ips || []).forEach((x) => {
    const rows = [
      [T("ptr"), { text: x.ptr || T("none"), class: "ltr" }],
      [T("asn"), { text: x.asn ? (x.asn + (x.as_name ? " · " + x.as_name : "")) : T("none"), class: "ltr" }],
      [T("network"), { text: x.network || T("none"), class: "ltr" }],
      [T("org"), x.org || T("none")],
      [T("country"), x.country || T("none")],
      [T("abuse"), { text: x.abuse || T("none"), class: "ltr" }],
    ];
    card.append(table([T("ip"), x.ip], rows, [false, true]));
  });
  return card;
}

function renderPing(d) {
  const card = el("section", { class: "card" }, el("div", { class: "card-head" }, icon("i-radar"),
    el("h3", { class: "card-title", text: T("ping") }), el("span", { class: "muted", text: d.summary || "" })));
  const rows = (d.rows || []).map((r) => [
    { text: r.node, },
    r.location || "",
    { text: r.ip, class: "ltr" },
    r.status === "ok" ? Math.round(r.loss) + "%" : "",
    r.status === "ok" && r.sent ? `${round(r.rtt_min)}/${round(r.rtt_avg)}/${round(r.rtt_max)}` : "",
    { text: T("st." + r.status) || r.status, class: PING_CLASS[r.status] || "" },
    r.note || r.ping_error || "",
  ]);
  card.append(table([T("node"), T("location"), T("ip"), T("loss"), T("rtt"), T("status"), T("note")], rows, [false, false, true, false, true, false, false]));
  return card;
}

function renderServices(d) {
  const card = el("section", { class: "card" }, el("div", { class: "card-head" }, icon("i-servers"),
    el("h3", { class: "card-title", text: T("services") }), el("span", { class: "muted", text: d.summary || "" })));
  const rows = (d.rows || []).map((r) => {
    let tls = "";
    if (r.tls) tls = (r.tls.subject || "") + (r.tls.days_left != null ? ` (${r.tls.days_left}d)` : "");
    else if (r.http && r.http.status) tls = "HTTP " + r.http.status + (r.http.server ? " · " + r.http.server : "");
    else if (r.http && r.http.error) tls = r.http.error;
    return [
      { text: r.ip, class: "ltr" },
      { text: r.port, class: "ltr" },
      r.port === customPort ? (r.service ? r.service + " · " + T("custom") : T("custom")) : (r.service || ""),
      { text: T("st." + r.state) || r.state, class: PORT_CLASS[r.state] || "" },
      r.state === "open" || r.state === "mixed" ? `${r.open_from}/${r.nodes}` : "",
      r.latency_ms ? round(r.latency_ms) : "",
      { text: tls, class: "ltr" },
    ];
  });
  card.append(table([T("ip"), T("port"), T("service"), T("state"), T("nodesOpen"), T("latency"), T("tls")], rows, [true, true, false, false, false, false, true]));
  return card;
}

function round(n) { return n == null ? "" : Math.round(n * 10) / 10; }

let running = false;
let customPort = 0; // the extra port of the run being shown, to label its row

// parsePort returns 0 for an empty box, the port for 1..65535, or -1.
function parsePort(s) {
  s = s.trim();
  if (s === "") return 0;
  if (!/^\d{1,5}$/.test(s)) return -1;
  const n = Number(s);
  return n >= 1 && n <= 65535 ? n : -1;
}

async function run(targetText, port) {
  if (running) return;
  if (port < 0) { showError(T("badPort")); return; }
  if (!$("authorized").checked) { showError(T("needAuth")); return; }
  running = true;
  customPort = port;
  showError(""); banner("");
  $("go").disabled = true;
  $("go").lastChild.textContent = T("checking");
  $("result").hidden = false;
  $("rtitle").textContent = targetText;
  $("rmeta").textContent = "";
  const stages = $("stages");
  stages.replaceChildren();
  const slots = {};

  const url = "/api/server-access?target=" + encodeURIComponent(targetText) + "&authorized=1" + (port ? "&port=" + port : "");
  try {
    const resp = await fetch(url, { headers: { Accept: "text/event-stream" } });
    if (!resp.ok || !resp.body) {
      let code = "";
      try { code = (await resp.json()).code; } catch (_) {}
      showError(code && T("err." + code) !== "err." + code ? T("err." + code) : T("net"));
      $("result").hidden = true;
      return;
    }
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, i);
        buf = buf.slice(i + 2);
        handleEvent(chunk, slots, stages);
      }
    }
  } catch (e) {
    showError(T("net"));
  } finally {
    running = false;
    $("go").disabled = false;
    $("go").lastChild.textContent = T("check");
  }
}

function handleEvent(chunk, slots, stages) {
  let ev = "message", data = "";
  for (const line of chunk.split("\n")) {
    if (line.startsWith("event:")) ev = line.slice(6).trim();
    else if (line.startsWith("data:")) data += line.slice(5).trim();
  }
  if (!data) return;
  let d;
  try { d = JSON.parse(data); } catch (_) { return; }
  const put = (key, node) => {
    if (slots[key]) slots[key].replaceWith(node);
    else stages.append(node);
    slots[key] = node;
  };
  switch (ev) {
    case "meta":
      customPort = d.custom_port || 0;
      if (d.ports) $("rmeta").textContent = (d.host ? d.host + " · " : "") + T("portsWord") + " " + d.ports.join(", ");
      break;
    case "identity": if (d.identity) put("identity", renderIdentity(d.identity)); break;
    case "ping": if (d.ping) put("ping", renderPing(d.ping)); break;
    case "services": if (d.services) put("services", renderServices(d.services)); break;
    case "error": showError(d.code && T("err." + d.code) !== "err." + d.code ? T("err." + d.code) : (d.error || T("net"))); break;
  }
}

function init() {
  applyLang(); applyTheme();
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    const t = $("target").value.trim();
    if (t) run(t, parsePort($("port").value));
  });
  document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => { lang = b.dataset.lang; applyLang(); applyTheme(); }));
  $("theme").addEventListener("click", () => { theme = theme === "dark" ? "light" : "dark"; applyTheme(); });
}
init();
