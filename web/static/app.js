// Domain Doctor panel. Server data is inserted with textContent only (never innerHTML).
"use strict";

const LAYERS = ["registration", "nameservers", "zone", "reachability", "web"];
const LAYER_ICON = { registration: "i-id", nameservers: "i-servers", zone: "i-records", reachability: "i-radar", web: "i-window" };

const STRINGS = {
  en: {
    tagline: "Domain troubleshooting", newCheck: "New check", recent: "Recent checks",
    recentEmpty: "Checks you run in this browser appear here.", nodes: "Measurement nodes", noNodes: "No node is online.",
    titleNew: "Check a domain", subNew: "Registration, name servers, DNS, reachability and the web server, in order.",
    titleResult: "Check result", titleReport: "Shared report",
    inputLabel: "Domain or URL", check: "Check", checking: "Checking…", try: "Try:",
    copyLink: "Copy link", copied: "Copied", permaLink: "Permanent link",
    introH: "What gets checked",
    layer: { registration: "Registration", nameservers: "Name servers", zone: "DNS zone", reachability: "Reachability", web: "Web server" },
    layerHelp: {
      registration: "Registered? Expiry, holds and registrar status (RDAP, WHOIS).",
      nameservers: "The delegation at the TLD, and whether each name server answers.",
      zone: "Records, mail authentication (SPF, DMARC, DKIM) and DNSSEC.",
      reachability: "Ping and TCP 80/443 from every measurement node.",
      web: "HTTP and HTTPS, redirects, TLS certificate and security headers.",
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
    t: {
      field: "Field", value: "Value", source: "Source", registrar: "Registrar", created: "Created", expires: "Expires", daysLeft: "Days left",
      epp: "EPP status", regNS: "Name servers (registry)", ns: "Name server", status: "Status", aa: "AA", serial: "SOA serial", rtt: "RTT ms",
      glue: "Glue", name: "Name", type: "Type", ttl: "TTL", node: "Node", sent: "Sent", recv: "Recv", loss: "Loss", rttmm: "RTT min/avg/max",
      note: "Note", url: "URL", server: "Server", total: "Total ms", final: "Final URL", result: "Result", check: "Check", start: "Start URL",
      delegation: "Delegation from {p}, asked {s}", zoneNS: "NS records inside the zone:", queried: "Queried:", email: "Mail authentication",
      dnssec: "DNSSEC", prop: "Public resolvers compared", perNode: "Per node", tls: "TLS certificate", protocol: "Protocol",
      subject: "Subject", issuer: "Issuer", valid: "Valid", match: "Hostname match", chain: "Chain", sans: "Names (SAN)", yes: "yes", no: "NO",
    },
  },
  fa: {
    tagline: "عیب‌یابی دامنه", newCheck: "بررسی جدید", recent: "بررسی‌های اخیر",
    recentEmpty: "بررسی‌هایی که در این مرورگر انجام می‌دهید اینجا نمایش داده می‌شوند.", nodes: "گره‌های اندازه‌گیری", noNodes: "هیچ گره‌ای آنلاین نیست.",
    titleNew: "بررسی دامنه", subNew: "ثبت دامنه، نیم‌سرورها، DNS، دسترس‌پذیری و وب‌سرور، به ترتیب.",
    titleResult: "نتیجهٔ بررسی", titleReport: "گزارش اشتراکی",
    inputLabel: "دامنه یا آدرس", check: "بررسی", checking: "در حال بررسی…", try: "امتحان کنید:",
    copyLink: "کپی لینک", copied: "کپی شد", permaLink: "لینک دائمی",
    introH: "چه چیزهایی بررسی می‌شود",
    layer: { registration: "ثبت دامنه", nameservers: "نیم‌سرورها", zone: "زون DNS", reachability: "دسترس‌پذیری", web: "وب‌سرور" },
    layerHelp: {
      registration: "ثبت شده است؟ تاریخ انقضا، تعلیق‌ها و وضعیت رجیسترار (RDAP و WHOIS).",
      nameservers: "تفویض در TLD و اینکه هر نیم‌سرور پاسخ می‌دهد یا نه.",
      zone: "رکوردها، احراز هویت ایمیل (SPF، DMARC، DKIM) و DNSSEC.",
      reachability: "پینگ و TCP روی پورت‌های 80 و 443 از همهٔ گره‌ها.",
      web: "HTTP و HTTPS، ریدایرکت‌ها، گواهی TLS و هدرهای امنیتی.",
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
    t: {
      field: "مورد", value: "مقدار", source: "منبع", registrar: "رجیسترار", created: "تاریخ ثبت", expires: "تاریخ انقضا", daysLeft: "روزهای باقی‌مانده",
      epp: "وضعیت EPP", regNS: "نیم‌سرورها (رجیستری)", ns: "نیم‌سرور", status: "وضعیت", aa: "AA", serial: "سریال SOA", rtt: "تأخیر (ms)",
      glue: "Glue", name: "نام", type: "نوع", ttl: "TTL", node: "گره", sent: "ارسال", recv: "دریافت", loss: "اتلاف", rttmm: "تأخیر کمینه/میانگین/بیشینه",
      note: "توضیح", url: "آدرس", server: "سرور", total: "کل (ms)", final: "آدرس نهایی", result: "نتیجه", check: "بررسی", start: "آدرس شروع",
      delegation: "تفویض از {p}، پرسیده‌شده از {s}", zoneNS: "رکوردهای NS داخل زون:", queried: "منبع پرس‌وجو:", email: "احراز هویت ایمیل",
      dnssec: "DNSSEC", prop: "مقایسهٔ ریزالورهای عمومی", perNode: "به تفکیک گره", tls: "گواهی TLS", protocol: "پروتکل",
      subject: "موضوع", issuer: "صادرکننده", valid: "اعتبار", match: "تطابق نام میزبان", chain: "زنجیره", sans: "نام‌ها (SAN)", yes: "بله", no: "خیر",
    },
  },
};

const $ = (id) => document.getElementById(id);
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) { /* private mode */ } },
};

let lang = store.get("dd.lang", "en") === "fa" ? "fa" : "en";
let current = { requestId: null, reportId: null, report: null, readOnly: false, es: null, layers: {} };
let nodeCache = [];

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
  renderRecent();
  setTitle();
  updateThemeLabel();
  if (current.report) renderReport(current.report);
  else if (current.requestId) { LAYERS.forEach((l) => setCard(l, current.layers[l] || { status: "PENDING" })); renderPipeline(); }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  store.set("dd.theme", theme);
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

// ---------- sidebar: nodes and recent checks ----------

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

function recentList() { return store.get("dd.recent", []).filter((r) => r && /^[0-9a-f]{40}$/.test(r.id)); }
function remember(entry) {
  const list = recentList().filter((r) => r.id !== entry.id);
  list.unshift(entry);
  store.set("dd.recent", list.slice(0, 8));
  renderRecent();
}
function updateRecent(id, status) {
  const list = recentList();
  const r = list.find((x) => x.id === id);
  if (r) { r.status = status; store.set("dd.recent", list); renderRecent(); }
}
function renderRecent() {
  const list = recentList();
  $("recent-empty").hidden = list.length > 0;
  $("recent").replaceChildren(...list.map((r) => {
    const href = r.perma ? "/r/" + r.id : "/c/" + r.id;
    const cur = r.id === current.requestId || r.id === current.reportId;
    const when = new Date(r.t).toLocaleTimeString(lang === "fa" ? "fa-IR" : undefined, { hour: "2-digit", minute: "2-digit" });
    return el("li", {}, el("a", { href, "aria-current": cur ? "page" : null },
      el("span", { class: "dot " + (r.status || "") }), el("span", { class: "name", text: r.domain }), el("span", { class: "sub", text: when })));
  }));
}

// ---------- API ----------

async function api(path, opts) {
  const resp = await fetch(path, opts);
  const ct = resp.headers.get("Content-Type") || "";
  const body = ct.includes("json") ? await resp.json() : await resp.text();
  if (!resp.ok) throw new Error((body && body.error) || "HTTP " + resp.status);
  return body;
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
  } catch (e) { body.push(el("p", { class: "alert", text: "Could not render details: " + e.message })); }
  if (r.skip_reason) body.push(el("p", {}, T("skipped") + ": ", el("span", { dir: "auto", text: r.skip_reason })));
  body.push(el("details", { class: "more" }, el("summary", {}, icon("i-chevron"), T("raw")), el("pre", { text: JSON.stringify(r, null, 2) })));
  return el("details", { class: "more" }, el("summary", {}, icon("i-chevron"), T("details")), el("div", { class: "detail-body" }, body));
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
      try { msg = JSON.parse(ev.data).error; } catch (_) { /* transport error */ }
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
  renderRecent();
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
    updateRecent(id, overallClass(rep));
  });
  es.onerror = () => {
    es.close();
    $("go").disabled = false;
    api(`/api/check/${id}`).then((rep) => {
      if (rep.status === "done") { renderReport(rep); updateRecent(id, overallClass(rep)); } else { banner(T("lost")); setTimeout(() => stream(id), 2000); }
    }).catch((e) => showError(e.message));
  };
}

async function startCheck(domain) {
  showError("");
  try {
    const r = await api("/api/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
    history.pushState(null, "", "/c/" + r.request_id);
    remember({ id: r.request_id, domain: r.domain.name, t: Date.now(), status: "" });
    stream(r.request_id);
    showResult(r.domain);
  } catch (e) { showError(e.message); }
}

async function loadPermanent(id) {
  try {
    const st = await api("/api/report?id=" + encodeURIComponent(id));
    current = { requestId: st.data.request_id, reportId: id, report: null, readOnly: true, es: null, layers: {} };
    renderReport(st.data);
    banner(fmt(T("reportBanner"), { t: new Date(st.captured_at).toLocaleString(lang === "fa" ? "fa-IR" : undefined) }));
  } catch (e) { showError(e.message); setTitle(); }
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (_) { window.prompt(T("copyLink"), text); return false; }
}

// ---------- wiring ----------

$("form").addEventListener("submit", (ev) => { ev.preventDefault(); if (!$("go").disabled) startCheck($("domain").value); });
document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => { $("domain").value = b.dataset.example; $("domain").focus(); }));
document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => { lang = b.dataset.lang; store.set("dd.lang", lang); applyLang(); }));
$("theme").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));
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
    remember({ id: r.id, domain: current.report.domain.name, t: Date.now(), status: overallClass(current.report), perma: true });
    banner(T("permaDone") + " " + url);
  } catch (e) { showError(e.message); }
});
window.addEventListener("popstate", () => location.reload());

(function init() {
  // ?lang=fa / ?theme=light override (and remember) the viewer's choice.
  const qs = new URLSearchParams(location.search);
  if (qs.get("lang") === "fa" || qs.get("lang") === "en") { lang = qs.get("lang"); store.set("dd.lang", lang); }
  if (qs.get("theme") === "light" || qs.get("theme") === "dark") store.set("dd.theme", qs.get("theme"));
  applyTheme(store.get("dd.theme", "dark") === "light" ? "light" : "dark");
  applyLang();
  loadNodes();
  const m = location.pathname.match(/^\/(c|r)\/([0-9a-f]{40})$/);
  if (m && m[1] === "c") stream(m[2]);
  else if (m && m[1] === "r") loadPermanent(m[2]);
  else $("domain").focus();
})();
