"use strict";
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let csrf = "", left = 900, tick, range = { frm: "", to: "" };
const IST = ts => ts ? new Date(ts * 1000).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", hour12: true }) : "-";

async function fp() {
  const c = document.createElement("canvas").getContext("2d"); c.font = "14px Arial"; c.fillText("lysandra☄", 2, 14);
  const raw = [navigator.userAgent, navigator.language, screen.width, screen.height, screen.colorDepth, Intl.DateTimeFormat().resolvedOptions().timeZone, c.canvas.toDataURL()].join("|");
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function api(path, method = "GET", body) {
  const r = await fetch("/admin/api" + path, { method, credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF": csrf }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { showLogin("Session expired"); throw new Error("auth"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || "Error " + r.status);
  left = 900; return j;
}
const toast = m => alert(m);
function showLogin(msg) { clearInterval(tick); $("#app").hidden = true; $("#login").hidden = false; $("#lerr").textContent = msg || ""; }
$("#lf").onsubmit = async e => {
  e.preventDefault();
  try {
    const r = await fetch("/admin/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ u: $("#u").value, p: $("#p").value, fp: await fp() }) });
    const j = await r.json(); if (!r.ok) throw new Error(j.detail);
    csrf = j.csrf; $("#p").value = ""; start();
  } catch (x) { $("#lerr").textContent = x.message; }
};
$("#out").onclick = async () => { try { await api("/logout", "POST"); } catch { } showLogin(); };
$("#theme").onclick = () => { const d = document.body.dataset.theme === "dark"; document.body.dataset.theme = d ? "light" : "dark"; $("#theme").textContent = d ? "Night mode" : "Day mode"; };
$("#burger").onclick = () => $("#side").classList.toggle("open");
$("#mx").onclick = () => $("#modal").hidden = true;
const modal = (t, html) => { $("#mt").textContent = t; $("#mb").innerHTML = html; $("#modal").hidden = false; return $("#mb"); };

const PAGES = { dashboard: "Dashboard", notif: "Notification", dialog: "Dialog", carousel: "Carousel", block: "Block", settings: "Settings", logs: "Admin Logs" };
function start() {
  $("#login").hidden = true; $("#app").hidden = false;
  $("#nav").innerHTML = Object.entries(PAGES).map(([k, v]) => `<a data-p="${k}">${v}</a>`).join("");
  $("#nav").onclick = e => { if (e.target.dataset.p) { go(e.target.dataset.p); $("#side").classList.remove("open"); } };
  clearInterval(tick); left = 900;
  tick = setInterval(() => { left--; $("#timer").textContent = `Session ends in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`; if (left <= 0) showLogin("Session expired"); }, 1000);
  go("dashboard");
}
function go(p) {
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("on", a.dataset.p === p));
  $("#title").textContent = PAGES[p]; $("#view").innerHTML = '<p class="muted">Loading…</p>';
  ({ dashboard, notif: () => items("notif"), dialog: () => items("dialog"), carousel: () => items("carousel"), block, settings, logs }[p])().catch(e => { if (e.message !== "auth") $("#view").innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
const num = n => (n ?? 0).toLocaleString("en-IN");
const rangeBar = cb => `<div class="card row"><span class="muted">Custom range (IST)</span><input type="date" id="rf" value="${range.frm}" style="width:auto"><input type="date" id="rt" value="${range.to}" style="width:auto"><button class="btn blue sm" id="ra">Apply</button></div>`;
function bindRange(cb) { $("#ra").onclick = () => { range = { frm: $("#rf").value, to: $("#rt").value }; cb(); }; }

// ---------- list modal with pagination
async function openList(what, frm, to, title) {
  const box = modal(title, '<div class="tw"><table id="lt"></table></div><div class="row"><button class="btn sm blue" id="more" hidden>Load more</button></div>');
  let cursor = "", first = true;
  const load = async () => {
    const q = new URLSearchParams({ what, frm, to, cursor });
    const r = await api("/list?" + q);
    const rows = r.rows.map(x => `<tr class="lk" data-d="${esc(x.d)}"><td>${esc(x.d)}</td><td>${esc(x.id || x.host || "")}</td><td>${esc(x.ip || "")}</td><td>${IST(x.ts || x.v)}</td><td>${x.c ? "clicked " + IST(x.c) : ""}</td></tr>`).join("");
    if (first) { $("#lt").innerHTML = "<tr><th>Device</th><th>Item/Host</th><th>IP</th><th>Time</th><th>Click</th></tr>"; first = false; }
    $("#lt").insertAdjacentHTML("beforeend", rows || "");
    cursor = r.next || ""; $("#more").hidden = !cursor;
  };
  $("#more").onclick = load; $("#lt").onclick = e => { const tr = e.target.closest(".lk"); if (tr) userLogs(tr.dataset.d); };
  await load();
}
async function userLogs(d) {
  let cursor = "";
  const box = modal("Device " + d.slice(0, 12), '<pre id="di" class="small"></pre><div class="tw"><table id="ul"><tr><th>Time (IST)</th><th>IP</th><th>Event</th><th>Version</th></tr></table></div><button class="btn sm blue" id="um" hidden>Load more</button>');
  const load = async () => {
    const r = await api(`/user?d=${encodeURIComponent(d)}&cursor=${cursor}`);
    if (!cursor) $("#di").textContent = JSON.stringify(r.device, null, 1);
    $("#ul").insertAdjacentHTML("beforeend", r.logs.map(l => `<tr><td>${IST(l.ts)}</td><td>${esc(l.ip)}</td><td>${esc(l.event)}</td><td>${esc(l.vc)}</td></tr>`).join(""));
    cursor = r.next || ""; $("#um").hidden = !cursor;
  };
  $("#um").onclick = load; await load();
}

// ---------- dashboard
async function dashboard() {
  const q = range.frm && range.to ? `?frm=${range.frm}&to=${range.to}` : "";
  const [d, top] = await Promise.all([api("/dashboard" + q), api("/top-users")]);
  const t = new Date(Date.now() + 5.5 * 3600e3).toISOString().slice(0, 10), y = new Date(Date.now() + 5.5 * 3600e3 - 864e5).toISOString().slice(0, 10);
  const cols = [["today", "Today", t, t], ["yesterday", "Yesterday", y, y], ["all", "All time", "all", "all"]];
  if (d.range) cols.push(["range", "Range", range.frm, range.to]);
  const stat = (what, label) => `<div class="grid">${cols.map(([k, n, f, to]) => `<div class="card stat" data-w="${what}" data-f="${f}" data-t="${to}" data-n="${label} · ${n}"><small>${label} · ${n}</small><b>${num(k === "all" && what === "new_users" ? d.total_users : d[k].new_users)}</b></div>`).join("")}</div>`;
  const row = (label, key) => `<tr><td>${label}</td>${cols.map(([k]) => `<td>${num(d[k][key])}</td>`).join("")}</tr>`;
  const head = `<tr><th></th>${cols.map(c => `<th>${c[1]}</th>`).join("")}</tr>`;
  const adKeys = [...new Set(Object.keys(d.all).filter(k => k.startsWith("ad_")))].sort();
  $("#view").innerHTML = rangeBar() + stat("new_users", "New users") +
    `<div class="grid"><div class="card stat" data-w="active" data-f="${y}" data-t="${y}" data-n="Yesterday active"><small>Yesterday users</small><b>${num(d.yesterday_active)}</b></div>
     <div class="card stat" data-w="active" data-f="${t}" data-t="${t}" data-n="Active today"><small>Active today</small><b>${num(d.active_today)}</b></div>
     <div class="card"><small>Yesterday users active today</small><b style="font-size:26px">${num(d.yesterday_active_today)}</b></div></div>
     <div class="card tw"><h3>Fetch</h3><table>${head}${row("Total fetch", "fetch_total")}${row("Success", "fetch_success")}${row("Failed", "fetch_failed")}${row("Admin-blocked hits", "blocked_hits")}</table></div><br>
     <div class="card tw"><h3>Ads (network · type · trigger)</h3><table>${head}${adKeys.map(k => row(k.slice(3).split("_").join(" · "), k)).join("") || '<tr><td class="muted">No data yet</td></tr>'}</table></div><br>
     <div class="card tw"><h3>Top 50 users by fetch</h3><table><tr><th>Device</th><th>IP</th><th>Device info</th><th>Fetch</th><th>Interstitial</th><th>Rewarded</th><th>Ads</th></tr>
     ${top.map(u => `<tr class="lk" data-d="${esc(u.d)}"><td>${esc(u.d.slice(0, 10))}…</td><td>${esc(u.ip)}</td><td>${esc(u.info?.model || "")} ${esc(u.info?.os || "")}</td><td>${u.fetch}</td><td>${u.inter}</td><td>${u.rew}</td><td>${u.ads}</td></tr>`).join("")}</table></div>`;
  bindRange(dashboard);
  $("#view").onclick = e => { const s = e.target.closest(".stat[data-w]"), l = e.target.closest(".lk"); if (s) openList(s.dataset.w, s.dataset.f, s.dataset.t, s.dataset.n); else if (l) userLogs(l.dataset.d); };
}

// ---------- notification / dialog / carousel
const F = {
  notif: [["image", "Image URL"], ["title", "Title"], ["message", "Message", "ta"], ["url", "On-click URL"]],
  dialog: [["image", "Image URL (optional)"], ["message", "Message (text/HTML)", "ta"], ["url", "On-click URL"], ["sort", "Sort order", "n"]],
  carousel: [["image", "Image URL"], ["url", "On-click URL (empty = no redirect)"], ["sort", "Sort order", "n"]],
};
const field = ([k, l, t], v = "") => `<label>${l}</label>${t === "ta" ? `<textarea name="${k}">${esc(v)}</textarea>` : `<input name="${k}" type="${t === "n" ? "number" : "text"}" value="${esc(v)}">`}`;
async function items(kind) {
  const q = range.frm && range.to ? `?frm=${range.frm}&to=${range.to}` : "";
  const r = await api(`/items/${kind}${q}`);
  const st = (n, o) => `<div class="card"><small class="muted">${n}</small><div class="row"><span>Today <b>${num(o.today)}</b></span><span>Yesterday <b>${num(o.yesterday)}</b></span><span>All <b>${num(o.all)}</b></span>${o.range != null ? `<span>Range <b>${num(o.range)}</b></span>` : ""}</div></div>`;
  $("#view").innerHTML = rangeBar() + `<div class="grid">${st("Unique views", r.views)}${st("Unique clicks", r.clicks)}</div>
   <div class="card"><h3>Add new</h3><form id="nf">${F[kind].map(f => field(f)).join("")}<br><button class="btn">${kind === "notif" ? "Send" : "Create"}</button></form></div><br>
   <div class="card tw"><table><tr><th>Preview</th><th>Content</th>${kind !== "notif" ? "<th>Sort</th>" : ""}<th>Views</th><th>Clicks</th><th>Status</th><th></th></tr>
   ${r.rows.map(x => `<tr><td>${x.image ? `<img class="th" src="${esc(x.image)}" alt="">` : ""}</td><td><b>${esc(x.title || "")}</b> ${esc((x.message || "").slice(0, 120))}<br><small class="muted">${esc(x.url || "")}</small></td>${kind !== "notif" ? `<td>${x.sort}</td>` : ""}
   <td>${num(x.views)}</td><td>${num(x.clicks)}</td><td><span class="pill ${x.enabled !== false ? "on-pill" : ""}">${x.enabled !== false ? "Enabled" : "Disabled"}</span></td>
   <td class="row" data-id="${x.id}"><button class="btn sm blue" data-a="users">Users</button><button class="btn sm ghost" data-a="edit">Edit</button><button class="btn sm ghost" data-a="tog">${x.enabled !== false ? "Disable" : "Enable"}</button><button class="btn sm red" data-a="del">Delete</button></td></tr>`).join("")}</table></div>`;
  bindRange(() => items(kind));
  $("#nf").onsubmit = async e => { e.preventDefault(); try { await api(`/items/${kind}`, "POST", Object.fromEntries(new FormData(e.target))); items(kind); } catch (x) { toast(x.message); } };
  $("#view").onclick = async e => {
    const b = e.target.closest("button[data-a]"); if (!b) return; const id = b.parentElement.dataset.id, x = r.rows.find(z => z.id === id);
    try {
      if (b.dataset.a === "del" && confirm("Delete?")) { await api(`/items/${kind}/${id}`, "DELETE"); items(kind); }
      if (b.dataset.a === "tog") { await api(`/items/${kind}/${id}/toggle`, "POST"); items(kind); }
      if (b.dataset.a === "users") usersOf(kind, id);
      if (b.dataset.a === "edit") {
        const m = modal("Edit", `<form id="ef">${F[kind].map(f => field(f, x[f[0]])).join("")}<br><button class="btn">Save</button></form>`);
        $("#ef").onsubmit = async ev => { ev.preventDefault(); try { await api(`/items/${kind}/${id}`, "PUT", Object.fromEntries(new FormData(ev.target))); $("#modal").hidden = true; items(kind); } catch (z) { toast(z.message); } };
      }
    } catch (z) { toast(z.message); }
  };
}
async function usersOf(kind, id) {
  let cursor = ""; modal("Seen / clicked by", '<div class="tw"><table id="iu"><tr><th>Device</th><th>Seen</th><th>Clicked</th></tr></table></div><button class="btn sm blue" id="im" hidden>Load more</button>');
  const load = async () => { const r = await api(`/items/${kind}/${id}/users?cursor=${cursor}`); $("#iu").insertAdjacentHTML("beforeend", r.rows.map(u => `<tr><td>${esc(u.d)}</td><td>${IST(u.v)}</td><td>${IST(u.c)}</td></tr>`).join("")); cursor = r.next || ""; $("#im").hidden = !cursor; };
  $("#im").onclick = load; await load();
}

// ---------- block
async function block() {
  const q = range.frm && range.to ? `?frm=${range.frm}&to=${range.to}` : "";
  const r = await api("/block" + q), t = new Date(Date.now() + 5.5 * 3600e3).toISOString().slice(0, 10);
  $("#view").innerHTML = rangeBar() + `<div class="card row">Blocked-domain hits: <span>Today <b>${num(r.hits.today)}</b></span><span>Yesterday <b>${num(r.hits.yesterday)}</b></span><span>All <b>${num(r.hits.all)}</b></span>${r.hits.range != null ? `<span>Range <b>${num(r.hits.range)}</b></span>` : ""}
   <button class="btn sm blue" id="bh">Users (today)</button><button class="btn sm ghost" id="bha">Users (range)</button></div><br>
   <div class="card"><h3>Block domains</h3><form id="bf"><label>Domains (one per line or comma separated)</label><textarea name="domains" placeholder="example.com&#10;other.com"></textarea><label>Message shown to users (text/HTML)</label><textarea name="message"></textarea><br><button class="btn">Add to block</button></form></div><br>
   <div class="card tw"><table><tr><th>Domain</th><th>Message</th><th>Since</th><th></th></tr>${r.rows.map(x => `<tr><td>${esc(x.domain)}</td><td>${esc(x.message.slice(0, 100))}</td><td>${IST(x.ts)}</td><td><button class="btn sm red" data-k="${esc(x.domain.replace(/\./g, ","))}">Unblock</button></td></tr>`).join("")}</table></div>`;
  bindRange(block);
  $("#bh").onclick = () => openList("blocked", t, t, "Blocked hits today");
  $("#bha").onclick = () => range.frm && openList("blocked", range.frm, range.to, "Blocked hits range");
  $("#bf").onsubmit = async e => { e.preventDefault(); try { await api("/block", "POST", Object.fromEntries(new FormData(e.target))); block(); } catch (x) { toast(x.message); } };
  $("#view").onclick = async e => { const b = e.target.closest("button[data-k]"); if (b && confirm("Unblock?")) { await api("/block/" + b.dataset.k, "DELETE"); block(); } };
}

// ---------- settings
function form(obj, id) {
  return Object.entries(obj).map(([k, v]) => {
    if (typeof v === "boolean") return `<label><input type="checkbox" name="${k}" ${v ? "checked" : ""} style="width:auto"> ${k}</label>`;
    if (typeof v === "number") return `<label>${k}</label><input type="number" name="${k}" value="${v}">`;
    if (typeof v === "object") return `<label>${k} (JSON)</label><textarea name="${k}" data-json="1" style="min-height:140px">${esc(JSON.stringify(v, null, 1))}</textarea>`;
    return `<label>${k}</label>${String(v).length > 70 || k.endsWith("html") ? `<textarea name="${k}">${esc(v)}</textarea>` : `<input name="${k}" value="${esc(v)}">`}`;
  }).join("");
}
async function settings() {
  const s = await api("/settings"), m = await api("/maintenance-stats" + (range.frm && range.to ? `?frm=${range.frm}&to=${range.to}` : ""));
  const sec = (k, t, extra = "") => `<div class="card"><h3>${t}</h3>${extra}<form data-s="${k}">${form(s[k])}<br><button class="btn">Save ${t}</button></form></div><br>`;
  $("#view").innerHTML = rangeBar() + sec("app", "App config, legal, developer, theme (day/night: set theme=light|dark)") + sec("ads", "Ads (Start.io / Monetag)") +
    sec("maintenance", "Maintenance mode", `<p class="muted">App opens during maintenance — Today <b>${num(m.today)}</b> · Yesterday <b>${num(m.yesterday)}</b> · All <b>${num(m.all)}</b>${m.range != null ? ` · Range <b>${num(m.range)}</b>` : ""} <button class="btn sm blue" id="mu">Users today</button></p>`) +
    `<div class="card"><h3>Supported apps / platforms (JSON list: name, url, icon, sort, highlight)</h3><form data-s="supported_apps"><textarea name="x" data-json="1" style="min-height:220px">${esc(JSON.stringify(s.supported_apps, null, 1))}</textarea><br><button class="btn">Save apps</button></form></div>`;
  bindRange(settings);
  const t = new Date(Date.now() + 5.5 * 3600e3).toISOString().slice(0, 10);
  $("#mu").onclick = () => openList("maint", t, t, "Maintenance opens today");
  document.querySelectorAll("form[data-s]").forEach(f => f.onsubmit = async e => {
    e.preventDefault(); const sec = f.dataset.s, orig = s[sec], out = {};
    try {
      if (sec === "supported_apps") out.v = JSON.parse(f.x.value);
      else for (const [k, v] of Object.entries(orig)) { const el = f.elements[k]; out[k] = typeof v === "boolean" ? el.checked : typeof v === "number" ? Number(el.value) : el.dataset.json ? JSON.parse(el.value) : el.value; }
      await api("/settings/" + sec, "PUT", sec === "supported_apps" ? out.v : out); toast("Saved & live");
    } catch (x) { toast(x.message); }
  });
}
async function logs() {
  const r = await api("/admin-logs");
  $("#view").innerHTML = `<div class="card tw"><table><tr><th>Time (IST)</th><th>Type</th><th>IP</th><th>Detail</th></tr>${r.rows.map(l => `<tr><td>${IST(l.ts)}</td><td>${esc(l.type)}${l.ok === false ? " ❌" : l.ok ? " ✅" : ""}</td><td>${esc(l.ip)}</td><td>${esc(JSON.stringify({ ...l, ts: undefined, type: undefined, ip: undefined }))}</td></tr>`).join("")}</table></div>`;
}
api("/me").then(r => { csrf = r.csrf; start(); }).catch(() => showLogin());
