/* Cyber Sentinel dashboard - vanilla JS over the JSON API + websocket. */
"use strict";

const SEV_COLORS = {
  critical: "#ff4d6d", high: "#ff9f43", medium: "#ffd166",
  low: "#4cc9f0", info: "#8b93a7",
};
const FEED_CAP = 250;
let alertOrder = [];
let statusFilter = "all";
let drawerAlertId = null;

const $ = (id) => document.getElementById(id);

function fmtTime(iso) {
  if (!iso) return "";
  const t = iso.includes("T") ? iso.split("T")[1] : iso;
  return t.slice(0, 8);
}
function toast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2600);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

async function loadStats() {
  const s = await api("/api/stats");
  $("stEvents").textContent = s.events;
  $("stAlerts").textContent = s.alerts;
  const hc = (s.alerts_by_severity.high || 0) + (s.alerts_by_severity.critical || 0);
  $("stHigh").textContent = hc;
  const top = s.top_risk_sources[0];
  $("stTop").textContent = top ? `${top.key} (${top.score})` : "-";
}

async function loadAlerts() {
  const q = statusFilter === "all" ? "" : `&status=${statusFilter}`;
  const alerts = await api(`/api/alerts?limit=100${q}`);
  alertOrder = alerts.map((a) => a.id);
  const box = $("alerts");
  box.innerHTML = "";
  $("alertCount").textContent = statusFilter === "all" ? "" : `${alerts.length} ${statusFilter}`;
  if (!alerts.length) {
    box.innerHTML = '<div class="empty">No alerts here yet. Replay a scenario to watch detection work.</div>';
    return;
  }
  for (const a of alerts) box.appendChild(alertCard(a));
}

function alertCard(a) {
  const el = document.createElement("div");
  el.className = `alert sev-${a.severity}`;
  el.dataset.id = a.id;
  const color = SEV_COLORS[a.severity] || SEV_COLORS.info;
  el.innerHTML = `
    <div class="top">
      <span class="title">${esc(a.title)}</span>
      <span class="chip ${a.severity}">${a.severity}</span>
    </div>
    <div class="meta"><span>${esc(a.key)}</span><span>${fmtTime(a.last_seen)}</span></div>
    <div class="scorebar"><div style="width:${a.score}%;background:${color}"></div></div>
    ${a.status && a.status !== "open" ? `<div class="stbadge st-${a.status}">${a.status}</div>` : ""}`;
  el.onclick = () => openAlert(a.id);
  return el;
}

async function upsertAlert(a) {
  const box = $("alerts");
  const empty = box.querySelector(".empty");
  if (empty) empty.remove();
  const existing = box.querySelector(`[data-id="${a.id}"]`);
  if (statusFilter !== "all" && a.status !== statusFilter) {
    if (existing) existing.remove();
    loadStats();
    return;
  }
  const card = alertCard(a);
  if (existing) existing.replaceWith(card);
  else box.prepend(card);
  loadStats();
}

async function setStatus(id, status) {
  const r = await api(`/api/alerts/${id}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (r.error) { toast(r.error); return; }
  toast(`alert ${id} marked ${status}`);
  loadAlerts();
  loadStats();
  if (drawerAlertId === id) openAlert(id);
}

async function openAlert(id) {
  const a = await api(`/api/alerts/${id}`);
  if (a.error) return;
  drawerAlertId = id;
  location.hash = `alert=${id}`;
  const color = SEV_COLORS[a.severity] || SEV_COLORS.info;
  const actions =
    a.status === "open"
      ? `<button data-st="acknowledged">acknowledge</button><button data-st="resolved">resolve</button>`
      : a.status === "acknowledged"
        ? `<button data-st="resolved">resolve</button><button data-st="open">reopen</button>`
        : `<button data-st="open">reopen</button>`;
  const signals = a.signals
    .map((s) => `
      <div class="signal">
        <div class="stitle"><span>${esc(s.title)}</span><span class="pts">+${s.points}</span></div>
        <div class="bar"><div style="width:${s.points}%"></div></div>
        <div class="expl">${esc(s.explanation)}</div>
        ${s.evidence.length ? `<div class="evidence">${esc(s.evidence.join("\n"))}</div>` : ""}
      </div>`)
    .join("");
  $("drawerBody").innerHTML = `
    <h3>${esc(a.title)}</h3>
    <div class="sub">source ${esc(a.key)} &middot; first ${fmtTime(a.first_seen)} &middot; last ${fmtTime(a.last_seen)}</div>
    <div class="bigscore">
      <span class="val" style="color:${color}">${a.score}</span>
      <span class="chip ${a.severity}">${a.severity}</span>
      <span class="chip stchip st-${a.status}">${a.status}</span>
    </div>
    <div class="triage">${actions}</div>
    ${signals}
    <div class="note">The score is a sum of the rule points above, capped at 100.
    It is not a probability. Each point value comes from a named detection rule.
    Triage state is local to this demo instance.</div>`;
  for (const b of $("drawerBody").querySelectorAll(".triage button")) {
    b.onclick = () => setStatus(id, b.dataset.st);
  }
  $("drawer").classList.add("open");
  $("overlay").classList.add("show");
}

function closeDrawer() {
  drawerAlertId = null;
  $("drawer").classList.remove("open");
  $("overlay").classList.remove("show");
}

function feedRow(ev) {
  const row = document.createElement("div");
  row.className = `row k-${ev.kind}`;
  row.innerHTML = `<span class="ts">${fmtTime(ev.ts)}</span>${esc(ev.raw.split("]: ")[1] || ev.raw)}`;
  return row;
}

async function loadEvents() {
  const events = await api("/api/events?limit=80");
  const feed = $("feed");
  feed.innerHTML = "";
  for (const ev of events) feed.appendChild(feedRow(ev)); // API returns newest first
  $("feedCount").textContent = `${events.length} shown, arrival order, newest first (row times are event times)`;
}

function addFeedEvent(ev) {
  const feed = $("feed");
  feed.prepend(feedRow(ev));
  while (feed.children.length > FEED_CAP) feed.removeChild(feed.lastChild);
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

async function loadScenarios() {
  const list = await api("/api/scenarios");
  const box = $("scenarioButtons");
  for (const sc of list) {
    const b = document.createElement("button");
    b.textContent = sc.name;
    b.title = sc.description;
    b.onclick = async () => {
      b.disabled = true;
      const r = await api(`/api/replay/${sc.name}?speed=40`, { method: "POST" });
      toast(r.error || `replaying ${sc.name} (${r.lines} lines)`);
      setTimeout(() => (b.disabled = false), 4000);
    };
    box.appendChild(b);
  }
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    $("dot").classList.add("live");
    $("connText").textContent = "live";
  };
  ws.onclose = () => {
    $("dot").classList.remove("live");
    $("connText").textContent = "reconnecting";
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.type === "event") { addFeedEvent(msg.data); }
    if (msg.type === "alert") { upsertAlert(msg.data); }
    if (msg.type === "alert_status") {
      const card = $("alerts").querySelector(`[data-id="${msg.data.id}"]`);
      if (card) {
        if (statusFilter !== "all" && msg.data.status !== statusFilter) card.remove();
        else api(`/api/alerts/${msg.data.id}`).then((a) => { if (!a.error) upsertAlert(a); });
      }
      loadStats();
    }
    if (msg.type === "reset") {
      closeDrawer();
      loadStats(); loadAlerts(); loadEvents();
      toast("demo data reset");
    }
  };
}

setInterval(() => {
  $("clock").textContent = new Date().toLocaleTimeString("en-GB");
}, 1000);

$("drawerClose").onclick = closeDrawer;
$("overlay").onclick = closeDrawer;
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

$("resetDemo").onclick = async () => {
  if (!confirm("Delete ALL stored synthetic demo data (events, alerts) and reset detectors?")) return;
  const r = await api("/api/demo/reset", { method: "POST" });
  if (r.reset) { closeDrawer(); loadStats(); loadAlerts(); loadEvents(); toast("demo data reset"); }
};

$("statusFilter").addEventListener("click", (e) => {
  const b = e.target.closest(".fchip");
  if (!b) return;
  statusFilter = b.dataset.status;
  for (const c of $("statusFilter").querySelectorAll(".fchip")) {
    c.classList.toggle("active", c === b);
  }
  loadAlerts();
});

loadStats();
loadAlerts().then(() => {
  const m = location.hash.match(/^#alert=(\d+)$/);
  if (m) openAlert(Number(m[1]));
});
loadEvents();
loadScenarios();
connectWs();
