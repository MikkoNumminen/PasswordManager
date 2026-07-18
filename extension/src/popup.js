// Popup UI. Holds no crypto: it asks the service worker to unlock and to
// decrypt one entry at a time, and it decides which entries match the current
// tab (registrable-domain matching via the PSL).

import { matchLevel, hostOf, loadRuleset } from "./psl.js";

const $ = (id) => document.getElementById(id);
const show = (id) => $(id).classList.remove("hidden");
const hide = (id) => $(id).classList.add("hidden");

let tab = null;
let tabHost = "";
let ruleset = null;
let index = [];

function send(message) {
  return chrome.runtime.sendMessage({ target: "background", ...message });
}

async function currentTab() {
  const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
  return t;
}

async function boot() {
  tab = await currentTab();
  tabHost = hostOf(tab?.url || "");
  ruleset = await loadRuleset();

  checkUpdate(); // fire and forget; the banner appears if a newer build exists

  const state = await send({ type: "getState" });
  if (!state.configured) {
    show("needs-config");
    $("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());
    return;
  }
  if (state.locked) {
    showLocked();
  } else {
    await showVault();
  }
}

function showLocked() {
  hide("vault");
  show("locked");
  $("master").focus();
}

$("unlock").addEventListener("click", unlock);
$("master").addEventListener("keydown", (e) => {
  if (e.key === "Enter") unlock();
});

async function unlock() {
  const password = $("master").value;
  if (!password) return;
  $("unlock-status").textContent = "Deriving key...";
  $("unlock-status").classList.remove("error");
  const res = await send({ type: "unlock", password });
  $("master").value = "";
  if (res.authRequired) return showAuth();
  if (res.error) {
    $("unlock-status").textContent = res.error;
    $("unlock-status").classList.add("error");
    return;
  }
  hide("locked");
  await showVault();
}

async function checkUpdate() {
  const r = await send({ type: "checkUpdate" });
  if (!r || !r.behind) return;
  $("update").textContent =
    `Update available: v${r.latest} (you have v${r.current}). ` +
    `Pull the repo, run build.ps1, and reload the extension.`;
  show("update");
}

function showAuth() {
  hide("locked");
  hide("vault");
  show("needs-auth");
  $("open-server").addEventListener("click", async () => {
    const { serverUrl } = await chrome.storage.local.get("serverUrl");
    if (serverUrl) chrome.tabs.create({ url: serverUrl });
  });
}

async function showVault() {
  const res = await send({ type: "list" });
  if (res.authRequired) return showAuth();
  if (res.locked) return showLocked();
  index = res.index || [];
  show("vault");
  $("scope").textContent = tabHost ? `for ${tabHost}` : "";
  render();
}

$("search").addEventListener("input", render);
$("all-sites").addEventListener("change", render);
$("lock").addEventListener("click", async () => {
  await send({ type: "lock" });
  window.close();
});

function matching() {
  const all = $("all-sites").checked;
  const q = $("search").value.trim().toLowerCase();
  let rows = index.map((e) => ({ e, level: matchLevel(tabHost, hostOf(e.url), ruleset) }));
  if (!all) rows = rows.filter((r) => r.level !== "none");
  if (q) {
    rows = rows.filter(
      (r) =>
        r.e.title.toLowerCase().includes(q) ||
        (r.e.username || "").toLowerCase().includes(q) ||
        (r.e.url || "").toLowerCase().includes(q)
    );
  }
  // exact-domain matches first, then subdomain, then the rest.
  const rank = { exact: 0, subdomain: 1, none: 2 };
  rows.sort((a, b) => rank[a.level] - rank[b.level] || a.e.title.localeCompare(b.e.title));
  return rows;
}

function render() {
  const list = $("list");
  list.replaceChildren();
  const rows = matching();
  $("empty").classList.toggle("hidden", rows.length > 0 || $("all-sites").checked);
  for (const { e, level } of rows) {
    list.appendChild(entryRow(e, level));
  }
}

function button(label, cls, onClick) {
  const b = document.createElement("button");
  b.className = cls;
  b.textContent = label;
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

function entryRow(e, level) {
  const row = document.createElement("div");
  row.className = "entry";

  const title = document.createElement("div");
  title.className = "title";
  title.textContent = e.title + (level === "exact" ? "  ✓" : "");
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = [e.username, hostOf(e.url)].filter(Boolean).join("  ·  ");
  const pw = document.createElement("div");
  pw.className = "pw sub";
  pw.textContent = "••••••";

  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(
    button("fill", "small", () => fill(e)),
    button("reveal", "small", async () => {
      if (pw.dataset.shown === "yes") {
        pw.textContent = "••••••";
        pw.dataset.shown = "no";
        return;
      }
      const r = await send({ type: "reveal", id: e.id });
      if (r.error) return note(row, r.error, true);
      pw.textContent = r.password || "(empty)";
      pw.dataset.shown = "yes";
    }),
    button("copy pw", "small", () => copy(e.id, "password", row)),
    button("copy user", "small", () => copy(e.id, "username", row))
  );

  row.append(title, sub, pw, actions);
  return row;
}

async function copy(id, field, row) {
  const r = await send({ type: "reveal", id });
  if (r.error) return note(row, r.error, true);
  const value = field === "password" ? r.password : r.username;
  try {
    await navigator.clipboard.writeText(value || "");
    if (field === "password") await send({ type: "clipboardCopied", value });
    note(row, field === "password" ? "copied, clears in 30s" : "copied");
  } catch {
    note(row, "clipboard unavailable", true);
  }
}

async function fill(e, confirmedMismatch = false) {
  const res = await send({
    type: "fill",
    id: e.id,
    tabId: tab.id,
    tabHost,
    confirmedMismatch,
  });
  if (res.authRequired) return showAuth();
  if (res.mismatch) return confirmMismatch(e, res);
  if (res.error) return noteGlobal(res.error, true);
  if (!res.foundPassword) return noteGlobal("no password field found on this page", true);
  noteGlobal(`filled${res.filledUser ? " username and" : ""} password`, false);
}

// The anti-phishing moment: an entry whose domain does not match the page.
function confirmMismatch(e, res) {
  const banner = document.createElement("div");
  banner.className = "warn";
  banner.textContent =
    `This entry is for ${res.entryHost || "another site"}, but this page is ` +
    `${res.tabHost || "unknown"}. Filling here could hand your credentials to ` +
    `the wrong site.`;
  const yes = button("Fill anyway", "small", () => {
    banner.remove();
    fill(e, true);
  });
  const no = button("Cancel", "small", () => banner.remove());
  const actions = document.createElement("div");
  actions.className = "actions";
  actions.append(no, yes);
  banner.appendChild(actions);
  $("list").prepend(banner);
}

function note(row, text, isError) {
  let n = row.querySelector(".rownote");
  if (!n) {
    n = document.createElement("div");
    n.className = "rownote muted";
    row.appendChild(n);
  }
  n.textContent = text;
  n.classList.toggle("error", !!isError);
  setTimeout(() => n.remove(), 3000);
}

function noteGlobal(text, isError) {
  const n = document.createElement("p");
  n.className = isError ? "error" : "muted";
  n.textContent = text;
  $("list").prepend(n);
  setTimeout(() => n.remove(), 3500);
}

boot();
