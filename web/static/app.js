// PasswordManager web client. All crypto happens in the wasm module built
// from the same Rust core as the CLI, running inside a Web Worker so the
// multi-second key derivation never freezes this page. This file only moves
// ciphertext and renders what the worker decrypts.
//
// API paths mirror core/src/api.rs; change both together.

let credential = null; // API token; authorizes ciphertext access only.
let metaJson = null; // Cleartext vault metadata (salt, KDF params, key check).
let editingEntry = null; // the decrypted entry being edited, or null when adding

const $ = (id) => document.getElementById(id);
const show = (id) => $(id).classList.remove("hidden");
const hide = (id) => $(id).classList.add("hidden");

// ---- crypto worker ----------------------------------------------------

const worker = new Worker("./worker.js", { type: "module" });
let nextCallId = 1;
const pending = new Map();

worker.onmessage = (event) => {
  const msg = event.data;
  const call = pending.get(msg.id);
  if (!call) return;
  pending.delete(msg.id);
  if (msg.ok) call.resolve(msg.result);
  else call.reject(new Error(msg.error));
};

// A worker that fails to load (missing or stale pkg/ build) would otherwise
// leave every pending call hanging forever with no visible error.
function failAllPending(reason) {
  for (const call of pending.values()) {
    call.reject(new Error(reason));
  }
  pending.clear();
}
worker.onerror = () =>
  failAllPending("crypto module failed to load; rebuild web/static/pkg per the README");
worker.onmessageerror = () => failAllPending("crypto worker message failed");

function callWorker(message) {
  return new Promise((resolve, reject) => {
    const id = nextCallId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, ...message });
  });
}

// ---- server API --------------------------------------------------------

async function api(path) {
  // no-store: these are live, per-request vault reads. Without it the browser
  // could serve a cached entries list right after a save and hide the change.
  const resp = await fetch(path, {
    headers: { Authorization: `Bearer ${credential}` },
    cache: "no-store",
  });
  if (!resp.ok) {
    throw new Error(`${path} answered ${resp.status}`);
  }
  return resp.text();
}

// A URL is safe to place in href only if it parses and uses http(s). Anything
// else (javascript:, data:, blob:, relative junk) is shown as plain text.
function isSafeUrl(value) {
  try {
    const scheme = new URL(value).protocol;
    return scheme === "http:" || scheme === "https:";
  } catch {
    return false;
  }
}

// The page knows exactly one credential: the API token, which authorizes
// ciphertext access only (no role in key derivation). It is remembered in
// this browser's localStorage so it is entered once per device; the master
// password is never stored and is required on every unlock.
const TOKEN_KEY = "pm_token";
// Bumped on every client change; shown in the footer so a stale cached
// client is immediately recognizable.
const CLIENT_VERSION = "client v5 (edit password)";

// Some browser modes (private windows, clear-on-close settings) silently
// drop or block localStorage. Probe it so the page can say so plainly
// instead of appearing to forget the token.
function storageWorks() {
  try {
    localStorage.setItem("pm_probe", "1");
    const ok = localStorage.getItem("pm_probe") === "1";
    localStorage.removeItem("pm_probe");
    return ok;
  } catch {
    return false;
  }
}

function authNote(text, isError) {
  $("auth-status").textContent = text;
  $("auth-status").classList.toggle("error", !!isError);
}

function boot() {
  const ver = document.createElement("p");
  ver.className = "muted";
  ver.textContent = CLIENT_VERSION;
  document.body.appendChild(ver);

  $("token-go").addEventListener("click", () => {
    const token = $("token").value.trim();
    if (token) onAuthed(token);
  });
  $("token").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("token-go").click();
  });

  if (!storageWorks()) {
    show("token-login");
    authNote(
      "This browser is blocking site storage (private window, or a " +
        "clear-data-on-close setting), so the token cannot be remembered " +
        "here. It will work, but asks every visit.",
      true
    );
    return;
  }
  const saved = localStorage.getItem(TOKEN_KEY);
  if (saved) {
    onAuthed(saved); // straight past the token step to the master password
  } else {
    show("token-login");
    authNote("No saved token on this device yet. Enter it once; after that this step disappears.");
  }
}

async function onAuthed(value) {
  credential = value;
  $("auth-status").classList.remove("error");
  $("auth-status").textContent = "Checking access...";
  let resp;
  try {
    resp = await fetch("/api/v1/vault", {
      headers: { Authorization: `Bearer ${value}` },
      cache: "no-store",
    });
  } catch (e) {
    // A thrown fetch here is usually not the token at all: an expired Google
    // session makes the gate redirect the request off-origin, which this
    // page's CSP blocks. A full reload renews the Google session. The saved
    // token is kept.
    authNote(
      `Cannot reach the server (${e.message ?? e}). Reload the page; if your ` +
        "Google session expired, the reload renews it.",
      true
    );
    show("token-login");
    credential = null;
    return;
  }
  if (resp.status === 401) {
    // A stale/wrong token: forget it and ask again.
    localStorage.removeItem(TOKEN_KEY);
    credential = null;
    $("token").value = "";
    show("token-login");
    $("auth-status").textContent = "Token was rejected. Enter it again.";
    $("auth-status").classList.add("error");
    return;
  }
  if (resp.status === 404) {
    // Token is valid, but no vault has been synced to this server yet.
    localStorage.setItem(TOKEN_KEY, value);
    show("token-login");
    $("auth-status").textContent =
      "No vault on this server yet. Create one with the CLI and run sync, then reload.";
    $("auth-status").classList.add("error");
    return;
  }
  if (!resp.ok) {
    $("auth-status").textContent = `No access: ${resp.status}`;
    $("auth-status").classList.add("error");
    show("token-login");
    credential = null;
    return;
  }
  metaJson = await resp.text();
  localStorage.setItem(TOKEN_KEY, value); // remember for next visit
  hide("auth");
  show("unlock");
  $("master").focus();
}

async function unlock() {
  const password = $("master").value;
  if (!password) return;
  $("unlock-status").classList.remove("error");
  // Report the parameters the vault actually stores, never a hardcoded guess.
  let kdfLabel = "Deriving key with Argon2id...";
  try {
    const kdf = JSON.parse(metaJson).kdf;
    kdfLabel = `Deriving key (Argon2id, ${Math.round(kdf.m_cost_kib / 1024)} MiB, ${kdf.t_cost} passes)...`;
  } catch {
    // metaJson is server-provided; fall back to the generic label.
  }
  $("unlock-status").textContent = kdfLabel;
  // The entries download runs while the worker grinds through the KDF.
  const entriesPromise = api("/api/v1/entries");
  try {
    await callWorker({ type: "unlock", metaJson, password });
    $("master").value = "";
    const recordsJson = await entriesPromise;
    const entries = JSON.parse(await callWorker({ type: "decrypt", recordsJson }));
    render(entries);
    hide("unlock");
    show("vault");
  } catch (e) {
    entriesPromise.catch(() => {}); // surfaced via the unlock error instead
    $("unlock-status").textContent =
      e.message === "wrong-password"
        ? "Wrong master password."
        : `Unlock failed: ${e.message ?? e}`;
    $("unlock-status").classList.add("error");
  }
}

// A small "did it" button that reverts its label after a moment.
function flashButton(btn, done) {
  const label = btn.textContent;
  btn.textContent = done;
  setTimeout(() => (btn.textContent = label), 1200);
}

async function copyText(btn, text) {
  try {
    await navigator.clipboard.writeText(text);
    flashButton(btn, "copied");
  } catch {
    flashButton(btn, "no clipboard");
  }
}

function actionButton(label, cls, onClick) {
  const b = document.createElement("button");
  b.className = cls;
  b.type = "button";
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}

function render(entries) {
  const tbody = $("entries");
  tbody.replaceChildren();
  for (const entry of entries) {
    const row = document.createElement("tr");

    const title = document.createElement("td");
    title.textContent = entry.title;
    const user = document.createElement("td");
    user.textContent = entry.username;
    const pass = document.createElement("td");
    pass.textContent = "••••••";
    pass.dataset.revealed = "no";
    const url = document.createElement("td");
    if (entry.url) {
      // Only render http(s) URLs as live links. A stored javascript: or data:
      // URL in an entry would otherwise execute in this origin on click and
      // exfiltrate every decrypted entry in the DOM.
      if (isSafeUrl(entry.url)) {
        const a = document.createElement("a");
        a.href = entry.url;
        a.textContent = entry.url;
        a.rel = "noreferrer noopener";
        a.target = "_blank";
        url.appendChild(a);
      } else {
        url.textContent = entry.url;
      }
    }

    const actions = document.createElement("td");
    actions.className = "row-actions";
    const reveal = actionButton("reveal", "small", () => {
      const hidden = pass.dataset.revealed === "no";
      pass.textContent = hidden ? entry.password : "••••••";
      pass.dataset.revealed = hidden ? "yes" : "no";
      reveal.textContent = hidden ? "hide" : "reveal";
    });
    const copyPass = actionButton("copy pw", "small", (e) => copyText(e.target, entry.password));
    const copyUser = actionButton("copy user", "small", (e) => copyText(e.target, entry.username));
    const edit = actionButton("edit", "small", () => openEditor(entry));
    const del = actionButton("delete", "small danger", () => deleteEntry(entry));
    actions.append(reveal, " ", copyPass, " ", copyUser, " ", edit, " ", del);

    row.append(title, user, pass, url, actions);
    tbody.appendChild(row);
  }
}

// ---- add / edit / delete ---------------------------------------------------

// Re-fetch every record and re-render. Called after any write so the view
// always reflects what the server actually holds.
async function refresh() {
  const recordsJson = await api("/api/v1/entries");
  render(JSON.parse(await callWorker({ type: "decrypt", recordsJson })));
}

function openEditor(entry) {
  editingEntry = entry || null;
  $("editor-title").textContent = entry ? "Edit entry" : "Add entry";
  $("f-title").value = entry ? entry.title : "";
  $("f-username").value = entry ? entry.username : "";
  $("f-password").value = entry ? entry.password : "";
  $("f-password").type = "password";
  $("f-url").value = entry ? entry.url : "";
  $("f-notes").value = entry ? entry.notes : "";
  $("editor-status").textContent = "";
  $("editor-status").classList.remove("error");
  hide("vault");
  show("editor");
  $("f-title").focus();
}

function closeEditor() {
  editingEntry = null;
  hide("editor");
  show("vault");
}

async function putRecord(entryId, recordJson) {
  const resp = await fetch(`/api/v1/entries/${entryId}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" },
    body: recordJson,
  });
  if (resp.status === 409) {
    throw new Error("this entry changed on the server; lock, reopen, and try again");
  }
  if (!resp.ok) {
    throw new Error(`save failed (${resp.status})`);
  }
}

async function saveEntry() {
  const title = $("f-title").value.trim();
  if (!title) {
    $("editor-status").textContent = "a title is required";
    $("editor-status").classList.add("error");
    return;
  }
  const entryId = editingEntry ? editingEntry.id : crypto.randomUUID();
  const createdMs = editingEntry ? editingEntry.created_ms : Date.now();
  // The timestamp must strictly increase per entry for last-write-wins sync.
  const prev = editingEntry ? editingEntry.modified_ms : 0;
  const modifiedMs = Math.max(Date.now(), prev + 1);
  const password = $("f-password").value;
  // Safety net: never let an empty field silently wipe an existing password
  // (e.g. if the browser cleared it, or a mis-click).
  if (editingEntry && editingEntry.password && !password) {
    if (!confirm("The password field is empty, but this entry has a password. Save with no password?")) {
      return;
    }
  }
  const data = {
    title,
    username: $("f-username").value,
    password,
    url: $("f-url").value,
    notes: $("f-notes").value,
    created_ms: createdMs,
  };
  $("editor-status").textContent = "saving...";
  $("editor-status").classList.remove("error");
  try {
    const recordJson = await callWorker({
      type: "seal",
      entryId,
      modifiedMs,
      dataJson: JSON.stringify(data),
    });
    await putRecord(entryId, recordJson);
    closeEditor();
    await refresh();
  } catch (e) {
    $("editor-status").textContent = `could not save: ${e.message ?? e}`;
    $("editor-status").classList.add("error");
  }
}

async function deleteEntry(entry) {
  if (!confirm(`Delete "${entry.title}"?`)) return;
  const modifiedMs = Math.max(Date.now(), entry.modified_ms + 1);
  try {
    const recordJson = await callWorker({ type: "tombstone", entryId: entry.id, modifiedMs });
    await putRecord(entry.id, recordJson);
    await refresh();
  } catch (e) {
    alert(`could not delete: ${e.message ?? e}`);
  }
}

// Strong password from the browser CSPRNG, uniform over the charset.
function generatePassword(len = 20) {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
  const limit = 256 - (256 % charset.length);
  const out = [];
  while (out.length < len) {
    const buf = new Uint8Array(len);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < limit) {
        out.push(charset[b % charset.length]);
        if (out.length === len) break;
      }
    }
  }
  return out.join("");
}

// ---- wiring ----------------------------------------------------------------

$("unlock-go").addEventListener("click", unlock);
$("master").addEventListener("keydown", (e) => {
  if (e.key === "Enter") unlock();
});
$("lock").addEventListener("click", async () => {
  try {
    await callWorker({ type: "lock" });
  } finally {
    location.reload();
  }
});
$("forget-token").addEventListener("click", () => {
  localStorage.removeItem(TOKEN_KEY);
  location.reload();
});
$("add").addEventListener("click", () => openEditor(null));
$("editor-save").addEventListener("click", saveEntry);
$("editor-cancel").addEventListener("click", closeEditor);
$("f-show").addEventListener("click", () => {
  const f = $("f-password");
  f.type = f.type === "password" ? "text" : "password";
});
$("f-gen").addEventListener("click", () => {
  $("f-password").value = generatePassword();
  $("f-password").type = "text";
});

boot();
