// PasswordManager web client. All crypto happens in the wasm module built
// from the same Rust core as the CLI, running inside a Web Worker so the
// multi-second key derivation never freezes this page. This file only moves
// ciphertext and renders what the worker decrypts.
//
// API paths mirror core/src/api.rs; change both together.

let credential = null; // Google ID token or API token; authorizes blob access only.
let metaJson = null; // Cleartext vault metadata (salt, KDF params, key check).

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
  const resp = await fetch(path, {
    headers: { Authorization: `Bearer ${credential}` },
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

async function boot() {
  const cfg = await (await fetch("/api/v1/webconfig")).json();
  if (cfg.google_client_id) {
    show("google-signin");
    const gsi = document.createElement("script");
    gsi.src = "https://accounts.google.com/gsi/client";
    gsi.onload = () => {
      google.accounts.id.initialize({
        client_id: cfg.google_client_id,
        callback: (resp) => onAuthed(resp.credential),
      });
      google.accounts.id.renderButton($("google-button"), { theme: "filled_black" });
    };
    document.head.appendChild(gsi);
  } else {
    show("token-login");
    $("token-go").addEventListener("click", () => {
      const token = $("token").value.trim();
      if (token) onAuthed(token);
    });
  }
}

async function onAuthed(value) {
  credential = value;
  $("auth-status").textContent = "Checking access...";
  try {
    metaJson = await api("/api/v1/vault");
  } catch (e) {
    $("auth-status").textContent = `No access: ${e.message}`;
    $("auth-status").classList.add("error");
    credential = null;
    return;
  }
  hide("auth");
  show("unlock");
  $("master").focus();
}

async function unlock() {
  const password = $("master").value;
  if (!password) return;
  $("unlock-status").classList.remove("error");
  $("unlock-status").textContent = "Deriving key (Argon2id, 64 MiB)...";
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
    const reveal = document.createElement("button");
    reveal.className = "small";
    reveal.textContent = "Reveal";
    reveal.addEventListener("click", () => {
      const hidden = pass.dataset.revealed === "no";
      pass.textContent = hidden ? entry.password : "••••••";
      pass.dataset.revealed = hidden ? "yes" : "no";
      reveal.textContent = hidden ? "Hide" : "Reveal";
    });
    const copy = document.createElement("button");
    copy.className = "small";
    copy.textContent = "Copy";
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(entry.password);
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = "Copy"), 1500);
    });
    actions.append(reveal, " ", copy);

    row.append(title, user, pass, url, actions);
    tbody.appendChild(row);
  }
}

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

boot().catch((e) => {
  $("auth-status").textContent = `Failed to load: ${e.message}`;
  $("auth-status").classList.add("error");
});
