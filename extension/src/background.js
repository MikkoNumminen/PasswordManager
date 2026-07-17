// Service worker: owns the vault session, talks to the server, and answers
// the popup. All crypto is the same wasm core the CLI and web page use.
//
// MV3 kills this worker after about 30s idle, which would drop a session key
// held in a variable. So after unlock the derived key is kept in
// chrome.storage.session (memory-backed, never written to disk, cleared when
// the browser closes and by the auto-lock alarm). On each wake the session is
// rebuilt from that key (fast, no Argon2). The master password is never
// stored anywhere.

import init, { Session } from "../vendor/pkg/password_manager_web.js";
import { matchLevel, hostOf, loadRuleset } from "./psl.js";

const LOCAL = "local"; // chrome.storage.local: server config
const SESSION = "session"; // chrome.storage.session: key, meta, index, records
const AUTOLOCK_ALARM = "autolock";
const CLIPBOARD_ALARM = "clipboard-clear";

let wasmReady = null;
let liveSession = null; // in-memory Session for this worker's lifetime

async function ensureWasm() {
  if (!wasmReady) {
    wasmReady = init(chrome.runtime.getURL("vendor/pkg/password_manager_web_bg.wasm"));
  }
  await wasmReady;
}

// Restrict session storage to trusted extension contexts (not content scripts).
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});
});

// ---- config & session storage ---------------------------------------------

async function getConfig() {
  const c = await chrome.storage.local.get(["serverUrl", "token", "autoLockMinutes"]);
  return {
    serverUrl: c.serverUrl || "",
    token: c.token || "",
    autoLockMinutes: c.autoLockMinutes ?? 15, // 0 means "until browser close"
  };
}

async function sess() {
  return chrome.storage.session.get(["vaultKey", "metaJson", "index", "records"]);
}

async function lock() {
  liveSession = null;
  await chrome.storage.session.remove(["vaultKey", "metaJson", "index", "records"]);
  await chrome.alarms.clear(AUTOLOCK_ALARM);
}

// Rebuild the wasm Session from the stored key, or null if locked.
async function ensureSession() {
  if (liveSession) return liveSession;
  const s = await sess();
  if (!s.vaultKey || !s.metaJson) return null;
  await ensureWasm();
  try {
    liveSession = Session.from_key(s.metaJson, new Uint8Array(s.vaultKey));
    return liveSession;
  } catch {
    await lock();
    return null;
  }
}

async function armAutoLock() {
  const { autoLockMinutes } = await getConfig();
  await chrome.alarms.clear(AUTOLOCK_ALARM);
  if (autoLockMinutes > 0) {
    chrome.alarms.create(AUTOLOCK_ALARM, { delayInMinutes: autoLockMinutes });
  }
}

// ---- server API ------------------------------------------------------------

// Distinguish a real API response from an auth-gate login redirect. When
// oauth2-proxy or Cloudflare Access intercepts, it answers with HTML, not our
// JSON. Fetch follows the redirect; we detect the HTML and report authRequired.
class AuthRequired extends Error {}

async function api(path, { method = "GET", body } = {}) {
  const { serverUrl, token } = await getConfig();
  if (!serverUrl) throw new Error("no server configured");
  const resp = await fetch(serverUrl.replace(/\/$/, "") + path, {
    method,
    credentials: "include", // ride the auth-gate cookie if one is set
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body,
    cache: "no-store",
  });
  const ct = resp.headers.get("content-type") || "";
  if (resp.ok && ct.includes("text/html")) throw new AuthRequired();
  if (resp.status === 401) {
    await lock();
    const e = new Error("unauthorized");
    e.status = 401;
    throw e;
  }
  return resp;
}

// ---- operations ------------------------------------------------------------

async function doUnlock(password) {
  await ensureWasm();
  const metaResp = await api("/api/v1/vault");
  if (metaResp.status === 404) return { error: "no vault on this server yet" };
  if (!metaResp.ok) return { error: `vault fetch failed (${metaResp.status})` };
  const metaJson = await metaResp.text();

  let session;
  try {
    session = Session.unlock(metaJson, password);
  } catch (e) {
    return { error: String(e?.message) === "wrong-password" ? "wrong master password" : String(e?.message ?? e) };
  }

  const recordsJson = await (await api("/api/v1/entries")).text();
  const index = JSON.parse(session.decrypt_index(recordsJson));
  const keyBytes = Array.from(session.export_key());

  liveSession = session;
  await chrome.storage.session.set({
    vaultKey: keyBytes,
    metaJson,
    index,
    records: JSON.parse(recordsJson),
  });
  await armAutoLock();
  return { ok: true };
}

async function decryptOne(id) {
  const session = await ensureSession();
  if (!session) return null;
  const { records } = await sess();
  const record = (records || []).find((r) => r.id === id);
  if (!record) return null;
  await armAutoLock(); // activity resets the idle timer
  return JSON.parse(session.decrypt_one(JSON.stringify(record)));
}

// Injected into the active tab (activeTab, on the user's fill click) to fill
// credentials. Self-contained: it only reads form fields and never sends page
// content anywhere.
function injectedFill(username, password) {
  const visible = (el) =>
    el && !el.disabled && el.type !== "hidden" && el.offsetParent !== null;
  const pwField = [...document.querySelectorAll('input[type="password"]')].find(visible);
  let userField = null;
  if (pwField) {
    const form = pwField.form || document;
    userField = [
      ...form.querySelectorAll(
        'input[autocomplete="username"], input[type="email"], input[type="text"], input[name*="user" i], input[id*="user" i]'
      ),
    ].find(visible);
  }
  const set = (el, val) => {
    if (!el) return false;
    el.focus();
    el.value = val;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  };
  const filledUser = username ? set(userField, username) : false;
  const filledPass = set(pwField, password);
  return { filledUser, filledPass, foundPassword: !!pwField };
}

async function doFill({ id, tabId, tabHost, confirmedMismatch }) {
  const entry = await decryptOne(id);
  if (!entry) return { error: "locked" };
  const ruleset = await loadRuleset();
  const level = matchLevel(tabHost, hostOf(entry.url), ruleset);
  if (level === "none" && !confirmedMismatch) {
    return { mismatch: true, entryHost: hostOf(entry.url), tabHost };
  }
  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: injectedFill,
    args: [entry.username || "", entry.password || ""],
  });
  return { ok: true, ...res.result };
}

// Clipboard: the popup writes the secret on its user gesture; here we schedule
// a clear 30s later via an offscreen document, and only clear if the clipboard
// still holds the copied value. Best-effort.
async function scheduleClipboardClear(value) {
  await chrome.storage.session.set({ clipStamp: value });
  await chrome.alarms.clear(CLIPBOARD_ALARM);
  chrome.alarms.create(CLIPBOARD_ALARM, { delayInMinutes: 0.5 });
}

async function clearClipboardIfUnchanged() {
  const { clipStamp } = await chrome.storage.session.get("clipStamp");
  if (!clipStamp) return;
  await chrome.storage.session.remove("clipStamp");
  try {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["CLIPBOARD"],
      justification: "clear a copied secret from the clipboard",
    });
  } catch {
    // already open
  }
  chrome.runtime.sendMessage({ target: "offscreen", type: "clipboard-clear", value: clipStamp });
}

// ---- alarms ----------------------------------------------------------------

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) lock();
  else if (alarm.name === CLIPBOARD_ALARM) clearClipboardIfUnchanged();
});

// ---- message router --------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.target && msg.target !== "background") return; // not for us
  (async () => {
    try {
      switch (msg.type) {
        case "getState": {
          const { serverUrl } = await getConfig();
          const session = await ensureSession();
          const s = await sess();
          return { configured: !!serverUrl, locked: !session, hasIndex: !!s.index };
        }
        case "unlock":
          return await doUnlock(msg.password);
        case "list": {
          const s = await sess();
          return { index: s.index || [], locked: !(await ensureSession()) };
        }
        case "reveal": {
          const entry = await decryptOne(msg.id);
          return entry ? { password: entry.password, username: entry.username } : { error: "locked" };
        }
        case "fill":
          return await doFill(msg);
        case "clipboardCopied":
          await scheduleClipboardClear(msg.value);
          return { ok: true };
        case "lock":
          await lock();
          return { ok: true };
        default:
          return { error: `unknown message ${msg.type}` };
      }
    } catch (e) {
      if (e instanceof AuthRequired) return { authRequired: true };
      return { error: String(e?.message ?? e) };
    }
  })().then(sendResponse);
  return true; // async response
});
