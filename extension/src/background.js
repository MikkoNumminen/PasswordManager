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
import { matchLevel, hostOf, loadRuleset, registrableDomain } from "./psl.js";
import { rankMatches } from "./rank.js";
import { sameSite, shouldOfferSave, SAVE_TTL_MS } from "./savepolicy.js";
import { isBehind } from "./version.js";

const LOCAL = "local"; // chrome.storage.local: server config
const SESSION = "session"; // chrome.storage.session: key, meta, index, records
const AUTOLOCK_ALARM = "autolock";
const CLIPBOARD_ALARM = "clipboard-clear";
const UPDATE_ALARM = "update-check";
const UPDATE_PERIOD_MINUTES = 360; // re-check the server for a newer build every 6h

let wasmReady = null;
let liveSession = null; // in-memory Session for this worker's lifetime

async function ensureWasm() {
  if (!wasmReady) {
    wasmReady = init(chrome.runtime.getURL("vendor/pkg/password_manager_web_bg.wasm"));
  }
  await wasmReady;
}

// Restrict session storage to trusted extension contexts (not content scripts).
// Also arm the periodic update check and run one now, so the toolbar badge
// reflects an available update without waiting for the popup to be opened.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});
  armUpdateCheck();
});
chrome.runtime.onStartup.addListener(armUpdateCheck);

function armUpdateCheck() {
  chrome.alarms.create(UPDATE_ALARM, { periodInMinutes: UPDATE_PERIOD_MINUTES });
  refreshUpdateBadge();
}

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

// Free the wasm Session so core's Drop runs and the vault key is zeroized now,
// rather than whenever GC eventually reclaims the handle.
function freeLive() {
  if (liveSession) {
    try {
      liveSession.free();
    } catch {
      // already freed
    }
    liveSession = null;
  }
}

async function lock() {
  freeLive();
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

// Ask the server which extension version it was built from and compare it to
// this installed one. A plain fetch, deliberately not through api(): the
// update check must never lock the vault on a 401 or throw AuthRequired, and
// any failure just means "don't nag".
async function checkUpdate() {
  const { serverUrl } = await getConfig();
  if (!serverUrl) return { behind: false };
  try {
    const resp = await fetch(serverUrl.replace(/\/$/, "") + "/api/v1/version", {
      credentials: "include",
      cache: "no-store",
    });
    const ct = resp.headers.get("content-type") || "";
    if (!resp.ok || !ct.includes("application/json")) return { behind: false };
    const latest = (await resp.json()).extension;
    const current = chrome.runtime.getManifest().version;
    return { current, latest, behind: isBehind(current, latest) };
  } catch {
    return { behind: false };
  }
}

// Flag an available update on the toolbar icon so it is visible on every tab
// without opening the popup. A subtle amber dot plus a tooltip; cleared when
// the installed build is current. Best-effort: a failed check never nags.
async function refreshUpdateBadge() {
  const r = await checkUpdate();
  if (r.behind) {
    chrome.action.setBadgeText({ text: "↑" }); // an up arrow
    chrome.action.setBadgeBackgroundColor({ color: "#d29922" }); // amber
    chrome.action.setTitle({
      title: `PasswordManager — update available (v${r.latest}; you have v${r.current})`,
    });
  } else {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setTitle({ title: "PasswordManager" });
  }
  return r;
}

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

  const keyBytes = Array.from(session.export_key());

  freeLive(); // drop any prior session before replacing it
  liveSession = session;
  try {
    await chrome.storage.session.set({ vaultKey: keyBytes, metaJson });
    await refreshEntries(session);
  } catch (e) {
    await lock(); // no half-unlocked state: key stored but entries missing
    throw e;
  }
  await armAutoLock();
  broadcastUnlocked();
  refreshUpdateBadge(); // a good moment to refresh the flag
  return { ok: true };
}

// Refetch and re-index the entries; shared by unlock and the post-save
// refresh so a just-saved entry shows up everywhere without a relock.
async function refreshEntries(session) {
  const recordsJson = await (await api("/api/v1/entries")).text();
  const index = JSON.parse(session.decrypt_index(recordsJson));
  await chrome.storage.session.set({ index, records: JSON.parse(recordsJson) });
}

// Tell every page's content script the vault just unlocked so an open locked
// dropdown or save banner can refresh. Best effort: most tabs have no
// listener and reject.
function broadcastUnlocked() {
  chrome.tabs.query({}).then((tabs) => {
    for (const t of tabs) {
      if (t.id != null) {
        chrome.tabs.sendMessage(t.id, { target: "content", type: "unlocked" }).catch(() => {});
      }
    }
  });
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

async function doFill({ id, tabId, confirmedMismatch }) {
  const entry = await decryptOne(id);
  if (!entry) return { error: "locked" };
  // Derive the target host from the tab we are about to fill, not from what the
  // popup passed. The popup reads the host when it opens; if the tab navigates
  // afterward (same tab id, new URL), a stale host could pass the domain check
  // while the password is injected into the navigated page. Checking and
  // filling the same tab.url closes that gap.
  let tabHost = "";
  try {
    const tab = await chrome.tabs.get(tabId);
    tabHost = hostOf(tab?.url || "");
  } catch {
    return { error: "cannot read the target tab" };
  }
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

// ---- content-script requests ------------------------------------------------
//
// Content scripts run inside arbitrary pages, so nothing they claim is
// trusted: the host is derived from sender.url (set by Chrome, not the page)
// and every answer is scoped to that host. They receive at most the match
// rows for their own site, the one fill they asked for after the domain
// gate, and a pending-save offer that never echoes the password back.

// Validate a content-script sender: top frame, real tab, http(s) page.
function csSender(sender) {
  if (!sender?.tab || sender.tab.id == null || sender.frameId !== 0) return null;
  const url = sender.url || "";
  if (!/^https?:\/\//i.test(url)) return null;
  const host = hostOf(url);
  if (!host) return null;
  try {
    return { tabId: sender.tab.id, host, origin: new URL(url).origin };
  } catch {
    return null;
  }
}

// The vault's own web page must never see autofill or capture: the master
// password gets typed there.
async function isServerOrigin(origin) {
  const { serverUrl } = await getConfig();
  if (!serverUrl) return false;
  try {
    return new URL(serverUrl).origin === origin;
  } catch {
    return false;
  }
}

async function doGetMatches(cs) {
  const { serverUrl } = await getConfig();
  if (!serverUrl || (await isServerOrigin(cs.origin))) return { disabled: true };
  // Passive: merely focusing a login field must not reset the auto-lock
  // timer, so this deliberately skips armAutoLock.
  const session = await ensureSession();
  if (!session) return { locked: true };
  const { index } = await sess();
  const ruleset = await loadRuleset();
  return rankMatches(cs.host, index || [], ruleset);
}

async function doCsFill(cs, id) {
  const entry = await decryptOne(id);
  if (!entry) return { error: "locked" };
  const ruleset = await loadRuleset();
  // The gate: values leave the worker only for the page's own site. Unlike
  // the popup there is no confirmed-mismatch override on this path.
  if (matchLevel(cs.host, hostOf(entry.url), ruleset) === "none") {
    return { error: "entry does not match this site" };
  }
  return { username: entry.username || "", password: entry.password || "" };
}

const PENDING_KEY = "pendingSave";

async function getPending() {
  const got = await chrome.storage.session.get(PENDING_KEY);
  return got[PENDING_KEY] || null;
}

async function saveContext() {
  const ruleset = await loadRuleset();
  const session = await ensureSession();
  const { index } = session ? await sess() : {};
  const { neverSaveDomains } = await chrome.storage.local.get("neverSaveDomains");
  return { ruleset, session, index: index || [], neverList: neverSaveDomains || [] };
}

async function capturePendingSave(cs, { username, password }) {
  // The response is {ok:true} on every path: the page learns nothing about
  // what was kept or why.
  if (typeof password !== "string" || !password || password.length > 1024) return { ok: true };
  if (typeof username !== "string" || username.length > 512) return { ok: true };
  if (await isServerOrigin(cs.origin)) return { ok: true };
  const { ruleset, session, index, neverList } = await saveContext();
  const pending = {
    id: crypto.randomUUID(),
    host: cs.host,
    origin: cs.origin,
    username,
    password,
    ts: Date.now(),
  };
  const verdict = shouldOfferSave({
    pending,
    now: pending.ts,
    senderHost: cs.host,
    index,
    neverList,
    ruleset,
    locked: !session,
  });
  if (verdict.offer) {
    await chrome.storage.session.set({ [PENDING_KEY]: pending });
  }
  return { ok: true };
}

async function checkPendingSave(cs) {
  const { serverUrl } = await getConfig();
  if (!serverUrl || (await isServerOrigin(cs.origin))) return { disabled: true };
  const pending = await getPending();
  if (!pending) return { none: true };
  const { ruleset, session, index, neverList } = await saveContext();
  const verdict = shouldOfferSave({
    pending,
    now: Date.now(),
    senderHost: cs.host,
    index,
    neverList,
    ruleset,
    locked: !session,
  });
  if (!verdict.offer) {
    // Terminal verdicts drop the capture; "different-site" keeps it, the
    // TTL bounds its life if no same-site page ever asks.
    if (["expired", "known", "never-listed"].includes(verdict.reason)) {
      await chrome.storage.session.remove(PENDING_KEY);
    }
    return { none: true };
  }
  return {
    offer: { offerId: pending.id, username: pending.username, host: pending.host },
    locked: !session,
  };
}

async function doSaveEntry(cs, offerId) {
  const pending = await getPending();
  const ruleset = await loadRuleset();
  if (
    !pending ||
    pending.id !== offerId ||
    Date.now() - pending.ts > SAVE_TTL_MS ||
    !sameSite(pending.host, cs.host, ruleset)
  ) {
    return { error: "nothing to save" };
  }
  const session = await ensureSession();
  if (!session) return { locked: true };
  const id = crypto.randomUUID();
  const now = Date.now();
  const data = {
    title: registrableDomain(pending.host, ruleset) || pending.host,
    username: pending.username,
    password: pending.password,
    url: pending.origin,
    notes: "",
    created_ms: now,
  };
  const record = session.seal_entry(id, now, JSON.stringify(data));
  const resp = await api(`/api/v1/entries/${id}`, { method: "PUT", body: record });
  if (!resp.ok) return { error: `save failed (${resp.status})` };
  // The entry is on the server: clear the capture before the index refresh
  // so a refresh hiccup cannot report failure and invite a duplicate save.
  await chrome.storage.session.remove(PENDING_KEY);
  try {
    await refreshEntries(session);
  } catch {
    // saved; the index catches up on the next unlock
  }
  await armAutoLock();
  return { ok: true };
}

async function neverForSite(cs, offerId) {
  const pending = await getPending();
  if (!pending || pending.id !== offerId) return { ok: true };
  const ruleset = await loadRuleset();
  const domain = registrableDomain(cs.host, ruleset) || cs.host.toLowerCase();
  const { neverSaveDomains } = await chrome.storage.local.get("neverSaveDomains");
  const list = neverSaveDomains || [];
  if (!list.includes(domain)) list.push(domain);
  await chrome.storage.local.set({ neverSaveDomains: list });
  await chrome.storage.session.remove(PENDING_KEY);
  return { ok: true };
}

// ---- alarms ----------------------------------------------------------------

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) lock();
  else if (alarm.name === CLIPBOARD_ALARM) clearClipboardIfUnchanged();
  else if (alarm.name === UPDATE_ALARM) refreshUpdateBadge();
});

// ---- message router --------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.target && msg.target !== "background") return; // not for us
  (async () => {
    try {
      // Everything prefixed cs. comes from a content script inside an
      // arbitrary page; validate the sender once, up front.
      let cs = null;
      if (typeof msg.type === "string" && msg.type.startsWith("cs.")) {
        cs = csSender(sender);
        if (!cs) return { error: "bad sender" };
      }
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
        case "checkUpdate":
          return await refreshUpdateBadge();
        case "cs.getMatches":
          return await doGetMatches(cs);
        case "cs.fill":
          return await doCsFill(cs, msg.id);
        case "cs.pendingSave":
          return await capturePendingSave(cs, msg);
        case "cs.checkPendingSave":
          return await checkPendingSave(cs);
        case "cs.saveNow":
          return await doSaveEntry(cs, msg.offerId);
        case "cs.dismissPendingSave": {
          const pending = await getPending();
          if (pending && pending.id === msg.offerId) {
            await chrome.storage.session.remove(PENDING_KEY);
          }
          return { ok: true };
        }
        case "cs.neverForSite":
          return await neverForSite(cs, msg.offerId);
        case "cs.openPopup":
          try {
            await chrome.action.openPopup();
            return { ok: true };
          } catch {
            return { error: "click the toolbar icon to unlock" };
          }
        case "cs.openServer": {
          const { serverUrl } = await getConfig();
          if (serverUrl) await chrome.tabs.create({ url: serverUrl });
          return { ok: true };
        }
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
