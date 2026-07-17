// Crypto worker. The Argon2id key derivation takes seconds by design; running
// it here keeps the page responsive instead of freezing the main thread. The
// master password and the unlocked session never leave this worker; only
// decrypted display data is posted back.

// The ?v= query cache-busts the wasm glue and binary together. A worker's
// module import and init() wasm fetch are not covered by the page's
// hard-refresh cache bypass, so without this a stale cached .wasm (from an
// older client) can load against new glue and blow up with
// "session_seal_entry is not a function". Bump v whenever the wasm changes.
const WASM_VERSION = "4";
import init, { Session } from "./pkg/password_manager_web.js?v=4";

let session = null;

self.onmessage = async (event) => {
  const msg = event.data;
  try {
    switch (msg.type) {
      case "unlock": {
        await init(`./pkg/password_manager_web_bg.wasm?v=${WASM_VERSION}`);
        // Drop any previous session before attempting the new one, so a
        // failed unlock can never leave a dangling freed handle behind.
        if (session) {
          session.free();
          session = null;
        }
        session = Session.unlock(msg.metaJson, msg.password);
        self.postMessage({ id: msg.id, ok: true });
        break;
      }
      case "decrypt": {
        if (!session) throw new Error("locked");
        const json = session.decrypt_entries(msg.recordsJson);
        self.postMessage({ id: msg.id, ok: true, result: json });
        break;
      }
      case "seal": {
        if (!session) throw new Error("locked");
        const record = session.seal_entry(msg.entryId, msg.modifiedMs, msg.dataJson);
        self.postMessage({ id: msg.id, ok: true, result: record });
        break;
      }
      case "tombstone": {
        if (!session) throw new Error("locked");
        const record = session.seal_tombstone(msg.entryId, msg.modifiedMs);
        self.postMessage({ id: msg.id, ok: true, result: record });
        break;
      }
      case "lock": {
        if (session) session.free();
        session = null;
        self.postMessage({ id: msg.id, ok: true });
        break;
      }
      default:
        throw new Error(`unknown message type ${msg.type}`);
    }
  } catch (e) {
    self.postMessage({ id: msg.id, ok: false, error: String(e?.message ?? e) });
  }
};
