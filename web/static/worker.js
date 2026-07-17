// Crypto worker. The Argon2id key derivation takes seconds by design; running
// it here keeps the page responsive instead of freezing the main thread. The
// master password and the unlocked session never leave this worker; only
// decrypted display data is posted back.

import init, { Session } from "./pkg/password_manager_web.js";

let session = null;

self.onmessage = async (event) => {
  const msg = event.data;
  try {
    switch (msg.type) {
      case "unlock": {
        await init();
        if (session) session.free();
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
