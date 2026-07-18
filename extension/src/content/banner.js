// Save-credentials banner, fixed to the viewport top in a closed shadow DOM.
// Same tamper caveat as the dropdown (ADR 0009): a page can hide it, but it
// carries no secret - the captured password stays in the background worker
// and is never handed back to any page.

(function () {
  const ns = (globalThis.__pmcs = globalThis.__pmcs || {});

  let host = null;
  let root = null;
  let offer = null;
  let callbacks = {};

  const CSS = `
    :host { all: initial; }
    .bar {
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      box-sizing: border-box; display: flex; align-items: center; gap: 12px;
      padding: 10px 16px; background: #1c1e26; color: #e6e6e6;
      border-bottom: 1px solid #3a3d4d; box-shadow: 0 4px 16px rgba(0,0,0,.35);
      font: 13px system-ui, sans-serif;
    }
    .msg { flex: 1; min-width: 0; }
    .msg b { font-weight: 600; }
    .user { color: #8b8fa3; margin-left: 8px; }
    button {
      font: inherit; padding: 5px 12px; border-radius: 5px; cursor: pointer;
      border: 1px solid #3a3d4d; background: #2b2f3f; color: #e6e6e6;
    }
    button.primary { background: #3d5afe; border-color: #3d5afe; color: #fff; }
    button.close { border: none; background: none; color: #8b8fa3; padding: 5px 8px; }
  `;

  function button(label, cls, onClick) {
    const b = document.createElement("button");
    b.className = cls;
    b.textContent = label;
    b.addEventListener("click", onClick);
    return b;
  }

  // state: "ready" | "locked" | "authRequired" | "saving" | "saved" | {error}
  function render(state) {
    root.innerHTML = "";
    const style = document.createElement("style");
    style.textContent = CSS;
    root.appendChild(style);
    const bar = document.createElement("div");
    bar.className = "bar";

    const msg = document.createElement("div");
    msg.className = "msg";
    const strong = document.createElement("b");
    strong.textContent = offer.host;
    const user = document.createElement("span");
    user.className = "user";
    user.textContent = offer.username || "(no username)";

    if (state === "ready") {
      msg.append("Save credentials for ", strong, "?", user);
      bar.append(
        msg,
        button("Save", "primary", () => callbacks.onSave?.()),
        button("Never for this site", "", () => callbacks.onNever?.()),
        button("×", "close", () => callbacks.onDismiss?.())
      );
    } else if (state === "locked") {
      msg.append("Unlock PasswordManager to save the credentials for ", strong, ".", user);
      bar.append(
        msg,
        button("Unlock", "primary", () => callbacks.onUnlock?.()),
        button("×", "close", () => callbacks.onDismiss?.())
      );
    } else if (state === "authRequired") {
      msg.append("Sign in to the vault server, then Save.");
      // Keep Save reachable: after signing in on the server tab, the user
      // comes back here and retries. The captured credential is held until
      // the save succeeds (subject to its short expiry).
      bar.append(
        msg,
        button("Sign in", "primary", () => callbacks.onSignIn?.()),
        button("Save", "", () => callbacks.onSave?.()),
        button("×", "close", () => callbacks.onDismiss?.())
      );
    } else if (state === "saving") {
      msg.append("Saving…");
      bar.append(msg);
    } else if (state === "saved") {
      msg.append("Saved to the vault.");
      bar.append(msg);
      setTimeout(close, 2000);
    } else if (state && state.error) {
      msg.append(state.error);
      bar.append(msg, button("×", "close", () => close()));
    }
    root.appendChild(bar);
  }

  function show(o, state, cbs) {
    close();
    offer = o;
    callbacks = cbs || {};
    host = document.createElement("div");
    root = host.attachShadow({ mode: "closed" });
    document.documentElement.appendChild(host);
    render(state);
    window.addEventListener("pagehide", close, { once: true });
  }

  function update(state) {
    if (host) render(state);
  }

  function close() {
    if (host) {
      host.remove();
      host = null;
      root = null;
    }
    offer = null;
    callbacks = {};
  }

  function isOpen() {
    return !!host;
  }

  ns.banner = { show, update, close, isOpen };
})();
