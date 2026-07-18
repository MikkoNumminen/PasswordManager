// Inline autofill dropdown. Rendered in a closed shadow DOM so the page's
// CSS and scripts cannot restyle or introspect it; the shadow root reference
// lives only in this isolated-world closure. The page can still remove or
// cover the host element - that is accepted and documented in ADR 0009: the
// dropdown carries only titles and usernames for the page's own domain, and
// fill values are released by the worker only after its domain gate.

(function () {
  const ns = (globalThis.__pmcs = globalThis.__pmcs || {});

  let host = null;
  let root = null;
  let anchor = null;
  let items = [];
  let active = -1;
  let callbacks = {};

  const CSS = `
    :host { all: initial; }
    .box {
      position: fixed; z-index: 2147483647; box-sizing: border-box;
      background: #1c1e26; color: #e6e6e6; border: 1px solid #3a3d4d;
      border-radius: 6px; box-shadow: 0 6px 24px rgba(0,0,0,.45);
      font: 13px system-ui, sans-serif; overflow: hidden;
    }
    .head { padding: 6px 10px; color: #8b8fa3; font-size: 11px;
      border-bottom: 1px solid #2a2d3a; }
    .item { padding: 8px 10px; cursor: pointer; display: flex;
      justify-content: space-between; gap: 8px; align-items: baseline; }
    .item.active, .item:hover { background: #2b2f3f; }
    .title { font-weight: 600; white-space: nowrap; overflow: hidden;
      text-overflow: ellipsis; }
    .user { color: #8b8fa3; white-space: nowrap; overflow: hidden;
      text-overflow: ellipsis; }
    .badge { color: #8b8fa3; font-size: 11px; flex-shrink: 0; }
    .foot { padding: 6px 10px; color: #8b8fa3; font-size: 11px;
      border-top: 1px solid #2a2d3a; }
  `;

  function ensureHost() {
    if (host && host.isConnected) return;
    host = document.createElement("div");
    root = host.attachShadow({ mode: "closed" });
    document.documentElement.appendChild(host);
  }

  function position(box) {
    const r = anchor.getBoundingClientRect();
    box.style.left = `${Math.max(0, r.left)}px`;
    box.style.top = `${r.bottom + 2}px`;
    box.style.width = `${Math.max(r.width, 260)}px`;
  }

  function render() {
    root.innerHTML = "";
    const style = document.createElement("style");
    style.textContent = CSS;
    root.appendChild(style);
    const box = document.createElement("div");
    box.className = "box";

    const head = document.createElement("div");
    head.className = "head";
    head.textContent = "PasswordManager";
    box.appendChild(head);

    if (callbacks.locked) {
      const it = document.createElement("div");
      it.className = "item";
      it.textContent = "Unlock PasswordManager…";
      it.addEventListener("mousedown", (e) => {
        e.preventDefault();
        callbacks.onUnlock?.();
      });
      box.appendChild(it);
    } else {
      items.forEach((m, i) => {
        const it = document.createElement("div");
        it.className = "item" + (i === active ? " active" : "");
        const title = document.createElement("span");
        title.className = "title";
        title.textContent = m.title;
        const user = document.createElement("span");
        user.className = "user";
        user.textContent = m.username;
        it.append(title, user);
        if (m.level === "subdomain") {
          const badge = document.createElement("span");
          badge.className = "badge";
          badge.textContent = "same domain";
          it.appendChild(badge);
        }
        // mousedown, not click: it fires before the input loses focus, so
        // the page never sees a blur before the fill lands.
        it.addEventListener("mousedown", (e) => {
          e.preventDefault();
          callbacks.onPick?.(m.id);
        });
        box.appendChild(it);
      });
      if (callbacks.more) {
        const foot = document.createElement("div");
        foot.className = "foot";
        foot.textContent = "more in the toolbar popup";
        box.appendChild(foot);
      }
    }
    root.appendChild(box);
    position(box);
  }

  function reposition() {
    if (!isOpen()) return;
    const box = root.querySelector(".box");
    if (box) position(box);
  }

  function onOutsideMouseDown(e) {
    if (e.composedPath().includes(host) || e.target === anchor) return;
    close();
  }

  function onKeyDown(e) {
    if (!isOpen()) return;
    if (e.key === "Escape") {
      close();
      e.preventDefault();
      e.stopPropagation();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (callbacks.locked || !items.length) return;
      const delta = e.key === "ArrowDown" ? 1 : -1;
      active = (active + delta + items.length) % items.length;
      render();
      e.preventDefault();
      e.stopPropagation();
    } else if (e.key === "Enter") {
      if (callbacks.locked) {
        callbacks.onUnlock?.();
        close();
        e.preventDefault();
        e.stopPropagation();
      } else if (active >= 0 && items[active]) {
        callbacks.onPick?.(items[active].id);
        e.preventDefault();
        e.stopPropagation();
      }
      // Enter with no active item falls through to the page's own submit.
    }
  }

  function open(opts) {
    close();
    anchor = opts.anchor;
    items = opts.items || [];
    callbacks = opts;
    active = -1;
    ensureHost();
    render();
    window.addEventListener("scroll", reposition, { capture: true, passive: true });
    window.addEventListener("resize", reposition, { passive: true });
    document.addEventListener("mousedown", onOutsideMouseDown, true);
    anchor.addEventListener("keydown", onKeyDown, true);
    window.addEventListener("pagehide", close, { once: true });
  }

  function close() {
    if (host) {
      host.remove();
      host = null;
      root = null;
    }
    if (anchor) anchor.removeEventListener("keydown", onKeyDown, true);
    window.removeEventListener("scroll", reposition, true);
    window.removeEventListener("resize", reposition);
    document.removeEventListener("mousedown", onOutsideMouseDown, true);
    anchor = null;
    items = [];
    active = -1;
    callbacks = {};
  }

  function isOpen() {
    return !!host;
  }

  ns.dropdown = { open, close, isOpen };
})();
