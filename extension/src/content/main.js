// Content-script orchestrator: builds field descriptors from the live DOM,
// wires detection to the dropdown and banner, and talks to the background
// worker. Holds no vault state: every answer it receives is scoped by the
// worker to this page's own site, and fill values are dropped as soon as
// they are written into the fields.

(function () {
  const ns = globalThis.__pmcs;
  if (!ns || !ns.detect || !ns.dropdown || !ns.banner) return;

  let dormant = false; // set when the worker says this page gets nothing
  let elements = [];
  let formEls = [];
  let fields = [];
  let forms = [];
  let lastCapture = "";
  let spaTimer = null;

  function send(message) {
    // The catch covers a sleeping-then-restarting worker losing the port and
    // an extension reload invalidating this context; both read as "no answer".
    try {
      return chrome.runtime.sendMessage({ target: "background", ...message }).catch(() => ({}));
    } catch {
      return Promise.resolve({});
    }
  }

  // ---- DOM adapter -----------------------------------------------------

  function isVisible(el) {
    return (
      !el.disabled &&
      el.type !== "hidden" &&
      el.offsetParent !== null &&
      el.getBoundingClientRect().width > 0
    );
  }

  function scan() {
    const inputs = [...document.querySelectorAll("input")];
    if (!inputs.some((el) => el.type === "password")) {
      elements = [];
      formEls = [];
      fields = [];
      forms = [];
      return;
    }
    elements = inputs;
    formEls = [];
    fields = inputs.map((el) => {
      let formIndex = -1;
      if (el.form) {
        let fi = formEls.indexOf(el.form);
        if (fi === -1) {
          formEls.push(el.form);
          fi = formEls.length - 1;
        }
        formIndex = fi;
      }
      const type = (el.getAttribute("type") || "text").toLowerCase();
      return {
        kind:
          type === "password" ? "password" : type === "email" ? "email" : type === "text" ? "text" : "other",
        name: el.name || "",
        id: el.id || "",
        autocomplete: (el.getAttribute("autocomplete") || "").toLowerCase(),
        placeholder: el.getAttribute("placeholder") || "",
        visible: isVisible(el),
        formIndex,
      };
    });
    forms = ns.detect.findLoginForms(fields);
  }

  function formOfElement(el) {
    let idx = elements.indexOf(el);
    if (idx === -1) {
      scan(); // stale after a mutation burst; one rescan
      idx = elements.indexOf(el);
      if (idx === -1) return null;
    }
    return forms.find((f) => f.passwordIdx === idx || f.usernameIdx === idx) || null;
  }

  // Native setter so framework-controlled inputs (React et al.) see the
  // change; plain el.value assignment is swallowed by their value tracking.
  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  function setValue(el, value) {
    if (!el) return;
    el.focus();
    valueSetter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // ---- autofill dropdown -----------------------------------------------

  async function onFocusIn(e) {
    if (dormant) return;
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    const form = formOfElement(el);
    if (!form) return;
    // Resolve the element refs now, before any await: a MutationObserver
    // rescan during the getMatches round-trip can rebuild the index arrays,
    // and stale indexes would misdirect the fill. Element refs stay valid
    // across a rescan; the indexes do not.
    const userEl = form.usernameIdx != null ? elements[form.usernameIdx] : null;
    const pwEl = elements[form.passwordIdx];
    const res = await send({ type: "cs.getMatches" });
    if (res.disabled) {
      dormant = true;
      return;
    }
    if (res.locked) {
      ns.dropdown.open({ anchor: el, locked: true, onUnlock: requestUnlock });
      return;
    }
    if (!res.matches || !res.matches.length) return;
    ns.dropdown.open({
      anchor: el,
      items: res.matches,
      more: res.more,
      onPick: (id) => fillEntry(userEl, pwEl, id),
    });
  }

  async function fillEntry(userEl, pwEl, id) {
    const res = await send({ type: "cs.fill", id });
    ns.dropdown.close();
    if (res.error || typeof res.password !== "string") return;
    if (res.username && userEl) setValue(userEl, res.username);
    setValue(pwEl, res.password);
    // Drop the only references to the values; nothing here retains them.
  }

  async function requestUnlock() {
    ns.dropdown.close();
    await send({ type: "cs.openPopup" });
  }

  // ---- save capture ----------------------------------------------------

  function captureForm(form) {
    const pw = elements[form.passwordIdx]?.value || "";
    if (!pw) return;
    const user = form.usernameIdx != null ? elements[form.usernameIdx]?.value || "" : "";
    const key = JSON.stringify([user, pw]);
    if (key === lastCapture) return; // same pair already sent for this page
    lastCapture = key;
    send({ type: "cs.pendingSave", username: user, password: pw });
    // SPA fallback: if no navigation happens, offer on this same page.
    clearTimeout(spaTimer);
    spaTimer = setTimeout(checkPendingSave, 4000);
  }

  function captureFromFormElement(formEl) {
    scan(); // the arrays may be stale after page mutations; values are read now
    const fi = formEls.indexOf(formEl);
    if (fi === -1) return; // form appeared after the scan or has no inputs
    const form = forms.find((f) => f.formIndex === fi);
    if (form) captureForm(form);
  }

  document.addEventListener(
    "submit",
    (e) => {
      if (!dormant && e.target instanceof HTMLFormElement) captureFromFormElement(e.target);
    },
    true
  );

  document.addEventListener(
    "click",
    (e) => {
      if (dormant) return;
      const btn = e.target instanceof Element ? e.target.closest("button, input[type=submit]") : null;
      if (!btn || (btn.tagName === "BUTTON" && btn.type === "reset")) return;
      const formEl = btn.form || btn.closest("form");
      if (formEl) captureFromFormElement(formEl);
    },
    true
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (dormant || e.key !== "Enter") return;
      const el = e.target;
      if (!(el instanceof HTMLInputElement) || el.type !== "password") return;
      scan();
      const idx = elements.indexOf(el);
      const form = forms.find((f) => f.passwordIdx === idx);
      if (form) captureForm(form);
    },
    true
  );

  // ---- save banner -----------------------------------------------------

  async function checkPendingSave() {
    if (dormant) return;
    const res = await send({ type: "cs.checkPendingSave" });
    if (res.disabled) {
      dormant = true;
      return;
    }
    if (!res.offer) return;
    showBanner(res.offer, res.locked ? "locked" : "ready");
  }

  function showBanner(offer, state) {
    ns.banner.show(offer, state, {
      onSave: async () => {
        ns.banner.update("saving");
        const res = await send({ type: "cs.saveNow", offerId: offer.offerId });
        if (res.ok) ns.banner.update("saved");
        else if (res.locked) ns.banner.update("locked");
        else if (res.authRequired) ns.banner.update("authRequired");
        else ns.banner.update({ error: res.error || "save failed" });
      },
      onNever: async () => {
        await send({ type: "cs.neverForSite", offerId: offer.offerId });
        ns.banner.close();
      },
      onDismiss: async () => {
        await send({ type: "cs.dismissPendingSave", offerId: offer.offerId });
        ns.banner.close();
      },
      onUnlock: () => send({ type: "cs.openPopup" }),
      onSignIn: () => send({ type: "cs.openServer" }),
    });
  }

  // After an unlock anywhere (popup), refresh whatever is showing.
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.target !== "content") return;
    if (msg.type === "unlocked") {
      if (ns.dropdown.isOpen()) ns.dropdown.close();
      checkPendingSave();
    }
  });

  // ---- boot ------------------------------------------------------------

  document.addEventListener("focusin", onFocusIn, true);

  let moTimer = null;
  const mo = new MutationObserver(() => {
    clearTimeout(moTimer);
    moTimer = setTimeout(() => {
      if (!dormant) scan();
    }, 300);
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });

  scan();
  checkPendingSave();
})();
