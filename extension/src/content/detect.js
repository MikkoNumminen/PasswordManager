// Login-form detection heuristics. Pure: operates on plain field descriptors
// built by the DOM adapter in main.js, so node can test it without a browser.
// Classic script (content scripts cannot be modules); exports through the
// shared __pmcs namespace.
//
// A descriptor: { kind: "password"|"text"|"email"|"other", name, id,
//   autocomplete, placeholder, visible, formIndex }
// formIndex -1 groups inputs that sit outside any <form>.

(function () {
  const ns = (globalThis.__pmcs = globalThis.__pmcs || {});

  const USER_HINT = /user|email|login|account/i;

  // A form qualifies as a login form only with exactly one visible password
  // field. Two or more visible password fields is a signup-with-confirm or a
  // change-password form; offering or capturing there does more harm than
  // good, so those are left alone.
  function findLoginForms(descriptors) {
    const byForm = new Map();
    descriptors.forEach((d, i) => {
      if (!byForm.has(d.formIndex)) byForm.set(d.formIndex, []);
      byForm.get(d.formIndex).push({ d, i });
    });
    const out = [];
    for (const [formIndex, fields] of byForm) {
      const pw = fields.filter(({ d }) => d.kind === "password" && d.visible);
      if (pw.length !== 1) continue;
      const passwordIdx = pw[0].i;
      out.push({ formIndex, passwordIdx, usernameIdx: pickUsername(fields, passwordIdx) });
    }
    return out.sort((a, b) => a.formIndex - b.formIndex);
  }

  // Username preference order: an explicit autocomplete="username" beats an
  // email field beats a hinted name/id/placeholder beats the nearest visible
  // text input before the password field. May be null (password-only pages,
  // e.g. the second step of a two-step login).
  function pickUsername(fields, passwordIdx) {
    const texts = fields.filter(({ d }) => d.visible && (d.kind === "text" || d.kind === "email"));
    if (!texts.length) return null;
    const byAutocomplete = texts.find(({ d }) => d.autocomplete === "username");
    if (byAutocomplete) return byAutocomplete.i;
    const byEmail = texts.find(({ d }) => d.kind === "email");
    if (byEmail) return byEmail.i;
    const byHint = texts.find(
      ({ d }) => USER_HINT.test(d.name) || USER_HINT.test(d.id) || USER_HINT.test(d.placeholder)
    );
    if (byHint) return byHint.i;
    const before = texts.filter(({ i }) => i < passwordIdx);
    return before.length ? before[before.length - 1].i : null;
  }

  ns.detect = { findLoginForms };
})();
