import { test } from "node:test";
import assert from "node:assert/strict";
import "../src/content/detect.js";

const { findLoginForms } = globalThis.__pmcs.detect;

// Descriptor helper: sensible defaults, override what the case needs.
const f = (over = {}) => ({
  kind: "text",
  name: "",
  id: "",
  autocomplete: "",
  placeholder: "",
  visible: true,
  formIndex: 0,
  ...over,
});

test("a plain username + password form is detected", () => {
  const forms = findLoginForms([f({ name: "u" }), f({ kind: "password" })]);
  assert.equal(forms.length, 1);
  assert.equal(forms[0].passwordIdx, 1);
  assert.equal(forms[0].usernameIdx, 0);
});

test("no password field means no login form", () => {
  assert.equal(findLoginForms([f(), f({ kind: "email" })]).length, 0);
});

test("two visible password fields (signup/change) are suppressed", () => {
  const forms = findLoginForms([f(), f({ kind: "password" }), f({ kind: "password" })]);
  assert.equal(forms.length, 0);
});

test("a hidden second password field does not suppress", () => {
  const forms = findLoginForms([
    f(),
    f({ kind: "password" }),
    f({ kind: "password", visible: false }),
  ]);
  assert.equal(forms.length, 1);
});

test("hidden fields are never picked as username", () => {
  const forms = findLoginForms([f({ visible: false }), f({ kind: "password" })]);
  assert.equal(forms[0].usernameIdx, null);
});

test("username preference: autocomplete beats email beats hint beats position", () => {
  // autocomplete="username" wins over everything, wherever it sits.
  let forms = findLoginForms([
    f({ kind: "email" }),
    f({ name: "loginname" }),
    f({ autocomplete: "username" }),
    f({ kind: "password" }),
  ]);
  assert.equal(forms[0].usernameIdx, 2);
  // email beats hint.
  forms = findLoginForms([f({ name: "user" }), f({ kind: "email" }), f({ kind: "password" })]);
  assert.equal(forms[0].usernameIdx, 1);
  // hint beats mere position.
  forms = findLoginForms([f(), f({ id: "Account" }), f(), f({ kind: "password" })]);
  assert.equal(forms[0].usernameIdx, 1);
  // otherwise the nearest text input before the password field.
  forms = findLoginForms([f(), f(), f({ kind: "password" })]);
  assert.equal(forms[0].usernameIdx, 1);
});

test("password-only form (two-step login) has null username", () => {
  const forms = findLoginForms([f({ kind: "password" })]);
  assert.equal(forms.length, 1);
  assert.equal(forms[0].usernameIdx, null);
});

test("two independent forms are both detected with their own fields", () => {
  const forms = findLoginForms([
    f({ formIndex: 0, name: "q" }), // search form, no password: not a login form
    f({ formIndex: 1, name: "user" }),
    f({ formIndex: 1, kind: "password" }),
    f({ formIndex: 2, kind: "email" }),
    f({ formIndex: 2, kind: "password" }),
  ]);
  assert.equal(forms.length, 2);
  assert.deepEqual(
    forms.map((x) => [x.usernameIdx, x.passwordIdx]),
    [
      [1, 2],
      [3, 4],
    ]
  );
});

test("inputs outside any form group together as one pseudo-form", () => {
  const forms = findLoginForms([
    f({ formIndex: -1 }),
    f({ formIndex: -1, kind: "password" }),
  ]);
  assert.equal(forms.length, 1);
  assert.equal(forms[0].formIndex, -1);
});
