import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePsl, registrableDomain, matchLevel } from "../src/psl.js";

// A small slice of the real Public Suffix List: a plain TLD, a multi-label
// suffix, a private suffix, and a wildcard with an exception.
const RULES = parsePsl(`
// comment line
com
co.uk
github.io
ck
*.ck
!www.ck
`);

const rd = (h) => registrableDomain(h, RULES);
const ml = (a, b) => matchLevel(a, b, RULES);

test("registrable domain of ordinary hosts", () => {
  assert.equal(rd("example.com"), "example.com");
  assert.equal(rd("www.example.com"), "example.com");
  assert.equal(rd("a.b.c.example.com"), "example.com");
  assert.equal(rd("foo.co.uk"), "foo.co.uk");
  assert.equal(rd("a.b.co.uk"), "b.co.uk");
});

test("a public suffix itself has no registrable domain", () => {
  assert.equal(rd("com"), null);
  assert.equal(rd("co.uk"), null);
  assert.equal(rd("github.io"), null);
  assert.equal(rd("user.github.io"), "user.github.io");
});

test("wildcard and exception rules", () => {
  assert.equal(rd("a.ck"), null); // *.ck: a.ck is a public suffix
  assert.equal(rd("b.a.ck"), "b.a.ck"); // one label under the *.ck suffix
  assert.equal(rd("www.ck"), "www.ck"); // !www.ck exception: suffix is just ck
});

test("the anti-phishing property: lookalikes never match", () => {
  // The whole reason this module exists.
  assert.equal(ml("evil-example.com", "example.com"), "none");
  assert.equal(ml("example.com.evil.com", "example.com"), "none");
  assert.equal(ml("notexample.com", "example.com"), "none");
  assert.equal(ml("example.co.uk", "example.com"), "none");
});

test("legitimate matches", () => {
  assert.equal(ml("example.com", "example.com"), "exact");
  assert.equal(ml("login.example.com", "www.example.com"), "subdomain");
  assert.equal(ml("example.com", "www.example.com"), "subdomain");
});

test("IDN / punycode hosts compare on their ASCII labels", () => {
  // URL.hostname yields punycode; two punycode hosts match only if equal.
  assert.equal(rd("shop.xn--80ak6aa92e.com"), "xn--80ak6aa92e.com");
  assert.equal(ml("sub.xn--80ak6aa92e.com", "xn--80ak6aa92e.com"), "subdomain");
  // A different punycode label is a different domain, not a match.
  assert.equal(ml("xn--80ak6aa92e.com", "xn--e1afmkfd.com"), "none");
});

test("IP hosts match only themselves", () => {
  assert.equal(ml("192.168.1.10", "192.168.1.10"), "exact");
  assert.equal(ml("192.168.1.10", "192.168.1.11"), "none");
  assert.equal(ml("192.168.1.10", "example.com"), "none");
});
