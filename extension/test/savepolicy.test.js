import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePsl } from "../src/psl.js";
import { sameSite, shouldOfferSave, SAVE_TTL_MS } from "../src/savepolicy.js";

const RULES = parsePsl(`
com
co.uk
`);

test("sameSite: registrable-domain equality, not string equality", () => {
  assert.equal(sameSite("login.example.com", "app.example.com", RULES), true);
  assert.equal(sameSite("example.com", "example.com", RULES), true);
  assert.equal(sameSite("evil-example.com", "example.com", RULES), false);
  assert.equal(sameSite("example.co.uk", "example.com", RULES), false);
});

test("sameSite: IPs and single-label hosts fall back to exact equality", () => {
  assert.equal(sameSite("127.0.0.1", "127.0.0.1", RULES), true);
  assert.equal(sameSite("127.0.0.1", "127.0.0.2", RULES), false);
  assert.equal(sameSite("localhost", "localhost", RULES), true);
  assert.equal(sameSite("localhost", "example.com", RULES), false);
});

const NOW = 1_000_000_000;
const pendingFor = (over = {}) => ({
  id: "offer-1",
  host: "login.example.com",
  username: "alice",
  password: "pw",
  ts: NOW,
  ...over,
});
const ask = (over = {}) => {
  const { pending, ...rest } = over;
  return shouldOfferSave({
    pending: pendingFor(pending || {}),
    now: NOW,
    senderHost: "login.example.com",
    index: [],
    neverList: [],
    ruleset: RULES,
    locked: false,
    ...rest,
  });
};

test("fresh unknown credential is offered", () => {
  assert.deepEqual(ask(), { offer: true, reason: "offer" });
});

test("expired capture is not offered", () => {
  const r = ask({ now: NOW + SAVE_TTL_MS + 1 });
  assert.deepEqual(r, { offer: false, reason: "expired" });
});

test("cross-subdomain within the registrable domain still offers", () => {
  const r = ask({ senderHost: "app.example.com" });
  assert.equal(r.offer, true);
});

test("a different site does not receive the offer", () => {
  const r = ask({ senderHost: "evil-example.com" });
  assert.deepEqual(r, { offer: false, reason: "different-site" });
});

test("never-listed domain suppresses", () => {
  const r = ask({ neverList: ["example.com"] });
  assert.deepEqual(r, { offer: false, reason: "never-listed" });
});

test("known same-site username suppresses, case- and space-insensitive", () => {
  const index = [{ id: "1", title: "t", username: " Alice ", url: "https://example.com" }];
  assert.deepEqual(ask({ index }), { offer: false, reason: "known" });
});

test("same username on a different site does not suppress", () => {
  const index = [{ id: "1", title: "t", username: "alice", url: "https://other.com" }];
  assert.equal(ask({ index }).offer, true);
});

test("different username on the same site offers", () => {
  const index = [{ id: "1", title: "t", username: "bob", url: "https://example.com" }];
  assert.equal(ask({ index }).offer, true);
});

test("empty username matches only an entry with an empty username", () => {
  const emptyPending = { pending: { username: "" } };
  const withUser = [{ id: "1", title: "t", username: "bob", url: "https://example.com" }];
  const withEmpty = [{ id: "1", title: "t", username: "", url: "https://example.com" }];
  assert.equal(ask({ ...emptyPending, index: withUser }).offer, true);
  assert.equal(ask({ ...emptyPending, index: withEmpty }).offer, false);
});

test("locked defers the dedup check and flags the offer", () => {
  const index = [{ id: "1", title: "t", username: "alice", url: "https://example.com" }];
  const r = ask({ index, locked: true });
  assert.deepEqual(r, { offer: true, reason: "offer-locked" });
});

test("no pending means no offer", () => {
  const r = shouldOfferSave({
    pending: null,
    now: NOW,
    senderHost: "example.com",
    index: [],
    neverList: [],
    ruleset: RULES,
    locked: false,
  });
  assert.deepEqual(r, { offer: false, reason: "none" });
});
