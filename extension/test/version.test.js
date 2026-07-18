import { test } from "node:test";
import assert from "node:assert/strict";
import { isBehind } from "../src/version.js";

test("a newer latest version is behind", () => {
  assert.equal(isBehind("0.1.0", "0.2.0"), true);
  assert.equal(isBehind("0.1.0", "0.1.1"), true);
  assert.equal(isBehind("1.9.0", "1.10.0"), true); // numeric, not lexical
  assert.equal(isBehind("0.1", "0.1.1"), true); // shorter current
});

test("same or older latest is not behind", () => {
  assert.equal(isBehind("0.2.0", "0.2.0"), false);
  assert.equal(isBehind("0.2.0", "0.1.9"), false);
  assert.equal(isBehind("1.10.0", "1.9.0"), false);
  assert.equal(isBehind("0.1.1", "0.1"), false); // shorter latest
});

test("unparseable versions never report behind", () => {
  assert.equal(isBehind("0.1.0", ""), false);
  assert.equal(isBehind("", "0.2.0"), false);
  assert.equal(isBehind("0.1.0", "v0.2.0"), false);
  assert.equal(isBehind("0.1.0", null), false);
  assert.equal(isBehind(undefined, "0.2.0"), false);
  assert.equal(isBehind("0.1.0", "0.-1.0"), false);
});
