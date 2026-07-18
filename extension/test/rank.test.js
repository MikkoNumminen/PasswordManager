import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePsl } from "../src/psl.js";
import { rankMatches } from "../src/rank.js";

const RULES = parsePsl(`
com
co.uk
`);

const entry = (id, title, url, username = "u") => ({ id, title, username, url });

test("exact host ranks before same-registrable-domain", () => {
  const index = [
    entry("1", "sub", "https://login.example.com"),
    entry("2", "exact", "https://example.com"),
  ];
  const { matches } = rankMatches("example.com", index, RULES);
  assert.deepEqual(
    matches.map((m) => [m.id, m.level]),
    [
      ["2", "exact"],
      ["1", "subdomain"],
    ]
  );
});

test("non-matching and lookalike hosts are excluded entirely", () => {
  const index = [
    entry("1", "other", "https://other.com"),
    entry("2", "evil", "https://evil-example.com"),
    entry("3", "nested", "https://example.com.evil.com"),
    entry("4", "real", "https://example.com"),
  ];
  const { matches } = rankMatches("example.com", index, RULES);
  assert.deepEqual(
    matches.map((m) => m.id),
    ["4"]
  );
});

test("ties break by title, and the cap reports more", () => {
  const index = Array.from({ length: 12 }, (_, i) =>
    entry(String(i), `t${String(i).padStart(2, "0")}`, "https://example.com")
  );
  const { matches, more } = rankMatches("example.com", index, RULES);
  assert.equal(matches.length, 10);
  assert.equal(more, true);
  assert.equal(matches[0].title, "t00");
});

test("rows carry no url and no password fields", () => {
  const index = [{ id: "1", title: "a", username: "u", url: "https://example.com", password: "leak?" }];
  const { matches } = rankMatches("example.com", index, RULES);
  assert.deepEqual(Object.keys(matches[0]).sort(), ["id", "level", "title", "username"]);
});

test("empty tab host or empty index yields nothing", () => {
  assert.deepEqual(rankMatches("", [entry("1", "a", "https://example.com")], RULES).matches, []);
  assert.deepEqual(rankMatches("example.com", [], RULES).matches, []);
});
