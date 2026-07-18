// Rank index entries for a host: exact host match first, then same
// registrable domain, everything else excluded. Mirrors the popup's ordering
// so the inline dropdown and the popup agree on what "matches this site"
// means. Background-side module; the content script only ever receives the
// result rows, never the index.

import { matchLevel, hostOf } from "./psl.js";

export function rankMatches(tabHost, index, ruleset, cap = 10) {
  const rank = { exact: 0, subdomain: 1 };
  const rows = (index || [])
    .map((e) => ({ e, level: matchLevel(tabHost, hostOf(e.url), ruleset) }))
    .filter((r) => r.level !== "none")
    .sort((a, b) => rank[a.level] - rank[b.level] || a.e.title.localeCompare(b.e.title));
  return {
    matches: rows.slice(0, cap).map((r) => ({
      id: r.e.id,
      title: r.e.title,
      username: r.e.username || "",
      level: r.level,
    })),
    more: rows.length > cap,
  };
}
