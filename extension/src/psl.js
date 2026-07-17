// Registrable-domain (eTLD+1) matching via the Public Suffix List.
//
// This is the anti-phishing core: evil-example.com must never match
// example.com. String splitting cannot do this correctly (co.uk, github.io,
// etc.), so we run the real PSL algorithm. The pure functions below take a
// parsed ruleset and are unit-tested; loadRuleset() is the browser loader.

// Parse public_suffix_list.dat into { rules, exceptions }. Rules may contain
// "*" wildcards; exception lines start with "!".
export function parsePsl(text) {
  const rules = [];
  const exceptions = [];
  for (let line of text.split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("//")) continue;
    // Only the part before whitespace is the rule.
    line = line.split(/\s/)[0].toLowerCase();
    if (!line) continue;
    if (line.startsWith("!")) exceptions.push(line.slice(1));
    else rules.push(line);
  }
  return { rules: new Set(rules), exceptions: new Set(exceptions) };
}

function isIp(host) {
  if (host.includes(":")) return true; // IPv6
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host); // IPv4
}

function normalizeHost(host) {
  return (host || "").toLowerCase().replace(/\.$/, "");
}

// A rule matches a host when, aligned from the right, each rule label equals
// the host label or is "*".
function suffixMatch(hostLabels, ruleLabels) {
  if (ruleLabels.length > hostLabels.length) return false;
  for (let i = 1; i <= ruleLabels.length; i++) {
    const rl = ruleLabels[ruleLabels.length - i];
    const hl = hostLabels[hostLabels.length - i];
    if (rl !== "*" && rl !== hl) return false;
  }
  return true;
}

// Number of labels forming the public suffix, per the PSL algorithm.
function publicSuffixLength(labels, ruleset) {
  // Exceptions win: the public suffix is the exception rule minus its
  // leftmost label.
  for (const ex of ruleset.exceptions) {
    const r = ex.split(".");
    if (suffixMatch(labels, r)) return r.length - 1;
  }
  let best = 0;
  for (const rule of ruleset.rules) {
    const r = rule.split(".");
    if (suffixMatch(labels, r) && r.length > best) best = r.length;
  }
  // No rule matches: the prevailing rule is "*", one label.
  return best === 0 ? 1 : best;
}

// The registrable domain (eTLD+1) of a host, or null if the host is itself a
// public suffix or has none (e.g. an IP address).
export function registrableDomain(host, ruleset) {
  host = normalizeHost(host);
  if (!host) return null;
  if (isIp(host)) return host; // IPs match only themselves; handled by caller
  const labels = host.split(".");
  const suffixLen = publicSuffixLength(labels, ruleset);
  if (labels.length <= suffixLen) return null; // host is a public suffix
  return labels.slice(labels.length - suffixLen - 1).join(".");
}

// How an entry's host relates to the current tab's host:
//   "exact"     - same host
//   "subdomain" - same registrable domain, different host
//   "none"      - different registrable domains (or unresolvable)
// evil-example.com vs example.com resolves to different registrable domains,
// so it is "none". That is the property this whole file exists to guarantee.
export function matchLevel(tabHost, entryHost, ruleset) {
  const t = normalizeHost(tabHost);
  const e = normalizeHost(entryHost);
  if (!t || !e) return "none";
  if (isIp(t) || isIp(e)) return t === e ? "exact" : "none";
  const rt = registrableDomain(t, ruleset);
  const re = registrableDomain(e, ruleset);
  if (!rt || !re || rt !== re) return "none";
  return t === e ? "exact" : "subdomain";
}

// The host of a URL string, or "" if it does not parse.
export function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Browser-only: load and cache the bundled PSL.
let cached = null;
export async function loadRuleset() {
  if (cached) return cached;
  const url = chrome.runtime.getURL("vendor/public_suffix_list.dat");
  const text = await (await fetch(url)).text();
  cached = parsePsl(text);
  return cached;
}
