// Save-offer policy: pure decisions, node-tested. The background worker asks
// these questions; content scripts never see the inputs to the reasoning
// (index, never-list, pending credentials).

import { registrableDomain, hostOf } from "./psl.js";

// How long a captured credential may wait for its post-login page before the
// offer expires. Bounds how long a typed password sits in session storage
// when the user never answers the banner.
export const SAVE_TTL_MS = 120_000;

// Two hosts belong to the same site when their registrable domains match.
// IPs and single-label hosts (localhost, intranet names) have no registrable
// domain and fall back to exact host equality.
export function sameSite(hostA, hostB, ruleset) {
  const a = (hostA || "").toLowerCase();
  const b = (hostB || "").toLowerCase();
  if (!a || !b) return false;
  const ra = registrableDomain(a, ruleset);
  const rb = registrableDomain(b, ruleset);
  if (ra && rb) return ra === rb;
  return a === b;
}

// Decide whether a pending capture should be offered on the page asking.
// Also used at capture time (now === pending.ts, senderHost === pending.host)
// so the storing and offering decisions cannot drift apart. The reason string
// is for tests and the caller's cleanup logic only.
export function shouldOfferSave({ pending, now, senderHost, index, neverList, ruleset, locked }) {
  if (!pending) return { offer: false, reason: "none" };
  if (now - pending.ts > SAVE_TTL_MS) return { offer: false, reason: "expired" };
  if (!sameSite(pending.host, senderHost, ruleset)) return { offer: false, reason: "different-site" };
  const domain = registrableDomain((senderHost || "").toLowerCase(), ruleset) || (senderHost || "").toLowerCase();
  if ((neverList || []).includes(domain)) return { offer: false, reason: "never-listed" };
  // While locked the index cannot be consulted; offer anyway and let the
  // caller re-run this check after unlock (the offer carries locked: true).
  if (!locked && isKnown(pending, index, ruleset)) return { offer: false, reason: "known" };
  return { offer: true, reason: locked ? "offer-locked" : "offer" };
}

// A credential is known when a same-site entry has the same username
// (case-insensitive, trimmed; empty matches empty). Passwords are not
// compared: that would mean decrypting every same-site entry. Consequence,
// documented in ADR 0009: a changed password does not re-prompt in v1.
function isKnown(pending, index, ruleset) {
  const user = (pending.username || "").trim().toLowerCase();
  return (index || []).some((e) => {
    const host = hostOf(e.url);
    if (!host || !sameSite(host, pending.host, ruleset)) return false;
    return (e.username || "").trim().toLowerCase() === user;
  });
}
