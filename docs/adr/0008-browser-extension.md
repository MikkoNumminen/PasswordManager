# ADR 0008: Browser extension key handling and fill policy

## Status

Accepted (extension phase 1, read-only daily driver). Two decisions are
superseded by ADR 0009 (phase 2): the extension is no longer read-only, and
it now runs a standing content script for in-page autofill and save offers.
Key handling, session storage, the popup fill policy, and PSL matching stand.

## Context

The extension brings the same client-side crypto into the browser toolbar:
look up an entry for the current site and fill it without opening the web
page. It reuses `core` compiled to wasm32 through the existing wasm-bindgen
setup, so there is one crypto implementation. Two problems needed a decision:
how to hold the vault key across a Manifest V3 service worker that Chrome
evicts after about 30 seconds idle, and how to match an entry to the current
tab without becoming a phishing vector.

## Decision: key handling

The master password is never stored. After unlock the derived vault key is
kept in `chrome.storage.session`, which is memory-backed, never written to
disk, and cleared when the browser closes. `setAccessLevel` restricts it to
trusted extension contexts, so content scripts cannot read it. On each
service-worker wake the session is rebuilt from that key with
`Vault::from_key_bytes` (a new `core` method that skips Argon2 and verifies
the key against the key check). Without this, an evicted worker would drop
the key and force re-entering the master password constantly, and the
extension would be unusable.

`core` gained two methods for this, used only by the extension: `export_key`
returns the raw key bytes, and `from_key_bytes` reconstructs a vault from
them. They are documented as memory-only-store use; the CLI and web page do
not call them. The key crosses into JavaScript to reach session storage, but
it never leaves the extension and never touches disk.

Auto-lock clears the key via `chrome.alarms` on a configurable timer (5, 15,
60 minutes, or until the browser closes; default 15). Any API 401 or a failed
key check drops to locked. The decrypted search index (titles, usernames,
URLs) may live in session storage while unlocked; passwords are never in the
index and are decrypted one at a time on an explicit reveal, copy, or fill,
then dropped.

## Decision: fill and matching

Fill happens only on an explicit click on an entry's fill button in the popup.
At that moment the extension uses `activeTab` plus `chrome.scripting.execute-
Script` to inject the fill function into the current tab, so it needs no
standing content-script access to any site and never auto-fills on load.

Domain matching compares registrable domains (eTLD+1) computed from the
Public Suffix List, never string operations. `evil-example.com` and
`example.com` have different registrable domains, so they do not match;
`example.com.evil.com` resolves to `evil.com`, so it does not match either.
Exact host match ranks first, same-registrable-domain (subdomain) match
second, everything else is not a match. Picking an entry whose domain does
not match the current tab shows an explicit warning and requires a second
confirmation, and the service worker re-checks the match and refuses a
cross-domain fill unless that confirmation flag is set. The worker derives the
tab's host from the tab it is about to fill, not from what the popup passed, so
a tab that navigates after the popup opens cannot pass the check with a stale
host and receive the fill anyway. The PSL is bundled
(the extension may only connect to the configured server origin, so it cannot
fetch the list at runtime).

The injected function reads only form fields, fills username and password,
dispatches input and change events so page frameworks notice, and reports
what it filled. It never reads or sends other page content.

## Decision: server connection and permissions

The server URL and API token are user configuration in `chrome.storage.local`.
Host permission is requested at runtime for that one origin when the user
saves it in options, never `<all_urls>` and never a hardcoded list. Fetches
use `credentials: "include"` so the extension rides an auth gate's cookie
(oauth2-proxy or Cloudflare Access) if one fronts the server; the user signs
in once in a normal tab. An auth-gate redirect (HTML instead of API JSON) is
detected and surfaced as "sign in required" with a button to open the server,
rather than trying to drive an OAuth flow inside the extension.

Clipboard copy writes on the popup's user gesture and schedules a clear 30
seconds later through an offscreen document, which overwrites the clipboard
only if it still holds the copied value. This is best-effort and labeled as
such in the UI.

## Consequences

- The vault key sits in memory-backed session storage while unlocked. A
  compromised browser profile that can read another extension's session
  storage, or that runs as the user while unlocked, reads what the user can
  read, the same trust delta as any client in the threat model.
- No npm crypto, no second KDF or AEAD path. The only bundled third-party
  data is the Public Suffix List.
- Writes (add, edit, delete) stay in the CLI and web page for now; the
  extension is read-only. No write path is scaffolded.
