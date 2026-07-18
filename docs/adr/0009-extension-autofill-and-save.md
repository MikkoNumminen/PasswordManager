# ADR 0009: Extension in-page autofill and credential capture

## Status

Accepted (extension phase 2). Supersedes two decisions of ADR 0008: the
extension is no longer read-only, and it now has standing access to pages.
Every other 0008 decision (key handling, session storage, popup fill policy,
bundled PSL) stands.

## Context

Daily-driver parity with commercial password managers needs two behaviors the
phase 1 extension deliberately lacked: an autofill offer on the login page
itself, and an offer to save credentials the user typed by hand. Both require
a content script present on pages before the user asks for anything, and the
save path requires the extension to write an entry to the vault.

## Decision: standing content script

A declarative content script runs on all http and https pages, top frame
only. It detects login forms (exactly one visible password field; forms with
two or more, signup-with-confirm and change-password, are left alone) and
renders its UI in closed shadow roots.

What keeps this from widening the secret surface:

- Content scripts hold no vault state. `chrome.storage.session` stays
  restricted to trusted contexts; everything arrives by messaging the worker.
- The worker trusts nothing a page-side script claims. For every `cs.*`
  message it derives the host from `sender.url`, which Chrome sets and pages
  cannot forge, and it rejects non-top frames.
- Payload minimization: a page's content script can receive at most the
  titles and usernames of entries matching its own registrable domain, the
  single credential it requested by id, and a save offer that never echoes
  the captured password back.
- The fill gate: credential values leave the worker only when the sender's
  host and the entry's host share a registrable domain (PSL matching, ADR
  0008). Unlike the popup, this path has no user-confirmable mismatch
  override. A compromised page can at most obtain credentials stored for its
  own domain, which is the definition of autofill.
- Both features are disabled on the configured server's own origin. The
  master password is typed on that page; the extension must never offer to
  fill or capture anything there.
- The in-page UI is not a security boundary. A hostile page can hide,
  remove, or cover the dropdown and banner, and could draw a lookalike. It
  gains nothing by doing so: the real UI carries no secrets, and spoofed UI
  cannot make the worker release cross-domain values.
- Merely focusing a login field does not reset the auto-lock timer; only a
  fill or a save does.

Cost, stated plainly: Chrome's install prompt changes to "read and change all
your data on all websites". That is the honest price of automatic detection,
and the reason phase 1 shipped without it.

## Decision: write path

The extension gains exactly one write operation: creating an entry from a
captured login. It reuses the web client's path verbatim: seal with
`Session.seal_entry` (same wasm, crypto stays client-side), `PUT
/api/v1/entries/{id}` with a fresh UUID and a last-write-wins timestamp. The
server still only ever sees ciphertext. After a save the worker refetches and
re-indexes entries, so the new entry appears everywhere without relocking.
Editing and deleting stay in the CLI and web page.

## Decision: pending-save custody

Captured credentials are held by the worker in `chrome.storage.session`
(memory only, cleared when the browser closes) for at most 120 seconds, in a
single slot where the newest capture wins. The capture is dropped the moment
it is saved, dismissed, never-listed, expired, or recognized as already
known. Known means: an entry with the same registrable domain and the same
username exists. Passwords are not compared, since that would mean decrypting
every same-site entry at capture time; the accepted consequence is that a
changed password does not re-prompt in v1.

The "never for this site" list stores registrable domains in
`chrome.storage.local`, is edited only by the worker, and suppresses only the
save offer, never autofill. It is managed in the options page.

## Consequences

- The dropdown and banner inherit the browser's trust model: a compromised
  browser or profile reads whatever the user can read, unchanged from ADR
  0008.
- Out of scope for v1, deliberately: iframe logins (top frame only), HTTP
  Basic auth, password-update prompts, filling on hosts with no registrable
  domain (localhost and friends; the popup has the same limit), Firefox.
- The SPA fallback (offer on the same page ~4 s after a captured submit that
  navigates nowhere) can offer to save credentials that failed to log in.
  Commercial managers share this false positive; the TTL and dedup bound it.
- Possible follow-ups: an options kill-switch for the in-page features,
  update-password prompts, unifying the popup's ranking with rank.js.
