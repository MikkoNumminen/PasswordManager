# PasswordManager

A local-first, zero-knowledge password manager for personal use. One Rust
crypto implementation shared by every client.

- `core`: crypto, data model, storage trait, sqlite and remote backends.
  The only place crypto exists. Compiles natively and to wasm32.
- `cli`: the daily driver (`password-manager`). Works fully offline against a local
  sqlite vault; syncs when told to.
- `server`: sync server (`password-manager-server`). Stores ciphertext and non-secret
  metadata, nothing else. Cannot read vaults.
- `web`: browser client. The same `core` crypto compiled to wasm32;
  decryption happens in the browser, so the server stays zero-knowledge on
  this path too.
- `vaultctl`: control tool that runs and exposes the server on this machine
  (tailnet path, the Google-gated public path, and the shared Tailscale
  funnel). See `ops/README.md`.
- `extension`: Chrome (Manifest V3) browser extension. The same `core` crypto
  compiled to wasm32; looks up an entry for the current site and fills it,
  read-only. See the Browser extension section below.

## Threat model

What this protects against:

- A stolen disk or laptop. The vault file holds only ciphertext, a random
  salt, KDF parameters, and a key check blob. Without the master password
  there is nothing to read.
- A leaked backup. Same reasoning; backups of the vault file or the server
  database are ciphertext.
- A breach of the sync server. The server never sees the master password,
  the vault key, or plaintext. An attacker with the full server database
  gets ciphertext plus metadata (entry UUIDs, timestamps, sizes, count of
  entries). They can also delete or withhold data.

What this does not protect against:

- A compromised client while the vault is unlocked. Anything that runs as
  you on an unlocked machine can read what you can read.
- A keylogger. It captures the master password at entry.
- Memory scraping during use. Keys and plaintext are zeroized after use,
  which narrows the window; it does not close it.
- A weak master password. Argon2id makes guessing expensive per attempt,
  never impossible. The password is the security of the vault.
- Traffic and metadata analysis. The server learns when you sync, how many
  entries exist, and how large they are.
- Rollback by the server. A malicious server cannot forge or swap records
  (each ciphertext is bound to its UUID and timestamp), but it can serve
  an older complete record instead of the newest one.

The public web access path, when enabled, runs on Tailscale Funnel. The
server stays bound to localhost with no public IP. Tailscale Funnel forwards
an encrypted TCP stream from a ts.net hostname to this machine, where
tailscaled terminates TLS using the ts.net certificate; the funnel relay
carries only encrypted bytes and never sees plaintext traffic. In front of
the server, on this same machine, oauth2-proxy runs the identity gate:
Google sign-in restricted to an email allowlist. The vault server itself
contains no identity code; who may reach it is decided by oauth2-proxy
before a request arrives. The service is reachable only while this machine
is on and the funnel is toggled on.

What that path adds, plainly:

- A public URL is a scanning and phishing target even behind the gate. A
  convincing fake of the page could capture a master password from a
  careless moment; the real page is only ever served from this machine.
- Trust in Tailscale to route and relay, and in oauth2-proxy plus Google
  for identity. Because TLS terminates on this machine, the relay never
  terminates TLS or sees plaintext. If the gate is bypassed or
  misconfigured, an attacker reaches the API and, with the API token,
  ciphertext. From there the master password plus Argon2id is the entire
  remaining boundary. Password strength is the real security of this
  system; everything else buys time and reduces exposure.
- A compromised browser or browser session reads whatever you decrypt in
  it, exactly as on any client.

An alternative public path is Cloudflare Tunnel plus Cloudflare Access
(documented under Public exposure below). Its trust model differs: TLS
terminates at Cloudflare's edge, so Cloudflare sees the HTTP traffic (the
API token and request metadata, though vault payloads are still ciphertext),
and identity is enforced by Cloudflare Access rather than a local proxy.
Choose it only if you accept a third party terminating TLS in exchange for
edge features. The two paths are not run at once.

Public exposure is opt-in and off by default.

## Security design, in short

- Argon2id (256 MiB, 3 passes, 1 lane; far above library defaults, about
  430 ms per unlock natively) derives the vault key from the master
  password. Per-vault random salt. ADR 0001.
- XChaCha20-Poly1305 seals each entry under a fresh random 24 byte nonce
  on every write. ADR 0002, 0003.
- Ciphertext is bound to entry UUID and modified timestamp via associated
  data, so records cannot be swapped or re-stamped. Deletions are sealed
  under the vault key too, so the server cannot forge them. ADR 0005.
- Password correctness is checked only by an AEAD tag on decrypt. No hash
  or verifier of the password is stored. ADR 0004.
- Sync is last-write-wins with losing versions preserved as conflict
  copies, never silently dropped. Every record pulled from the server is
  verified under the vault key before it is stored, and change detection
  does not depend on device clocks agreeing. ADR 0006.
- The app checks one credential: the API token, which gates ciphertext
  access only. Identity on the public path is enforced outside the app:
  oauth2-proxy (Google, email allowlist) in front of the server on the
  Tailscale Funnel path in use, or Cloudflare Access on the alternative
  Cloudflare path. Neither identity nor the token is ever an input to key
  derivation; losing them exposes no vault contents. ADR 0007.
- The wasm client is served by the same server from the same machine. No
  third party hosts the crypto code the browser runs.
- Primitives are vetted RustCrypto crates: `argon2`, `chacha20poly1305`,
  `getrandom`, `zeroize`, `secrecy`, `subtle`. Nothing hand-rolled.

## CLI setup

```
cargo install --path cli
password-manager init
password-manager add "example.com"        # prompts for fields; -g 24 generates a password
password-manager list
password-manager get example              # password masked; --reveal prints it
password-manager edit example             # field by field; Enter keeps, - clears
password-manager rm example
```

The vault lives in the platform data directory by default (on Windows
`%APPDATA%\PasswordManager\data\vault.db`); `--vault` or
`PASSWORD_MANAGER_VAULT` overrides. The
master password is always prompted, never a command line argument. There
is no recovery: losing the master password loses the vault.

## Sync server on the tailnet (primary access path)

On the machine that hosts the server:

```
cargo install --path server
password-manager-server --db /path/to/password-manager-server.db token   # prints the API token once
password-manager-server --db /path/to/password-manager-server.db serve --bind <tailnet-ip>:7787
```

`<tailnet-ip>` is the machine's Tailscale address (`tailscale ip -4`,
typically 100.x.y.z). Binding to that address makes the server reachable
only inside your tailnet; Tailscale encrypts and authenticates the
transport between your devices. The default bind is 127.0.0.1:7787, which
serves nothing beyond the machine itself. Do not bind 0.0.0.0 unless you
mean to expose the port on every interface.

On each device:

```
password-manager sync --server http://<tailnet-ip>:7787   # prompts for the API token once
password-manager sync                                      # from then on
```

A fresh device with no vault adopts the vault from the server on first
sync and asks for the master password to unlock it. Conflicts are printed
and the losing version is kept as a `(conflict ...)` entry. The API token
is stored in the local vault database; it authorizes ciphertext access
only. After rotating the server token, run
`password-manager sync --set-token` to enter the new one.

## Web access page

Build the wasm client once (requires the wasm target and a matching
wasm-bindgen CLI):

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.126 --locked
cargo build -p password-manager-web --target wasm32-unknown-unknown --release
wasm-bindgen --target web --no-typescript --out-dir web/static/pkg target/wasm32-unknown-unknown/release/password_manager_web.wasm
```

Serve it with the server, from the same machine. The page, its JavaScript,
and the wasm crypto module all come from this process; no third party ever
hosts the code the browser runs:

```
password-manager-server serve --bind <tailnet-ip>:7787 --web-dir web/static
```

On the tailnet that is the whole setup: open the page, enter the API
token, unlock with the master password. Decryption happens in the browser;
the master password never leaves the page.

## Public exposure (opt-in)

Off by default. Two paths with different trust models; only one runs at a
time. Read the threat model section before enabling either.

### Tailscale Funnel plus oauth2-proxy (the path in use)

The server stays on localhost, oauth2-proxy provides the Google identity
gate in front of it, and Tailscale Funnel exposes the machine's ts.net
hostname. TLS terminates on this machine, and the funnel relay forwards only
encrypted TCP. The full operational setup and the `vaultctl` control tool
that runs it are in `ops/README.md`. In short:

1. Keep the server bound to localhost.
2. Create a Google OAuth client (Web application), with the ts.net funnel
   URL as an authorized origin and `.../oauth2/callback` as a redirect URI.
3. Put the client id, client secret, and your allowlisted email in the
   out-of-repo secrets under the data directory (never in this repo).
4. `vaultctl up` starts the vault, the oauth2-proxy gate, and the funnel;
   `vaultctl down` stops and unexposes.

### Cloudflare Tunnel plus Cloudflare Access (alternative)

A different trust model: TLS terminates at Cloudflare's edge, Cloudflare
sees the HTTP traffic (the API token and metadata, though vault payloads
stay ciphertext), and Cloudflare Access enforces identity rather than a
local proxy. Keep the server on localhost, then:

```
cloudflared tunnel create password-manager
cloudflared tunnel route dns password-manager vault.example.com
cloudflared tunnel run password-manager
```

In Cloudflare Zero Trust, add Google as an identity provider and create an
Access application for the hostname with an Allow policy restricted to your
email. The tunnel token lives in an environment variable or the cloudflared
service store, never in this repository.

Both paths keep the vault server free of identity code, and neither
identity nor the API token is ever an input to key derivation.

## Secrets

Nothing secret is committed. On the Tailscale Funnel path, the Google OAuth
client id and secret and the oauth2-proxy cookie secret live outside the
repo under the data directory. On the Cloudflare alternative, the Google
client id and secret live in Cloudflare and the tunnel token in an
environment variable. Either way the API token exists only as a hash on the
server and in each client's local storage. `.gitignore` excludes env files,
key material, and credential files as a backstop.

## Browser extension

A Chrome Manifest V3 extension that fills credentials from the vault into the
current tab, without opening the web page. It reuses the same `core` crypto
compiled to wasm32; the master password and vault key never leave the
extension, and the server still only serves ciphertext. It is read-only:
add, edit, and delete stay in the CLI and web page.

What it does: unlock, search, view (masked, reveal on click), fill into the
current tab on an explicit click, and copy to the clipboard. It never
auto-fills on page load, and it fills only when the entry's registrable
domain (eTLD+1, via the Public Suffix List) matches the current tab, with an
explicit warning and a second confirmation for a deliberate mismatch.

Trust delta: a compromised browser profile reads whatever you decrypt in it,
the same as any client. The vault key sits in memory-backed session storage
(never on disk) while unlocked and is cleared on auto-lock or when the browser
closes.

Build and load:

```
cd extension
pwsh build.ps1        # builds the wasm and downloads the Public Suffix List into vendor/
```

Then open `chrome://extensions`, enable Developer mode, Load unpacked, and
pick the `extension/` directory. Open the extension's options, set the server
URL and API token (Chrome will prompt to grant access to that one origin),
and, if the public path is behind an auth gate, sign in once in a normal tab
so the extension can ride the cookie.

Extension tests (registrable-domain matching, including the phishing cases):

```
cd extension
node --test test/psl.test.js
```

Manual test checklist:

- Unlock with the master password; a wrong password is rejected.
- Search; entries for the current site show first, with an "all sites" toggle.
- Fill on a site whose domain matches an entry.
- Pick an entry whose domain does not match the tab: the fill is refused until
  you confirm the warning.
- Wait for the auto-lock timer: the vault locks and asks for the master
  password again.
- Copy a password: it clears from the clipboard after 30 seconds if unchanged.
- Behind an auth gate, a fetch that hits the login page shows "sign in
  required" with a button to open the server.

## Development

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```

Tests include known answer vectors for the AEAD and KDF, tamper detection,
a zero-knowledge check that inspects the raw server database for plaintext
after real pushes, and a two-device sync over real HTTP. Architecture
decision records live in `docs/adr/`.
