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

The public web access path, when enabled, works like this: the server runs
self-hosted on my machine with no public IP, a Cloudflare Tunnel connects
outward, and Cloudflare Access gates the hostname at the edge with Google
as the identity provider and an email allowlist. Identity is enforced
before any request reaches the app; the app itself contains no OAuth or
identity code. The service is reachable only while my machine is on.

What that path adds, plainly:

- A public URL is a scanning and phishing target even behind the edge
  gate. A convincing fake of the page could capture a master password
  from a careless moment; the real page is only ever served from my
  origin through my hostname.
- Trust in Cloudflare to enforce the Access policy. If the edge gate is
  bypassed or misconfigured, an attacker reaches the API and, with the
  API token, ciphertext. From there the master password plus Argon2id is
  the entire remaining boundary. Password strength is the real security
  of this system; everything else buys time and reduces exposure.
- A compromised browser or browser session reads whatever you decrypt in
  it, exactly as on any client.

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
  access only. Identity on the public path (Cloudflare Access with
  Google) is enforced at the edge, outside the app, and neither is ever
  an input to key derivation. Losing them exposes no vault contents.
  ADR 0007.
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

## Public exposure (opt-in, Cloudflare Tunnel plus Access)

Off by default. Enabling it is a deliberate multi-step act, and the app
itself contains no identity code; who may reach it is decided at
Cloudflare's edge before a request arrives.

1. Keep the server bound to localhost: `--bind 127.0.0.1:7787`.
2. Create a named tunnel and route a hostname of your own domain to it
   (pick the hostname freely; it is configuration, not code):

```
cloudflared tunnel create password-manager
cloudflared tunnel route dns password-manager vault.example.com
cloudflared tunnel run password-manager
```

   The tunnel config maps `vault.example.com` to
   `http://127.0.0.1:7787`. The origin has no public IP and no open
   inbound port; `cloudflared` connects outward. Run it with the tunnel
   token in an environment variable or the cloudflared service store,
   never in this repository.

3. In Cloudflare Zero Trust, add Google as an identity provider (its
   client id and secret live in Cloudflare, not here), then create an
   Access application for `vault.example.com` with an Allow policy
   restricted to your email. From then on Cloudflare serves a Google
   login at the edge, and only allowlisted identities ever reach the
   tunnel.

Cloudflare Access and Google decide who can reach the service and nothing
else. They are never inputs to key derivation, and a valid Google session
still yields only ciphertext without the master password. Read the threat
model section on this path before enabling it.

## Secrets

Nothing secret is committed. The Google OAuth client id and secret live in
Cloudflare, the tunnel token lives in an environment variable or the
cloudflared service store, and the API token exists only as a hash on the
server and in each client's local database. `.gitignore` excludes env
files, key material, and cloudflared credentials as a backstop.

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
