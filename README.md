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

The public web access path, when enabled, adds internet-facing attack
surface: the server endpoint, the OAuth gate, and the browser runtime all
become reachable from outside. The server stays zero-knowledge on that
path, and the tradeoff is real: a reachable endpoint can be probed, and a
compromised browser or browser session reads whatever you decrypt in it.
Public exposure is opt-in and off by default.

## Security design, in short

- Argon2id (RFC 9106: 64 MiB, 3 passes, 1 lane) derives the vault key from
  the master password. Per-vault random salt. ADR 0001.
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
- Credentials (API token, Google OIDC) gate ciphertext access only and are
  never inputs to key derivation. Losing them exposes no vault contents.
  ADR 0007.
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

## Web access page (opt-in public path)

Build the wasm client once (requires the wasm target and a matching
wasm-bindgen CLI):

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.126 --locked
cargo build -p password-manager-web --target wasm32-unknown-unknown --release
wasm-bindgen --target web --no-typescript --out-dir web/static/pkg target/wasm32-unknown-unknown/release/password_manager_web.wasm
```

Serve it with the server:

```
password-manager-server serve --bind <tailnet-ip>:7787 --web-dir web/static
```

On the tailnet the page works with the API token. For public exposure, add
the Google OIDC gate:

1. Create an OAuth client id (type: Web application) in the Google Cloud
   console. Add your public origin to the authorized JavaScript origins.
2. Run the server with the gate:

```
password-manager-server serve --bind 127.0.0.1:7787 --web-dir web/static \
    --google-client-id <id>.apps.googleusercontent.com \
    --allowed-email you@example.com
```

3. Publish the port through a tunnel you set up deliberately, for example
   Cloudflare Tunnel (`cloudflared tunnel --url http://127.0.0.1:7787`
   for a quick test, or a named tunnel with your own domain for real use).
   The tunnel provides TLS.

The page signs you in with Google, pulls ciphertext, and decrypts in the
browser with the master password. Google's ID token authorizes ciphertext
access only; the master password never leaves the page. Deriving the key
in the browser takes a few seconds by design.

Remember what the threat model says about this path before enabling it.

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
