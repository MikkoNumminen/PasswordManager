# Operations: vaultctl

`vaultctl` is the control tool for the PasswordManager vault, the sibling of
`ragctl` (mikkonumminen.dev) and `feedctl` (feedback-intelligence). It owns
the vault's processes and its funnel port, and shows the RAGs read-only. Build
it with `cargo build --release -p vaultctl`; the binary is
`target\release\vaultctl.exe`.

Node: `paskamyrsky.tail6ed53b.ts.net`  (tailnet IP `100.101.51.19`)

Nothing here contains a secret. The Google credentials, cookie secret, and
API token live outside the repo under `%APPDATA%\PasswordManager\`.

## Commands

```
vaultctl tailnet      # private: vault on the tailnet IP, no gate, no funnel
vaultctl up           # public: vault (localhost) + Google gate + funnel 8443
vaultctl down         # stop the funnel, the gate, and the vault
vaultctl status       # what is running and what is exposed (incl. the RAGs)
vaultctl funnel on    # toggle only the vault's funnel (leaves processes)
vaultctl funnel off
vaultctl token        # rotate the API token into the secrets file
vaultctl doctor       # check everything needed to go public is in place
vaultctl logs vault   # tail a process log (vault | gate)
```

The vault runs on demand, not as an always-on service. Start it when you need
it, `vaultctl down` when you are done.

## Shared funnel on this node

Tailscale Funnel allows only three public ports (443, 8443, 10000):

| Service | Local | Funnel port | Gate | Managed by |
| --- | --- | --- | --- | --- |
| mikkonumminen.dev RAG chat | 127.0.0.1:8000 | 443 | none | `ragctl` |
| Feedback Intelligence | 127.0.0.1:5088 | 443 | none | `feedctl` |
| PasswordManager vault | 127.0.0.1:4180 (gate) | 8443 | Google (oauth2-proxy) | `vaultctl` |

The two RAGs are GPU-bound, both use port 443, and run one at a time. The
vault needs no GPU and carries a Google gate, so it sits on 8443 and coexists
with whichever RAG holds 443. `vaultctl` only ever touches port 8443 and never
runs `tailscale funnel reset`, so it cannot disturb the RAGs.

## Private path (tailnet, default)

```
vaultctl tailnet
```

Serves on `100.101.51.19:7787`, reachable only inside the tailnet. Clients:
`password-manager sync --server http://100.101.51.19:7787`.

## Public path (Google gate then vault)

```
internet
 -> Tailscale Funnel  https://paskamyrsky.tail6ed53b.ts.net:8443  (TLS at the edge)
   -> oauth2-proxy    Google login, your email only               [identity gate]
     -> password-manager-server 127.0.0.1:7787                    [API token + vault]
```

One-time setup:

1. Create a Google OAuth client (Google Cloud Console -> APIs & Services ->
   Credentials -> OAuth client ID -> Web application):
   - Authorized JavaScript origin: `https://paskamyrsky.tail6ed53b.ts.net:8443`
   - Authorized redirect URI: `https://paskamyrsky.tail6ed53b.ts.net:8443/oauth2/callback`
   - Add your Google account as a test user on the consent screen.
2. Fill the out-of-repo secrets:
   - `%APPDATA%\PasswordManager\secrets\oauth2.env` -> `OAUTH2_PROXY_CLIENT_ID`
     and `OAUTH2_PROXY_CLIENT_SECRET` (the cookie secret is already generated).
   - `%APPDATA%\PasswordManager\secrets\allowed-emails.txt` -> your email.
3. `vaultctl doctor` to confirm, then `vaultctl up`.

Public address: **https://paskamyrsky.tail6ed53b.ts.net:8443**

There must be a vault synced to the server before the web page can unlock:
create one with the CLI (`password-manager init`, `add`) and `sync` it over
the tailnet path. Until then the page says "no vault on this server yet".

## Security notes

- The public URL is a real, scannable, phishable target even behind the gate.
  Only ever reach the vault through the exact URL above; a lookalike could
  capture a master password.
- Master password strength is the true boundary. If the gate is bypassed and
  the API token leaks, the master password plus Argon2id (256 MiB) is all that
  remains, and only ciphertext ever leaves this machine.
- The two RAGs are intentionally unauthenticated; the vault is the only gated
  service, by design.

## Files

- `oauth2-proxy.cfg` - non-secret gate config (`vaultctl` runs oauth2-proxy with it)
- `resources.json` - the shared-funnel registry `vaultctl status` reads
- Secrets, the API token, the oauth2-proxy binary, PID files, logs, and
  config backups all live under `%APPDATA%\PasswordManager\` (and its
  `.vaultctl\` subdirectory), never in the repo.
