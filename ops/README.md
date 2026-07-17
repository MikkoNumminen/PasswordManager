# Operations: running and exposing the vault server

Two access paths and a control panel. No Rust here, just the built binaries
plus Tailscale and oauth2-proxy. Nothing in this directory contains a secret;
the Google credentials and cookie secret live outside the repo under
`%APPDATA%\PasswordManager\secrets\`.

Node: `paskamyrsky.tail6ed53b.ts.net`  (tailnet IP `100.101.51.19`)

## Shared funnel on this node

This machine runs three funnel-capable services and Tailscale Funnel allows
only three public ports (443, 8443, 10000):

| Service | Local | Funnel port | Gate | Managed by |
| --- | --- | --- | --- | --- |
| mikkonumminen.dev RAG chat | 127.0.0.1:8000 | 443 | none | `ragctl` (Python/WSL) |
| Feedback Intelligence | 127.0.0.1:5088 | 443 | none | `feedctl` (.NET) |
| PasswordManager vault | 127.0.0.1:4180 (gate) | 8443 | Google (oauth2-proxy) | this repo |

The two RAGs are GPU-bound, both use port 443, and run one at a time. The
vault needs no GPU and carries a Google gate, so it lives on **8443** and
coexists with whichever RAG holds 443. Every tool here scopes its changes to
its own port and never runs `tailscale funnel reset`, which would wipe all
three at once.

## Private path (tailnet, default)

Reachable only by devices in your tailnet, over the encrypted tailnet. No
public exposure, no gate, touches none of the shared funnel config.

```
ops\serve-tailnet.ps1              # serves on 100.101.51.19:7787
ops\serve-tailnet.ps1 -Web         # also serve the browser client
```

Clients: `password-manager sync --server http://100.101.51.19:7787`

The API token was generated once into `%APPDATA%\PasswordManager\server.db`
(only its hash is stored). Rotate it with:
`target\release\password-manager-server.exe --db %APPDATA%\PasswordManager\server.db token`

## Public path (opt-in, Google gate then vault)

```
internet
 -> Tailscale Funnel  https://paskamyrsky.tail6ed53b.ts.net:8443  (TLS at the edge)
   -> oauth2-proxy    Google login, your email only               [identity gate]
     -> password-manager-server 127.0.0.1:7787                    [API token + vault]
```

The vault server never sees identity and holds no key. Google decides who
reaches it; the API token and master password are the vault's own auth.

### One-time setup

1. Create a Google OAuth client (Google Cloud Console -> APIs & Services ->
   Credentials -> Create OAuth client ID -> Web application):
   - Authorized JavaScript origin: `https://paskamyrsky.tail6ed53b.ts.net:8443`
   - Authorized redirect URI: `https://paskamyrsky.tail6ed53b.ts.net:8443/oauth2/callback`
   - On the OAuth consent screen add your Google account as a test user.

2. Put the credentials in the out-of-repo secrets (already scaffolded; the
   cookie secret is filled in for you):
   - `%APPDATA%\PasswordManager\secrets\oauth2.env` -> set
     `OAUTH2_PROXY_CLIENT_ID` and `OAUTH2_PROXY_CLIENT_SECRET`.
   - `%APPDATA%\PasswordManager\secrets\allowed-emails.txt` -> your Google
     email, one per line. Only these pass the gate.

### Running it

```
ops\serve-public.ps1               # starts the vault (localhost) + oauth2-proxy
```

Then expose it with the control panel: toggle the vault on. Until you do,
oauth2-proxy runs but nothing is public.

Public address once the funnel is on: **https://paskamyrsky.tail6ed53b.ts.net:8443**

## Control panel

```
ops\funnel-control.ps1
```

Shows every funnel resource on this node and the state of ports 443 and 8443.

- The **vault** is owned by this panel: selecting it toggles its funnel on
  8443 (with a typed confirmation before going public).
- The **two RAGs** are shown read-only. Selecting one prints its own control
  command (`ragctl up`/`down`, `feedctl up`/`down`) and where to run it; the
  panel never touches their funnel, because their tools also manage Docker,
  Ollama, and the shared GPU.

The panel backs up the serve config to `%APPDATA%\PasswordManager\funnel-backups\`
before any change, scopes changes to one port, and never runs a reset.

To adjust a RAG's local port or tool later, edit `resources.json`.

## Security notes

- The public URL is a real, scannable, phishable target even behind the gate.
  Only ever reach the vault through `https://paskamyrsky.tail6ed53b.ts.net:8443`;
  a lookalike page could capture a master password.
- Master password strength is the true boundary. If the gate is bypassed and
  the API token leaks, the master password plus Argon2id (256 MiB) is all that
  remains, and even then only ciphertext ever leaves this machine.
- The two RAGs are intentionally unauthenticated (synthetic data, rate-limit +
  CORS only). The vault is the only gated service here, by design.
- Reachable only while this machine is on and the funnel is toggled on. Turn
  the funnel off when you are not using it.

## Secrets (none committed)

- Google client id/secret: `%APPDATA%\PasswordManager\secrets\oauth2.env`
- oauth2-proxy cookie secret: same file (generated locally)
- Allowlisted emails: `%APPDATA%\PasswordManager\secrets\allowed-emails.txt`
- API token: only its hash, in the server DB
- oauth2-proxy binary: `%APPDATA%\PasswordManager\tools\oauth2-proxy.exe`

All of the above live outside the repository. `.gitignore` also excludes env
and credential files as a backstop.
