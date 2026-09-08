# PO Token Server

A self-hosted, multi-user **PO Token server** for Home Assistant. It issues the
"PO tokens" that yt-dlp and Music Assistant need to stream YouTube (and
YouTube Music) reliably — and it does so through a proper, automated
**OAuth 2.0 / OpenID Connect** login instead of manual browser-cookie
scraping.

---

## Origin & the problem it solves

Music Assistant's YouTube Music provider (and yt-dlp in general) depend on
**PO tokens** — short-lived, per-client proof-of-origin tokens that YouTube
requires for many streams. Without a valid PO token, playback fails or is
throttled.

The common way to supply these tokens is the third-party
[`bgutil-ytdlp-pot-provider`](https://github.com/Brainicism/bgutil-ytdlp-pot-provider)
add-on. In practice that setup has two painful gaps:

1. **Manual cookie extraction.** You have to log in to YouTube in a browser,
   scrape the session cookie, and paste it into the provider's configuration.
   The cookie expires, the step has to be repeated, and it is fragile and
   error-prone — especially on a headless Home Assistant OS box where there is
   no browser to scrape from.
2. **Single-user, single-credential.** The add-on is effectively tied to one
   scraped credential. It does not cleanly support several household members
   each using their own Google account, nor does it give each client (e.g. one
   Music Assistant provider instance per user) its own scoped credential.

`po-token-server` was built to close both gaps.

## Purpose

Provide a **secure, automated, multi-user** replacement for the bgutil add-on
that:

- **Eliminates manual cookie extraction.** Users sign in once through standard
  OAuth 2.0 / OIDC (Google by default). The server holds the resulting session
  securely and mints PO tokens on demand — no browser scraping, ever.
- **Supports concurrent multi-user sessions.** Every user authenticates with
  their own identity and receives their own, isolated PO tokens.
- **Is stateless and refreshable.** Sessions are signed JWTs with rotating
  refresh tokens, so the server keeps no client-side cookies and can scale to
  many simultaneous logins.
- **Drops into the existing stack.** It exposes a yt-dlp-compatible
  `/get_token` endpoint, so Music Assistant and yt-dlp keep working unchanged —
  you just point them at this server.
- **Runs on Home Assistant OS.** It is packaged as a custom add-on (and as a
  plain Docker image), so it deploys alongside Music Assistant.

## What it does

- **OAuth 2.0 / OpenID Connect login** (authorization-code + PKCE) with nonce
  validation — no manual browser cookie extraction.
- **Stateless JWT sessions** (HS256) with per-`jti` revocation.
- **Rotating refresh tokens** with family-based reuse (theft) detection.
- **Concurrent multi-user** support — every user gets their own PO tokens,
  cached and isolated.
- A **yt-dlp-compatible `/get_token` endpoint** so Music Assistant / yt-dlp
  keep working unchanged.
- **Per-user API keys** for headless clients (e.g. one MA provider instance per
  user).
- Secrets **encrypted at rest** (Fernet) and **hashed** (SHA-256) for lookup.

Built with FastAPI, uvicorn, aiosqlite, authlib, PyJWT, and cryptography.

---

## Architecture

```
Browser / client
      │  1. GET /auth/login  ──────────────►  302 → IdP (Google)
      │  2. user authorises on IdP
      │  3. IdP redirects → GET /auth/callback?code&state
      │                                        │
      │                                        ▼
      │                              exchange code (PKCE)
      │                              decode id_token (nonce check)
      │                              upsert user, store Google refresh token
      │                              issue access JWT + rotating refresh token
      │  ◄──────────── JSON {access_token, refresh_token, ...}
      │
      │  4. GET /get_token  (Authorization: Bearer <access_token>)
      │        or  X-API-Key: pot_...
      │                                        ▼
      │                              per-user PO token cache (asyncio.Lock)
      │                                        ▼
      │  ◄──────────── JSON {po_token, gvs_po_token, player_client, ...}
```

- **Stateless**: the access token is a signed JWT; the server keeps no session
  cookie. Revocation is done via a `revoked_jti` table checked on each request.
- **Refresh rotation**: each refresh grants a *new* refresh token and revokes
  the old one. Reusing an already-rotated token revokes the whole family
  (theft detection).
- **Multi-user**: users are keyed by their IdP `sub`. PO tokens are cached
  per `(user, player_client, video_id)` and guarded by a per-user lock to avoid
  thundering-herd regeneration.

---

## Quick start (Docker)

```bash
cd po_token_server
cp .env.example .env
# edit .env: set PO_JWT_SECRET, PO_SECRET_KEY, PO_OAUTH_CLIENT_ID,
#            PO_OAUTH_CLIENT_SECRET, PO_PUBLIC_URL
docker compose up -d --build
```

The server listens on `http://localhost:4416`. Open it in a browser to see the
login page, or check `GET /health`.

### Generate secrets

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"   # PO_JWT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(48))"   # PO_SECRET_KEY
```

---

## OAuth 2.0 / OIDC client setup (Google)

1. Go to <https://console.cloud.google.com/apis/credentials> → **Create
   credentials → OAuth client ID**.
2. Application type: **Web application**.
3. Add an **Authorized redirect URI** that exactly matches the server's
   `PO_PUBLIC_URL` + `/auth/callback`, e.g.
   `http://localhost:4416/auth/callback`.
4. Copy the **Client ID** and **Client Secret** into `PO_OAUTH_CLIENT_ID` and
   `PO_OAUTH_CLIENT_SECRET`.
5. Ensure the **Google People / OAuth** APIs are enabled (they are by default
   for `openid email profile`).

> **Any OIDC provider works.** Point `PO_OIDC_DISCOVERY_URL` at the provider's
> `/.well-known/openid-configuration` and register a matching client. The
> default is Google to match the YouTube Music use case.

> **Admin bootstrap.** The first user to log in is *not* automatically an admin.
> To grant admin, either set the user's `is_admin` in the SQLite DB
> (`data/po_token.db`, `users` table) or, if your IdP exposes a claim, extend
> `oauth.py`. Admins can then manage users and issue API keys via the admin API.

---

## Configuration

All settings are environment variables prefixed with `PO_` (or a local `.env`).
See [`.env.example`](.env.example) for the full annotated list.

| Variable | Default | Description |
| --- | --- | --- |
| `PO_HOST` / `PO_PORT` | `0.0.0.0` / `4416` | Bind address |
| `PO_PUBLIC_URL` | `http://localhost:4416` | Base URL used to build the OAuth redirect URI |
| `PO_JWT_SECRET` | *(random)* | **Required** in production. HMAC secret for JWTs |
| `PO_JWT_ALGORITHM` | `HS256` | `HS256` or `RS256` |
| `PO_ACCESS_TOKEN_TTL` | `900` | Access token lifetime (s) |
| `PO_REFRESH_TOKEN_TTL` | `2592000` | Refresh token lifetime (s, 30 days) |
| `PO_SECRET_KEY` | *(random)* | **Required** in production. Fernet key material |
| `PO_OIDC_DISCOVERY_URL` | Google | OIDC discovery document URL |
| `PO_OAUTH_CLIENT_ID` / `PO_OAUTH_CLIENT_SECRET` | *(empty)* | **Required**. OAuth client credentials |
| `PO_OAUTH_SCOPES` | `openid email profile` | Space-separated scopes |
| `PO_OAUTH_REDIRECT_PATH` | `/auth/callback` | Redirect path |
| `PO_DATABASE_URL` | `sqlite+aiosqlite:///./data/po_token.db` | aiosqlite URL |
| `PO_DATA_DIR` | `./data` | Directory for the SQLite DB |
| `PO_CACHE_TTL` | `21600` | PO token cache lifetime (s) |
| `PO_PLAYER_CLIENTS` | `web_music,web,android` | yt-dlp player clients |
| `PO_RATE_LIMIT_AUTH` / `PO_RATE_LIMIT_TOKEN` / `PO_RATE_LIMIT_WINDOW` | `20` / `120` / `60` | Sliding-window rate limits |
| `PO_CORS_ORIGINS` | `*` | Comma-separated allowed origins |

---

## API

Interactive docs: `http://localhost:4416/docs` (Swagger) and `/redoc`.

### Auth

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/` | — | Login / status page (HTML) |
| `GET` | `/auth/status` | — | `{"oidc_configured": bool}` |
| `GET` | `/auth/login` | — | 302 redirect to the IdP |
| `GET` | `/auth/callback` | — | IdP redirect target; returns a token pair (JSON) |
| `POST` | `/auth/token` | — | `?refresh_token=...` → new token pair (rotation) |
| `POST` | `/auth/refresh` | — | Alias of `/auth/token` |
| `POST` | `/auth/logout` | Bearer | Revoke current access token (+ family if `?refresh_token=`) |
| `GET` | `/auth/me` | Bearer | Current user profile |

**Token pair response** (`TokenResponse`):

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "opaque-refresh-token",
  "id_token": null,
  "scope": "openid email profile"
}
```

### Tokens (yt-dlp compatible)

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/get_token` | Bearer / API key | yt-dlp-compatible PO token |
| `GET` | `/api/v1/tokens` | Bearer / API key | Same, typed response |
| `GET` | `/api/v1/status` | — | Generator + server status |

`/get_token` query params: `video_id`, `player_client`, `url`, `format_id`
(the last two are accepted for yt-dlp compatibility).

**PO token response** (`PoTokenResponse`):

```json
{
  "po_token": "PO_TOKEN_STRING",
  "player_client": "web_music",
  "video_id": "dQw4w9WgXcQ",
  "generated_at": "2026-09-08T17:00:00Z",
  "expires_at": "2026-09-08T23:00:00Z",
  "gvs_po_token": null,
  "visitor_data": null,
  "metadata": {}
}
```

### Admin (requires an admin JWT)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/admin/users` | List users + active session counts |
| `POST` | `/api/v1/admin/users/{id}/status` | `{"status": "active"|"suspended"}` |
| `POST` | `/api/v1/admin/users/{id}/revoke-sessions` | Revoke all refresh families (force re-login) |
| `GET` | `/api/v1/admin/users/{id}/api-keys` | List API keys (no raw values) |
| `POST` | `/api/v1/admin/users/{id}/api-keys` | Create key; raw key returned **once** |
| `DELETE` | `/api/v1/admin/users/{id}/api-keys/{key_id}` | Revoke a key |

### Health

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Liveness + version + user count |
| `GET` | `/ready` | Readiness (storage reachable) |

---

## Authentication for clients

Two ways to authenticate a request:

1. **Bearer JWT** — `Authorization: Bearer <access_token>` (from the OAuth
   flow or a refresh).
2. **API key** — `X-API-Key: pot_...` (created via the admin API). Ideal for
   headless clients such as a Music Assistant provider instance, where there is
   no browser to complete the OAuth flow.

---

## Music Assistant integration

Point the YouTube Music provider's PO token endpoint at this server:

- **PO token URL**: `http://<host>:4416/get_token`
- **Auth**: create an API key for the MA user (admin API) and supply it as the
  `X-API-Key` header, or use a long-lived access token.

This removes the need to paste a manually-scraped browser cookie — the server
holds the Google session (encrypted) and mints PO tokens on demand.

---

## Running the tests

```bash
cd po_token_server
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

The test suite (40 tests) covers security primitives, storage, the full OAuth
flow (login → callback → me → refresh → reuse-detection → logout), and the
token/admin APIs. The PO generator runs in **stub mode** in tests (no `pot`
extra required).

---

## Install on Home Assistant OS (custom add-on)

This is distributed as a **custom add-on repository** — the same mechanism the
`bgutil-ytdlp-pot-provider` add-on uses — so a user adds one URL and clicks
install. No manual Docker steps on the HAOS box.

### End-user install (on your HAOS instance)

1. **Supervisor → Menu (⋮) → Add-on Store → ⋮ → "Add custom add-on store"**.
2. Paste the repository URL, e.g.
   `https://github.com/peraltagroup/po-token-server` and click **Reload**.
3. The **PO Token Server** add-on now appears in the store → **Install**.
4. Open the add-on → **Configuration** and set:
   - `public_url` — the URL HAOS users reach the add-on at, e.g.
     `http://<haos-ip>:4416`
   - `jwt_secret` and `secret_key` — generate each with
     `python -c "import secrets; print(secrets.token_urlsafe(48))"`
   - `oauth_client_id` / `oauth_client_secret` — from your Google OAuth client
     (redirect URI must be `<public_url>/auth/callback`)
5. **Save → Start**. Open the add-on **Dashboard** (webui) to log in with
   Google.
6. In **Music Assistant**, point the YouTube Music provider's PO token URL at
   `http://<haos-ip>:4416/get_token` and supply an API key (see below).

> The add-on stores its SQLite DB under `/config` (the add-on's config dir), so
> it survives updates and is included in HAOS backups.

### Publisher: build & publish the add-on

The `addon/` directory is a ready-to-publish add-on repository:

```
addon/
├── repo.yaml                  # repository manifest (Supervisor reads this)
├── build.sh                   # buildx build + push for each arch
└── data/
    └── amd64/
        ├── config.yaml        # per-arch add-on manifest
        └── Dockerfile         # add-on image build
```

1. **Set your identity** in `addon/repo.yaml` (`url`, `maintainers`) and in
   each `data/<arch>/config.yaml` (`url`, and the `image:` tag).
2. **Build & push** the images (one per architecture you support):
   ```bash
   cd po_token_server/addon
   REGISTRY=ghcr.io/peraltagroup VERSION=1.0.0 ARCHS="amd64 aarch64" ./build.sh --push
   ```
   This produces `ghcr.io/peraltagroup/po-token-server:amd64-1.0.0`, etc. Make
   sure the `image:` field in each `config.yaml` matches the pushed tag.
3. **Commit & push** the repo (including `repo.yaml` and `data/`).
4. Users add the repo URL as in the end-user steps above.

> To support more architectures, copy `data/amd64/` to `data/aarch64/`,
> `data/armv7/`, etc., set the matching `arch:` in each `config.yaml`, and add
> them to `ARCHS` in the build command.

> `hassio/` holds an equivalent single-arch manifest + Dockerfile for local
> testing; `addon/` is the canonical multi-arch repository layout.

---

## Security notes

- **No client-side cookie scraping.** Identity comes from the IdP's signed
  `id_token`; the server never reads browser cookies.
- **PKCE + state** on the authorization-code flow (CSRF protection).
- **Nonce** validation on the `id_token`.
- **Secrets at rest**: the Google refresh token is Fernet-encrypted; refresh
  tokens and API keys are stored by SHA-256 hash (deterministic lookup) with the
  encrypted value alongside.
- **Refresh rotation + reuse detection**: replaying a rotated refresh token
  revokes the entire family.
- **JWT revocation** via a `revoked_jti` table (checked per request).
- **Rate limiting** (sliding window) on auth and token endpoints.
- **Security headers** (HSTS, `X-Content-Type-Options`, etc.) and configurable
  CORS.
- **Log redaction** — secrets are masked in structured logs.

---

## Project layout

```
po_token_server/
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── README.md
├── addon/
│   ├── repo.yaml            # add-on repository manifest
│   ├── build.sh             # buildx build + push per arch
│   └── data/
│       └── amd64/
│           ├── config.yaml  # per-arch add-on manifest
│           └── Dockerfile
├── hassio/                  # single-arch manifest for local testing
│   ├── config.yaml
│   └── Dockerfile
├── po_token_server/
│   ├── __init__.py
│   ├── __main__.py        # entrypoint
│   ├── app.py             # FastAPI app factory, middleware, lifespan
│   ├── config.py          # pydantic-settings (PO_* env)
│   ├── security.py        # JWT, Fernet cipher, redaction
│   ├── models.py          # pydantic schemas
│   ├── storage.py         # aiosqlite persistence
│   ├── oauth.py           # OAuth 2.0 / OIDC flow + token issuance
│   ├── potoken.py         # PO token generator (bgutil or stub)
│   ├── deps.py            # auth dependencies (Bearer / API key)
│   └── routers/
│       ├── auth.py
│       ├── tokens.py
│       └── admin.py
└── tests/
    ├── conftest.py
    ├── test_security.py
    ├── test_storage.py
    ├── test_api.py
    └── test_oauth_flow.py
```
