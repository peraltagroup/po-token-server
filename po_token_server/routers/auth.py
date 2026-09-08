"""Authentication router: OAuth 2.0 / OIDC login, token, refresh, logout.

Endpoints
---------
* ``GET  /auth/login``    — start the OAuth flow (redirects to the IdP)
* ``GET  /auth/callback`` — IdP redirect target; exchanges code, issues tokens
* ``POST /auth/token``    — exchange a refresh token for a new token pair
* ``POST /auth/refresh``  — alias for /auth/token (refresh grant)
* ``POST /auth/logout``   — revoke the current access + refresh tokens
* ``GET  /auth/status``   — whether OIDC is configured
* ``GET  /``              — minimal login UI / status page
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..deps import AuthContext, get_current_user
from ..models import TokenResponse
from ..oauth import OAuthError, OAuthService
from ..security import redact_json

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])

# Minimal, dependency-free login page.
_LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PO Token Server</title>
<style>
  body {{ font-family: system-ui, sans-serif; display:flex; align-items:center;
         justify-content:center; min-height:100vh; margin:0; background:#0f172a; color:#e2e8f0; }}
  .card {{ background:#1e293b; padding:2.5rem 3rem; border-radius:16px;
           box-shadow:0 10px 40px rgba(0,0,0,.4); text-align:center; max-width:420px; }}
  h1 {{ font-size:1.4rem; margin:0 0 .5rem; }}
  p {{ color:#94a3b8; font-size:.95rem; line-height:1.5; }}
  a.btn {{ display:inline-block; margin-top:1.5rem; padding:.8rem 1.6rem;
           background:#3b82f6; color:#fff; text-decoration:none; border-radius:10px;
           font-weight:600; }}
  a.btn:hover {{ background:#2563eb; }}
  .status {{ font-size:.8rem; color:#64748b; margin-top:1.5rem; }}
  .ok {{ color:#34d399; }} .bad {{ color:#f87171; }}
</style>
</head>
<body>
  <div class="card">
    <h1>PO Token Server</h1>
    <p>Self-hosted, multi-user PO Token server with OAuth 2.0 / OIDC login.</p>
    {body}
    <div class="status">v{version} &middot; {status_line}</div>
  </div>
</body>
</html>
"""


def _get_oauth(request: Request) -> OAuthService:
    return request.app.state.oauth


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request) -> HTMLResponse:
    """Login / status page."""
    oauth: OAuthService = request.app.state.oauth
    settings = request.app.state.settings
    if oauth.configured:
        body = '<a class="btn" href="/auth/login">Sign in with Google</a>'
        status_line = '<span class="ok">OIDC configured</span>'
    else:
        body = (
            '<p class="bad">OAuth is not configured. Set '
            '<code>PO_OAUTH_CLIENT_ID</code> and <code>PO_OAUTH_CLIENT_SECRET</code>.</p>'
        )
        status_line = '<span class="bad">OIDC not configured</span>'
    html = _LOGIN_HTML.format(body=body, version=settings and "1.0.0", status_line=status_line)
    return HTMLResponse(html)


@router.get("/auth/status")
async def auth_status(request: Request) -> dict[str, Any]:
    oauth: OAuthService = request.app.state.oauth
    return {"oidc_configured": oauth.configured}


@router.get("/auth/login")
async def login(request: Request) -> RedirectResponse:
    """Begin the OAuth 2.0 authorization-code + PKCE flow."""
    oauth: OAuthService = request.app.state.oauth
    if not oauth.configured:
        raise HTTPException(
            status_code=503,
            detail="OAuth is not configured (set PO_OAUTH_CLIENT_ID / PO_OAUTH_CLIENT_SECRET)",
        )
    try:
        await oauth.load_discovery()
        url, _state = oauth.build_authorization_url()
    except OAuthError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url, status_code=302)


@router.get("/auth/callback")
async def callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
) -> JSONResponse:
    """IdP redirect target. Exchanges the code and returns tokens as JSON.

    Returning JSON (rather than setting a cookie) keeps the server stateless and
    avoids client-side cookie handling entirely — the client stores the JWT.
    """
    oauth: OAuthService = request.app.state.oauth
    if error:
        logger.warning("OAuth callback error: %s %s", error, error_description)
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")
    try:
        tokens: TokenResponse = await oauth.handle_callback(code, state)
    except OAuthError as exc:
        logger.warning("OAuth callback failed: %s", exc)
        # A bad/expired state is a client-side (CSRF) error -> 400.
        if "state" in str(exc).lower():
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    logger.info("Issued tokens for callback (state=%s...)", state[:8])
    return JSONResponse(tokens.model_dump())


@router.post("/auth/token", response_model=TokenResponse)
@router.post("/auth/refresh", response_model=TokenResponse)
async def token(
    request: Request,
    refresh_token: str = Query(..., description="Opaque refresh token"),
) -> TokenResponse:
    """Exchange a refresh token for a new access + refresh pair (rotation)."""
    oauth: OAuthService = request.app.state.oauth
    try:
        return await oauth.refresh(refresh_token)
    except OAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.post("/auth/logout")
async def logout(
    request: Request,
    ctx: AuthContext = Depends(get_current_user),
) -> dict[str, Any]:
    """Revoke the current access token (and refresh family if provided)."""
    oauth: OAuthService = request.app.state.oauth
    refresh_token = request.query_params.get("refresh_token")
    if ctx.jti:
        await oauth.logout(ctx.jti, refresh_token)
    return {"status": "logged_out"}


@router.get("/auth/me")
async def me(ctx: AuthContext = Depends(get_current_user)) -> dict[str, Any]:
    """Return the current user's public profile."""
    u = ctx.user
    return {
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "is_admin": u.is_admin,
        "authenticated_via": ctx.via,
    }
