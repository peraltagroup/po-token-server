"""End-to-end OAuth 2.0 / OIDC flow tests (IdP mocked with respx).

Covers: discovery, authorization URL + PKCE, callback code exchange, token
issuance, refresh rotation, reuse detection, and logout.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from conftest import make_id_token

DISCOVERY = {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
}

SUB = "google-sub-123"
EMAIL = "ibslkvi@gmail.com"
NAME = "Test User"


def _token_response(id_token: str, refresh: str | None = "google-refresh-xyz") -> dict:
    return {
        "access_token": "google-access",
        "expires_in": 3599,
        "refresh_token": refresh,
        "id_token": id_token,
        "token_type": "Bearer",
        "scope": "openid email profile",
    }


@respx.mock
async def test_full_oauth_flow(client, app):
    """Login -> callback -> /auth/me -> refresh -> reuse detection -> logout."""
    oauth = app.state.oauth
    nonce_holder: dict[str, str] = {}

    # 1) Discovery.
    respx.get("https://accounts.google.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=DISCOVERY)
    )
    await oauth.load_discovery()

    # 2) Build the authorization URL (creates a pending state + nonce).
    auth_url, state = oauth.build_authorization_url()
    assert "code_challenge" in auth_url
    assert "code_challenge_method=S256" in auth_url
    assert f"state={state}" in auth_url
    nonce = oauth._pending[state].nonce
    nonce_holder["nonce"] = nonce

    # 3) Simulate the IdP token endpoint responding to the code exchange.
    id_token = make_id_token(SUB, EMAIL, NAME, nonce)
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json=_token_response(id_token))
    )

    # 4) Hit the callback with the code + state.
    resp = await client.get("/auth/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 200, resp.text
    tokens = resp.json()
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["token_type"] == "Bearer"

    # 5) The user was created and has Google credentials stored (encrypted).
    user = await app.state.storage.get_user(SUB)
    assert user is not None
    assert user.email == EMAIL
    assert user.encrypted_google_refresh_token is not None
    # The stored value must NOT be the raw refresh token.
    assert user.encrypted_google_refresh_token != "google-refresh-xyz"

    # 6) /auth/me works with the new access token.
    me = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["email"] == EMAIL

    # 7) Refresh rotation: old refresh token is single-use.
    refresh1 = tokens["refresh_token"]
    r1 = await client.post("/auth/token", params={"refresh_token": refresh1})
    assert r1.status_code == 200, r1.text
    tokens2 = r1.json()
    assert tokens2["access_token"]
    assert tokens2["refresh_token"] != refresh1  # rotated

    # 8) Reuse of the OLD refresh token must fail and revoke the family.
    r_reuse = await client.post("/auth/token", params={"refresh_token": refresh1})
    assert r_reuse.status_code == 401
    # The new (rotated) token is now also revoked (family revoked).
    r_new = await client.post("/auth/token", params={"refresh_token": tokens2["refresh_token"]})
    assert r_new.status_code == 401

    # 9) Logout revokes the access token.
    out = await client.post(
        "/auth/logout", headers={"Authorization": f"Bearer {tokens2['access_token']}"}
    )
    assert out.status_code == 200
    # The revoked access token no longer works.
    me2 = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {tokens2['access_token']}"}
    )
    assert me2.status_code == 401


@respx.mock
async def test_callback_rejects_bad_state(client, app):
    # No pending state exists for "bogus".
    resp = await client.get("/auth/callback", params={"code": "c", "state": "bogus"})
    assert resp.status_code == 400


@respx.mock
async def test_callback_nonce_mismatch(client, app):
    oauth = app.state.oauth
    respx.get("https://accounts.google.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=DISCOVERY)
    )
    await oauth.load_discovery()
    auth_url, state = oauth.build_authorization_url()
    # Craft an id_token with the WRONG nonce.
    bad_id_token = make_id_token(SUB, EMAIL, NAME, nonce="wrong-nonce")
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json=_token_response(bad_id_token))
    )
    resp = await client.get("/auth/callback", params={"code": "c", "state": state})
    assert resp.status_code == 401


@respx.mock
async def test_login_redirects_to_idp(client, app):
    respx.get("https://accounts.google.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=DISCOVERY)
    )
    resp = await client.get("/auth/login", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "client_id=test-client-id" in location


async def test_login_503_when_not_configured(app, client):
    # Point the app at unconfigured settings.
    from po_token_server.config import Settings
    from po_token_server.app import create_app

    unconfigured = Settings(
        _env_file=None,
        oauth_client_id="",
        oauth_client_secret="",
        jwt_secret="x" * 40,
        secret_key="y" * 40,
        database_url="sqlite+aiosqlite:///:memory:",
    )
    app2 = create_app(unconfigured)
    async with app2.router.lifespan_context(app2):
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app2)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/auth/login")
            assert resp.status_code == 503
            status = await c.get("/auth/status")
            assert status.json()["oidc_configured"] is False
