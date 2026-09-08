"""API-level tests: health, token endpoint, multi-user isolation, admin."""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from po_token_server.models import UserStatus


# --------------------------------------------------------------------------- #
# Health / status
# --------------------------------------------------------------------------- #
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["oidc_configured"] is True
    assert body["users"] == 0


async def test_ready(client):
    resp = await client.get("/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


async def test_status_endpoint(client):
    resp = await client.get("/api/v1/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "generator" in body
    assert body["generator"]["backend"] in ("bgutil", "stub")


# --------------------------------------------------------------------------- #
# Auth required
# --------------------------------------------------------------------------- #
async def test_get_token_requires_auth(client):
    resp = await client.get("/get_token")
    assert resp.status_code == 401


async def test_admin_requires_auth(client):
    resp = await client.get("/api/v1/admin/users")
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Helpers to create users + tokens directly (bypassing the IdP)
# --------------------------------------------------------------------------- #
async def _make_user_with_token(app, user_id: str, email: str, is_admin: bool = False):
    storage = app.state.storage
    jwt_service = app.state.jwt
    await storage.upsert_user(user_id, email=email, name=user_id, is_admin=is_admin)
    access = jwt_service.create_access_token(
        sub=user_id, email=email, name=user_id, is_admin=is_admin
    )
    return access


# --------------------------------------------------------------------------- #
# Token endpoint
# --------------------------------------------------------------------------- #
async def test_get_token_with_jwt(client, app):
    token = await _make_user_with_token(app, "alice", "alice@example.com")
    resp = await client.get(
        "/get_token",
        headers={"Authorization": f"Bearer {token}"},
        params={"video_id": "dQw4w9WgXcQ", "player_client": "web_music"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["po_token"]
    assert body["player_client"] == "web_music"
    assert body["video_id"] == "dQw4w9WgXcQ"
    assert body["gvs_po_token"] == body["po_token"]


async def test_get_token_default_player_client(client, app):
    token = await _make_user_with_token(app, "bob", "bob@example.com")
    resp = await client.get("/get_token", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    # Default client is the first configured (web_music).
    assert resp.json()["player_client"] == "web_music"


async def test_get_token_with_api_key(client, app):
    import hashlib

    storage = app.state.storage
    await storage.upsert_user("carol", email="carol@example.com")
    raw_key = "pot_testkey123"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    await storage.create_api_key("carol", "ma", key_hash)

    resp = await client.get(
        "/get_token",
        headers={"X-API-Key": raw_key},
        params={"player_client": "android"},
    )
    assert resp.status_code == 200
    assert resp.json()["player_client"] == "android"


async def test_get_token_invalid_api_key(client):
    resp = await client.get("/get_token", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Multi-user isolation + concurrency
# --------------------------------------------------------------------------- #
async def test_multi_user_isolation(client, app):
    t_alice = await _make_user_with_token(app, "alice", "alice@example.com")
    t_bob = await _make_user_with_token(app, "bob", "bob@example.com")

    r_alice = await client.get(
        "/get_token",
        headers={"Authorization": f"Bearer {t_alice}"},
        params={"player_client": "web_music"},
    )
    r_bob = await client.get(
        "/get_token",
        headers={"Authorization": f"Bearer {t_bob}"},
        params={"player_client": "web_music"},
    )
    assert r_alice.status_code == 200
    assert r_bob.status_code == 200
    # Different users get different (stub) tokens.
    assert r_alice.json()["po_token"] != r_bob.json()["po_token"]


async def test_concurrent_requests_same_user(client, app):
    """Many concurrent requests for the same user must all succeed and agree."""
    token = await _make_user_with_token(app, "dave", "dave@example.com")

    async def one():
        r = await client.get(
            "/get_token",
            headers={"Authorization": f"Bearer {token}"},
            params={"player_client": "web_music"},
        )
        assert r.status_code == 200
        return r.json()["po_token"]

    results = await asyncio.gather(*[one() for _ in range(20)])
    # All should resolve to the same cached token.
    assert len(set(results)) == 1


async def test_suspended_user_cannot_get_token(client, app):
    token = await _make_user_with_token(app, "eve", "eve@example.com")
    await app.state.storage.set_user_status("eve", UserStatus.SUSPENDED)
    resp = await client.get("/get_token", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Admin API
# --------------------------------------------------------------------------- #
async def test_admin_list_users(client, app):
    admin_token = await _make_user_with_token(app, "admin", "admin@example.com", is_admin=True)
    await _make_user_with_token(app, "alice", "alice@example.com")

    resp = await client.get(
        "/api/v1/admin/users", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    users = {u["email"]: u for u in resp.json()}
    assert "alice@example.com" in users
    assert users["admin@example.com"]["is_admin"] is True


async def test_non_admin_forbidden(client, app):
    token = await _make_user_with_token(app, "mallory", "m@example.com", is_admin=False)
    resp = await client.get(
        "/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403


async def test_admin_create_and_revoke_api_key(client, app):
    admin_token = await _make_user_with_token(app, "admin", "admin@example.com", is_admin=True)
    await _make_user_with_token(app, "frank", "frank@example.com")

    # Create.
    resp = await client.post(
        "/api/v1/admin/users/frank/api-keys",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "ma"},
    )
    assert resp.status_code == 200
    body = resp.json()
    raw_key = body["api_key"]
    key_id = body["id"]
    assert raw_key.startswith("pot_")

    # The new key works.
    r = await client.get("/get_token", headers={"X-API-Key": raw_key})
    assert r.status_code == 200

    # Revoke.
    resp = await client.delete(
        f"/api/v1/admin/users/frank/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    r = await client.get("/get_token", headers={"X-API-Key": raw_key})
    assert r.status_code == 401


async def test_admin_revoke_sessions(client, app):
    admin_token = await _make_user_with_token(app, "admin", "admin@example.com", is_admin=True)
    await _make_user_with_token(app, "grace", "grace@example.com")
    # Create a refresh token for grace.
    from datetime import datetime, timedelta, timezone

    rec = await app.state.storage.create_refresh_token(
        "grace", "fam1", "h-enc", "enc", datetime.now(timezone.utc) + timedelta(days=1)
    )
    resp = await client.post(
        "/api/v1/admin/users/grace/revoke-sessions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["revoked_tokens"] >= 1
