"""Smoke test for the new POST /get_token and POST /auth/login endpoints."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from po_token_server.app import create_app
from po_token_server.config import Settings


def _test_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        host="127.0.0.1",
        port=4416,
        public_url="http://localhost:4416",
        jwt_secret="test-jwt-secret-0123456789abcdef0123456789abcdef",
        secret_key="test-fernet-secret-0123456789abcdef",
        oauth_client_id="test-client-id",
        oauth_client_secret="test-client-secret",
        database_url="sqlite+aiosqlite:///:memory:",
        data_dir=str(tmp_path),
        access_token_ttl=3600,
        refresh_token_ttl=86400,
        po_cache_ttl=3600,
        rate_limit_auth=1000,
        rate_limit_token=1000,
    )


@pytest_asyncio.fixture
async def app(tmp_path):
    settings = _test_settings(tmp_path)
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_get_token_post_no_auth(client):
    """POST /get_token without auth should return 401."""
    r = await client.post("/get_token", json={})
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text}"


async def test_get_token_get_no_auth(client):
    """GET /get_token without auth should return 401."""
    r = await client.get("/get_token")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text}"


async def test_auth_login_username_password(client):
    """POST /auth/login with username/password should create a user and return tokens."""
    r = await client.post(
        "/auth/login",
        json={"username": "test@example.com", "password": "testpass123"},
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert "access_token" in data, f"Missing access_token: {data}"
    assert "refresh_token" in data, f"Missing refresh_token: {data}"


async def test_get_token_post_with_auth(client):
    """POST /get_token with a valid JWT should return a PO token."""
    login = await client.post(
        "/auth/login",
        json={"username": "test2@example.com", "password": "testpass456"},
    )
    assert login.status_code == 200, f"Login failed: {login.text}"
    access_token = login.json()["access_token"]

    r = await client.post(
        "/get_token",
        json={"video_id": "dQw4w9WgXcQ", "player_client": "web_music"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert "po_token" in data, f"Missing po_token: {data}"
    assert data["player_client"] == "web_music"
    assert data["video_id"] == "dQw4w9WgXcQ"


async def test_get_token_get_with_auth(client):
    """GET /get_token with a valid JWT should return a PO token."""
    login = await client.post(
        "/auth/login",
        json={"username": "test3@example.com", "password": "testpass789"},
    )
    assert login.status_code == 200
    access_token = login.json()["access_token"]

    r = await client.get(
        "/get_token?video_id=dQw4w9WgXcQ&player_client=web",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert "po_token" in data


async def test_get_token_post_with_url(client):
    """POST /get_token with a URL (no video_id) should extract the video id."""
    login = await client.post(
        "/auth/login",
        json={"username": "test4@example.com", "password": "testpass000"},
    )
    assert login.status_code == 200
    access_token = login.json()["access_token"]

    r = await client.post(
        "/get_token",
        json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert data["video_id"] == "dQw4w9WgXcQ"


async def test_auth_login_idempotent(client):
    """Logging in twice with the same email should reuse the user."""
    r1 = await client.post(
        "/auth/login",
        json={"username": "same@example.com", "password": "pass1"},
    )
    r2 = await client.post(
        "/auth/login",
        json={"username": "same@example.com", "password": "pass2"},
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    t2 = r2.json()["access_token"]
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {t2}"})
    assert r.status_code == 200
    assert r.json()["email"] == "same@example.com"


async def test_auth_me_after_login(client):
    """After username/password login, /auth/me should return the user profile."""
    login = await client.post(
        "/auth/login",
        json={"username": "me@example.com", "password": "mypass"},
    )
    assert login.status_code == 200
    access_token = login.json()["access_token"]
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == "me@example.com"
    assert data["authenticated_via"] == "jwt"
