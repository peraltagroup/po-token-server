"""Shared pytest fixtures for the PO Token server test suite."""

from __future__ import annotations

import base64
import json
import os
import time
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from po_token_server.app import create_app
from po_token_server.config import Settings


def _test_settings(tmp_path) -> Settings:
    """Build isolated Settings for a test (in-memory SQLite, fixed secrets)."""
    return Settings(
        _env_file=None,  # ignore any .env
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


@pytest.fixture
def settings(tmp_path) -> Settings:
    return _test_settings(tmp_path)


@pytest_asyncio.fixture
async def app(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --------------------------------------------------------------------------- #
# Helpers to simulate the IdP (Google) for the OAuth flow
# --------------------------------------------------------------------------- #
def make_id_token(sub: str, email: str, name: str, nonce: str, exp_delta: int = 3600) -> str:
    """Build an unsigned (alg=none) JWT id_token for tests.

    The server decodes the payload without signature verification (the
    authorization-code + PKCE + state flow provides integrity), so an unsigned
    token is sufficient for unit tests.
    """
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = {
        "sub": sub,
        "email": email,
        "name": name,
        "nonce": nonce,
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_delta,
        "iss": "https://accounts.google.com",
        "aud": "test-client-id",
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{payload_b64}."


def discover_nonce_from_state(app, state: str) -> str:
    """Read the nonce the server stored for a given OAuth state."""
    pending = app.state.oauth._pending.get(state)
    return pending.nonce if pending else None
