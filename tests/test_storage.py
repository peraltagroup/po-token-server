"""Tests for the SQLite storage layer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from po_token_server.storage import Storage
from po_token_server.models import UserStatus


@pytest_asyncio.fixture
async def storage():
    s = Storage("sqlite+aiosqlite:///:memory:")
    await s.connect()
    yield s
    await s.close()


async def test_user_upsert_and_get(storage: Storage):
    user = await storage.upsert_user("u1", email="a@b.com", name="A")
    assert user.id == "u1"
    assert user.email == "a@b.com"

    fetched = await storage.get_user("u1")
    assert fetched is not None
    assert fetched.email == "a@b.com"

    # Upsert again with a new name; email preserved.
    await storage.upsert_user("u1", name="A2")
    fetched = await storage.get_user("u1")
    assert fetched.name == "A2"
    assert fetched.email == "a@b.com"


async def test_user_count(storage: Storage):
    assert await storage.count_users() == 0
    await storage.upsert_user("u1")
    await storage.upsert_user("u2")
    assert await storage.count_users() == 2


async def test_google_credentials_roundtrip(storage: Storage):
    await storage.upsert_user("u1")
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    await storage.set_google_credentials("u1", "encrypted-rt", exp)
    user = await storage.get_user("u1")
    assert user.encrypted_google_refresh_token == "encrypted-rt"
    assert user.google_refresh_token_expires_at is not None


async def test_refresh_token_lifecycle(storage: Storage):
    await storage.upsert_user("u1")
    exp = datetime.now(timezone.utc) + timedelta(days=1)
    rec = await storage.create_refresh_token("u1", "fam1", "h-enc", "enc-token", exp)
    assert rec.jti

    found = await storage.get_refresh_token(rec.jti)
    assert found is not None
    assert found.revoked is False

    # Rotate.
    await storage.revoke_refresh_token(rec.jti, replaced_by="new-jti")
    found = await storage.get_refresh_token(rec.jti)
    assert found.revoked is True
    assert found.replaced_by == "new-jti"

    # Find by deterministic hash.
    by_hash = await storage.find_refresh_token_by_hash("h-enc")
    assert by_hash is not None
    assert by_hash.jti == rec.jti


async def test_revoke_family(storage: Storage):
    await storage.upsert_user("u1")
    exp = datetime.now(timezone.utc) + timedelta(days=1)
    await storage.create_refresh_token("u1", "famX", "h-t1", "t1", exp)
    await storage.create_refresh_token("u1", "famX", "h-t2", "t2", exp)
    await storage.create_refresh_token("u1", "famY", "h-t3", "t3", exp)

    count = await storage.revoke_family("famX")
    assert count == 2

    # famY untouched.
    async with storage.db.execute(
        "SELECT COUNT(*) c FROM refresh_tokens WHERE family_id='famY' AND revoked=0"
    ) as cur:
        row = await cur.fetchone()
    assert row["c"] == 1


async def test_active_sessions_count(storage: Storage):
    await storage.upsert_user("u1")
    now = datetime.now(timezone.utc)
    await storage.create_refresh_token("u1", "f1", "h-a", "a", now + timedelta(days=1))
    await storage.create_refresh_token("u1", "f2", "h-b", "b", now + timedelta(days=1))
    await storage.create_refresh_token("u1", "f3", "h-c", "c", now - timedelta(days=1))  # expired
    assert await storage.count_active_sessions("u1") == 2


async def test_po_token_cache(storage: Storage):
    now = datetime.now(timezone.utc)
    await storage.set_po_token("u1", "web_music", "tok1", now, now + timedelta(hours=1))
    entry = await storage.get_po_token("u1", "web_music")
    assert entry is not None
    assert entry.token == "tok1"

    # Overwrite.
    await storage.set_po_token("u1", "web_music", "tok2", now, now + timedelta(hours=1))
    entry = await storage.get_po_token("u1", "web_music")
    assert entry.token == "tok2"

    # Different client is separate.
    assert await storage.get_po_token("u1", "android") is None


async def test_api_keys(storage: Storage):
    await storage.upsert_user("u1")
    rec = await storage.create_api_key("u1", "ma", "hash-abc")
    found = await storage.get_api_key_by_hash("hash-abc")
    assert found is not None
    assert found.user_id == "u1"
    assert found.name == "ma"

    await storage.revoke_api_key(rec.id)
    assert await storage.get_api_key_by_hash("hash-abc") is None


async def test_jti_revocation(storage: Storage):
    assert await storage.is_jti_revoked("jti1") is False
    await storage.revoke_jti("jti1")
    assert await storage.is_jti_revoked("jti1") is True


async def test_user_status_change(storage: Storage):
    await storage.upsert_user("u1")
    await storage.set_user_status("u1", UserStatus.SUSPENDED)
    user = await storage.get_user("u1")
    assert user.status == UserStatus.SUSPENDED
