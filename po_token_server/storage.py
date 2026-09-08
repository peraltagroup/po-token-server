"""Async SQLite storage layer (aiosqlite).

Isolated behind :class:`Storage` so a different backend (e.g. Postgres) can be
swapped in later without touching the rest of the app. SQLite runs in WAL mode
for concurrent reads with a single writer.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from .models import (
    ApiKey,
    PoTokenCacheEntry,
    RefreshTokenRecord,
    User,
    UserStatus,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    name TEXT,
    picture TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    is_admin INTEGER NOT NULL DEFAULT 0,
    encrypted_google_refresh_token TEXT,
    google_refresh_token_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    encrypted_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    replaced_by TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash);

CREATE TABLE IF NOT EXISTS po_token_cache (
    user_id TEXT NOT NULL,
    player_client TEXT NOT NULL,
    token TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (user_id, player_client)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_apikey_user ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS revoked_jti (
    jti TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL
);
"""


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


class Storage:
    """Thin async wrapper over aiosqlite for all persistence."""

    def __init__(self, database_url: str) -> None:
        # Accept "sqlite+aiosqlite:///path", "sqlite:///path", or a bare path.
        # The triple-slash form yields an empty authority, so ":memory:" and
        # relative/absolute paths are handled correctly.
        url = database_url
        for prefix in ("sqlite+aiosqlite://", "sqlite://"):
            if url.startswith(prefix):
                path = url[len(prefix):]
                break
        else:
            path = url
        # Normalize the leading slash left over from the "///" form.
        if path.startswith("/") and not path.startswith("//"):
            path = path.lstrip("/")
        self._path = path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA foreign_keys=ON;")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Storage not connected; call connect() first")
        return self._db

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #
    async def upsert_user(
        self,
        user_id: str,
        email: str | None = None,
        name: str | None = None,
        picture: str | None = None,
        is_admin: bool | None = None,
    ) -> User:
        now = datetime.now(timezone.utc)
        async with self.db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            user = User(
                id=user_id,
                email=email,
                name=name,
                picture=picture,
                is_admin=bool(is_admin) if is_admin is not None else False,
                created_at=now,
                updated_at=now,
            )
            await self.db.execute(
                """INSERT INTO users
                   (id, email, name, picture, status, is_admin,
                    encrypted_google_refresh_token, google_refresh_token_expires_at,
                    created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    user.id,
                    user.email,
                    user.name,
                    user.picture,
                    user.status.value,
                    int(user.is_admin),
                    None,
                    None,
                    _iso(now),
                    _iso(now),
                ),
            )
            await self.db.commit()
            return user

        # Update mutable profile fields (don't clobber existing values with None).
        updates: dict[str, Any] = {}
        if email is not None:
            updates["email"] = email
        if name is not None:
            updates["name"] = name
        if picture is not None:
            updates["picture"] = picture
        if is_admin is not None:
            updates["is_admin"] = int(is_admin)
        updates["updated_at"] = _iso(now)
        if updates:
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            await self.db.execute(
                f"UPDATE users SET {set_clause} WHERE id = ?",
                (*updates.values(), user_id),
            )
            await self.db.commit()
        return await self.get_user(user_id)  # type: ignore[return-value]

    async def get_user(self, user_id: str) -> User | None:
        async with self.db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        return self._row_to_user(row) if row else None

    async def list_users(self) -> list[User]:
        async with self.db.execute("SELECT * FROM users ORDER BY created_at") as cur:
            rows = await cur.fetchall()
        return [self._row_to_user(r) for r in rows]

    async def count_users(self) -> int:
        async with self.db.execute("SELECT COUNT(*) AS c FROM users") as cur:
            row = await cur.fetchone()
        return int(row["c"])

    async def set_google_credentials(
        self,
        user_id: str,
        encrypted_refresh_token: str,
        expires_at: datetime | None,
    ) -> None:
        await self.db.execute(
            """UPDATE users
               SET encrypted_google_refresh_token = ?,
                   google_refresh_token_expires_at = ?,
                   updated_at = ?
               WHERE id = ?""",
            (
                encrypted_refresh_token,
                _iso(expires_at),
                _iso(datetime.now(timezone.utc)),
                user_id,
            ),
        )
        await self.db.commit()

    async def set_user_status(self, user_id: str, status: UserStatus) -> None:
        await self.db.execute(
            "UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, _iso(datetime.now(timezone.utc)), user_id),
        )
        await self.db.commit()

    @staticmethod
    def _row_to_user(row: aiosqlite.Row) -> User:
        return User(
            id=row["id"],
            email=row["email"],
            name=row["name"],
            picture=row["picture"],
            status=UserStatus(row["status"]),
            is_admin=bool(row["is_admin"]),
            encrypted_google_refresh_token=row["encrypted_google_refresh_token"],
            google_refresh_token_expires_at=_dt(row["google_refresh_token_expires_at"]),
            created_at=_dt(row["created_at"]),
            updated_at=_dt(row["updated_at"]),
        )

    # ------------------------------------------------------------------ #
    # Refresh tokens
    # ------------------------------------------------------------------ #
    async def create_refresh_token(
        self,
        user_id: str,
        family_id: str,
        token_hash: str,
        encrypted_token: str,
        expires_at: datetime,
    ) -> RefreshTokenRecord:
        jti = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        await self.db.execute(
            """INSERT INTO refresh_tokens
               (jti, user_id, family_id, token_hash, encrypted_token, expires_at,
                revoked, replaced_by, created_at)
               VALUES (?,?,?,?,?,?,0,?,?)""",
            (jti, user_id, family_id, token_hash, encrypted_token, _iso(expires_at),
             None, _iso(now)),
        )
        await self.db.commit()
        return RefreshTokenRecord(
            jti=jti,
            user_id=user_id,
            family_id=family_id,
            token_hash=token_hash,
            encrypted_token=encrypted_token,
            expires_at=expires_at,
            created_at=now,
        )

    async def get_refresh_token(self, jti: str) -> RefreshTokenRecord | None:
        async with self.db.execute(
            "SELECT * FROM refresh_tokens WHERE jti = ?", (jti,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return self._row_to_refresh(row)

    async def revoke_refresh_token(self, jti: str, replaced_by: str | None = None) -> None:
        await self.db.execute(
            "UPDATE refresh_tokens SET revoked = 1, replaced_by = ? WHERE jti = ?",
            (replaced_by, jti),
        )
        await self.db.commit()

    async def revoke_family(self, family_id: str) -> int:
        """Revoke every token in a rotation family (reuse detection)."""
        cur = await self.db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ? AND revoked = 0",
            (family_id,),
        )
        await self.db.commit()
        return cur.rowcount or 0

    async def count_active_sessions(self, user_id: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        async with self.db.execute(
            "SELECT COUNT(*) AS c FROM refresh_tokens WHERE user_id = ? AND revoked = 0 AND expires_at > ?",
            (user_id, now),
        ) as cur:
            row = await cur.fetchone()
        return int(row["c"])

    async def find_refresh_token_by_hash(
        self, token_hash: str
    ) -> RefreshTokenRecord | None:
        """Find a refresh token by its deterministic SHA-256 lookup hash.

        Used for refresh + logout. The hash is computed by the caller from the
        raw token; this returns the matching row (or None).
        """
        async with self.db.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return self._row_to_refresh(row)

    @staticmethod
    def _row_to_refresh(row: aiosqlite.Row) -> RefreshTokenRecord:
        return RefreshTokenRecord(
            jti=row["jti"],
            user_id=row["user_id"],
            family_id=row["family_id"],
            token_hash=row["token_hash"],
            encrypted_token=row["encrypted_token"],
            expires_at=_dt(row["expires_at"]),  # type: ignore[arg-type]
            revoked=bool(row["revoked"]),
            replaced_by=row["replaced_by"],
            created_at=_dt(row["created_at"]),  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------ #
    # PO token cache
    # ------------------------------------------------------------------ #
    async def get_po_token(
        self, user_id: str, player_client: str
    ) -> PoTokenCacheEntry | None:
        async with self.db.execute(
            "SELECT * FROM po_token_cache WHERE user_id = ? AND player_client = ?",
            (user_id, player_client),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return PoTokenCacheEntry(
            user_id=row["user_id"],
            player_client=row["player_client"],
            token=row["token"],
            generated_at=_dt(row["generated_at"]),  # type: ignore[arg-type]
            expires_at=_dt(row["expires_at"]),  # type: ignore[arg-type]
        )

    async def set_po_token(
        self,
        user_id: str,
        player_client: str,
        token: str,
        generated_at: datetime,
        expires_at: datetime,
    ) -> None:
        await self.db.execute(
            """INSERT INTO po_token_cache
               (user_id, player_client, token, generated_at, expires_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(user_id, player_client)
               DO UPDATE SET token = excluded.token,
                             generated_at = excluded.generated_at,
                             expires_at = excluded.expires_at""",
            (user_id, player_client, token, _iso(generated_at), _iso(expires_at)),
        )
        await self.db.commit()

    # ------------------------------------------------------------------ #
    # API keys
    # ------------------------------------------------------------------ #
    async def create_api_key(
        self, user_id: str, name: str, encrypted_key: str
    ) -> ApiKey:
        key_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        await self.db.execute(
            """INSERT INTO api_keys (id, user_id, name, encrypted_key, last_used_at,
                                     created_at, revoked)
               VALUES (?,?,?,?,?, ?, 0)""",
            (key_id, user_id, name, encrypted_key, None, _iso(now)),
        )
        await self.db.commit()
        return ApiKey(
            id=key_id,
            user_id=user_id,
            name=name,
            encrypted_key=encrypted_key,
            created_at=now,
        )

    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        async with self.db.execute(
            "SELECT * FROM api_keys WHERE encrypted_key = ? AND revoked = 0",
            (key_hash,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return ApiKey(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            encrypted_key=row["encrypted_key"],
            last_used_at=_dt(row["last_used_at"]),
            created_at=_dt(row["created_at"]),  # type: ignore[arg-type]
            revoked=bool(row["revoked"]),
        )

    async def touch_api_key(self, key_id: str) -> None:
        await self.db.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (_iso(datetime.now(timezone.utc)), key_id),
        )
        await self.db.commit()

    async def list_api_keys(self, user_id: str) -> list[ApiKey]:
        async with self.db.execute(
            "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at", (user_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [
            ApiKey(
                id=r["id"],
                user_id=r["user_id"],
                name=r["name"],
                encrypted_key=r["encrypted_key"],
                last_used_at=_dt(r["last_used_at"]),
                created_at=_dt(r["created_at"]),  # type: ignore[arg-type]
                revoked=bool(r["revoked"]),
            )
            for r in rows
        ]

    async def revoke_api_key(self, key_id: str) -> None:
        await self.db.execute(
            "UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,)
        )
        await self.db.commit()

    # ------------------------------------------------------------------ #
    # Revoked JTIs (access-token revocation list)
    # ------------------------------------------------------------------ #
    async def revoke_jti(self, jti: str) -> None:
        await self.db.execute(
            "INSERT OR IGNORE INTO revoked_jti (jti, revoked_at) VALUES (?, ?)",
            (jti, _iso(datetime.now(timezone.utc))),
        )
        await self.db.commit()

    async def is_jti_revoked(self, jti: str) -> bool:
        async with self.db.execute(
            "SELECT 1 FROM revoked_jti WHERE jti = ?", (jti,)
        ) as cur:
            return await cur.fetchone() is not None
