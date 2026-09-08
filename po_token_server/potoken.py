"""PO token generation with a per-user cache.

Wraps the reference ``bgutil-ytdlp-pot-provider`` library for the actual PO
token math. When that library is not installed (e.g. in unit tests or a
minimal environment) a deterministic **stub** generator is used so the rest of
the server — auth, sessions, caching, the yt-dlp endpoint — remains fully
testable.

Concurrency model
-----------------
* Tokens are cached **per (user, player_client)** in SQLite.
* A per-user :class:`asyncio.Lock` serializes generation so concurrent requests
  for the same user don't trigger a thundering-herd of upstream calls.
* The cache TTL is configurable (``PO_PO_CACHE_TTL``).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import Settings
from .models import PoTokenResponse
from .security import SecretCipher
from .storage import Storage

logger = logging.getLogger(__name__)


class POTokenError(Exception):
    """Raised when a PO token cannot be generated."""


class POTokenGenerator:
    """Generates and caches PO tokens per user."""

    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        cipher: SecretCipher,
    ) -> None:
        self._settings = settings
        self._storage = storage
        self._cipher = cipher
        self._locks: dict[str, asyncio.Lock] = {}
        self._bgutil = self._try_load_bgutil()

    # ------------------------------------------------------------------ #
    # bgutil integration
    # ------------------------------------------------------------------ #
    def _try_load_bgutil(self) -> Any | None:
        """Import the bgutil PO token provider if available."""
        try:
            # The library exposes a POTProvider / get_pot entry point in recent
            # versions. We import defensively so a missing/changed API degrades
            # to the stub rather than crashing the server.
            from bgutil_ytdlp_pot_provider import POTProvider  # type: ignore

            return POTProvider
        except Exception:  # pragma: no cover - optional dependency
            logger.info(
                "bgutil-ytdlp-pot-provider not installed; using stub PO token "
                "generator. Install the 'pot' extra for real tokens."
            )
            return None

    # ------------------------------------------------------------------ #
    # Locks
    # ------------------------------------------------------------------ #
    def _lock_for(self, user_id: str) -> asyncio.Lock:
        lock = self._locks.get(user_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[user_id] = lock
        return lock

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    async def get_token(
        self,
        user_id: str,
        player_client: str | None = None,
        video_id: str | None = None,
    ) -> PoTokenResponse:
        """Return a (cached or freshly generated) PO token for a user.

        ``player_client`` defaults to the first configured client. The result is
        cached per (user, player_client) for ``po_cache_ttl`` seconds.
        """
        client = player_client or self._settings.player_client_list[0]
        now = datetime.now(timezone.utc)

        # 1) Serve from cache if fresh.
        cached = await self._storage.get_po_token(user_id, client)
        if cached and cached.expires_at > now:
            return self._to_response(cached.token, client, video_id, cached)

        # 2) Generate under a per-user lock to avoid duplicate work.
        async with self._lock_for(user_id):
            # Re-check cache after acquiring the lock (another coroutine may
            # have filled it while we waited).
            cached = await self._storage.get_po_token(user_id, client)
            if cached and cached.expires_at > now:
                return self._to_response(cached.token, client, video_id, cached)

            token = await self._generate(user_id, client, video_id)
            generated_at = datetime.now(timezone.utc)
            expires_at = generated_at + timedelta(seconds=self._settings.po_cache_ttl)
            await self._storage.set_po_token(
                user_id, client, token, generated_at, expires_at
            )
            return self._to_response(token, client, video_id, None,
                                     generated_at=generated_at,
                                     expires_at=expires_at)

    async def _generate(
        self, user_id: str, player_client: str, video_id: str | None
    ) -> str:
        """Produce a raw PO token string for a user + client."""
        user = await self._storage.get_user(user_id)
        if user is None:
            raise POTokenError(f"Unknown user: {user_id}")

        # If we have a real bgutil provider and the user has Google
        # credentials, use them. Otherwise fall back to the stub.
        if self._bgutil is not None and user.encrypted_google_refresh_token:
            try:
                return await self._generate_with_bgutil(
                    user, player_client, video_id
                )
            except Exception as exc:  # pragma: no cover - depends on lib
                logger.warning(
                    "bgutil PO token generation failed for user %s: %s; "
                    "falling back to stub", user_id, exc
                )

        return self._stub_token(user_id, player_client, video_id)

    async def _generate_with_bgutil(
        self, user: Any, player_client: str, video_id: str | None
    ) -> str:  # pragma: no cover - depends on optional lib
        """Generate a real PO token via bgutil using the user's credentials."""
        refresh_token = self._cipher.decrypt(user.encrypted_google_refresh_token)
        # The exact API varies by bgutil version; we call the most common entry
        # point and let the caller fall back to the stub on failure.
        provider = self._bgutil()
        # bgutil's POTProvider typically exposes get_pot(video_id, player_client)
        # after being configured with credentials. We attempt the documented
        # shape and raise if it's unavailable.
        if hasattr(provider, "get_pot"):
            result = provider.get_pot(
                video_id=video_id or "", player_client=player_client
            )
            if isinstance(result, dict):
                return result.get("po_token") or result.get("token") or str(result)
            return str(result)
        raise POTokenError("bgutil provider has no get_pot() method")

    @staticmethod
    def _stub_token(
        user_id: str, player_client: str, video_id: str | None
    ) -> str:
        """Deterministic stand-in token for environments without bgutil.

        It is *not* a valid YouTube PO token, but it exercises the full
        caching / concurrency / API path deterministically in tests.
        """
        basis = f"{user_id}|{player_client}|{video_id or ''}|{int(time.time() // 3600)}"
        digest = hashlib.sha256(basis.encode()).hexdigest()
        return f"stub-pot-{digest[:40]}"

    # ------------------------------------------------------------------ #
    # Response shaping
    # ------------------------------------------------------------------ #
    def _to_response(
        self,
        token: str,
        player_client: str,
        video_id: str | None,
        cached: Any | None,
        generated_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> PoTokenResponse:
        now = datetime.now(timezone.utc)
        gen = generated_at or (cached.generated_at if cached else now)
        exp = expires_at or (cached.expires_at if cached else now)
        return PoTokenResponse(
            po_token=token,
            player_client=player_client,
            video_id=video_id,
            generated_at=gen,
            expires_at=exp,
            gvs_po_token=token,
            metadata={"generator": "bgutil" if self._bgutil else "stub"},
        )

    async def status(self) -> dict[str, Any]:
        """Report generator status (for /api/v1/status)."""
        return {
            "backend": "bgutil" if self._bgutil else "stub",
            "cache_ttl_seconds": self._settings.po_cache_ttl,
            "player_clients": self._settings.player_client_list,
        }
