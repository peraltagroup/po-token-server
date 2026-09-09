"""PO token generation with a per-user cache.

Delegates actual PO token generation to the bundled **bgutil Node.js server**
(which runs as a sidecar process on ``PO_BGUTIL_URL``, default
``http://127.0.0.1:4417``). When the bgutil server is unreachable (e.g. in
unit tests or a minimal environment) a deterministic **stub** generator is
used so the rest of the server — auth, sessions, caching, the yt-dlp
endpoint — remains fully testable.

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
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

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
        self._bgutil_url = settings.bgutil_url.rstrip("/")
        self._bgutil_available: bool | None = None  # lazily probed
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        """Create the shared HTTP client and probe the bgutil server."""
        self._http = httpx.AsyncClient(timeout=60.0)
        self._bgutil_available = await self._probe_bgutil()
        if self._bgutil_available:
            logger.info("bgutil server available at %s", self._bgutil_url)
        else:
            logger.warning(
                "bgutil server NOT reachable at %s — using stub PO token "
                "generator. Real tokens require the bgutil Node.js server.",
                self._bgutil_url,
            )

    async def stop(self) -> None:
        """Close the HTTP client."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _probe_bgutil(self) -> bool:
        """Check whether the bgutil server is up via GET /ping."""
        if self._http is None:
            return False
        try:
            resp = await self._http.get(f"{self._bgutil_url}/ping", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                logger.info(
                    "bgutil server ping OK (version=%s, uptime=%.1fs)",
                    data.get("version", "?"),
                    data.get("server_uptime", 0),
                )
                return True
        except Exception as exc:
            logger.debug("bgutil ping failed: %s", exc)
        return False

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

        # Try the bgutil HTTP server first.
        if await self._bgutil_ready():
            try:
                return await self._generate_via_bgutil_http(
                    user, player_client, video_id
                )
            except Exception as exc:
                logger.warning(
                    "bgutil HTTP PO token generation failed for user %s: %s; "
                    "falling back to stub", user_id, exc,
                )

        return self._stub_token(user_id, player_client, video_id)

    # ------------------------------------------------------------------ #
    # bgutil HTTP integration
    # ------------------------------------------------------------------ #
    async def _bgutil_ready(self) -> bool:
        """Return True if the bgutil server is (still) reachable."""
        if self._bgutil_available is True:
            return True
        # Re-probe if we previously failed (server may have come up).
        self._bgutil_available = await self._probe_bgutil()
        return self._bgutil_available

    async def _generate_via_bgutil_http(
        self, user: Any, player_client: str, video_id: str | None
    ) -> str:
        """Call the bgutil Node.js server's POST /get_pot endpoint.

        The bgutil server generates a PO token using BotGuard attestation.
        It does NOT require user credentials — it mints anonymous tokens
        that are valid for the given player client context.
        """
        if self._http is None:
            raise POTokenError("HTTP client not initialised")

        # Build the InnerTube context for the requested player client.
        innertube_context = self._build_innertube_context(player_client)

        payload: dict[str, Any] = {
            "bypass_cache": False,
        }
        if innertube_context:
            payload["innertube_context"] = innertube_context
        if video_id:
            # For player tokens the content binding is the video ID.
            payload["content_binding"] = video_id

        url = f"{self._bgutil_url}/get_pot"
        logger.debug("Calling bgutil %s with payload keys: %s", url, list(payload.keys()))

        resp = await self._http.post(url, json=payload, timeout=120.0)

        if resp.status_code != 200:
            body = resp.text[:500]
            raise POTokenError(
                f"bgutil server returned {resp.status_code}: {body}"
            )

        data = resp.json()
        po_token = data.get("poToken") or data.get("po_token")
        if not po_token:
            raise POTokenError(
                f"bgutil server response missing poToken: {json.dumps(data)[:300]}"
            )

        logger.info(
            "bgutil generated PO token for client=%s video=%s (len=%d)",
            player_client, video_id or "none", len(po_token),
        )
        return po_token

    @staticmethod
    def _build_innertube_context(player_client: str) -> dict[str, Any] | None:
        """Build a minimal InnerTube context for the given player client.

        The bgutil server uses this to determine which BotGuard attestation
        to generate. If the client is unknown, returns None (bgutil will
        use its default).
        """
        # Map our player client names to InnerTube client names.
        client_map = {
            "web_music": {
                "client": {
                    "clientName": "WEB_REMIX",
                    "clientVersion": "2.20240101.00.00",
                    "hl": "en",
                    "gl": "US",
                }
            },
            "web": {
                "client": {
                    "clientName": "WEB",
                    "clientVersion": "2.20240101.00.00",
                    "hl": "en",
                    "gl": "US",
                }
            },
            "android": {
                "client": {
                    "clientName": "ANDROID_MUSIC",
                    "clientVersion": "8.19.19",
                    "androidSdkVersion": 30,
                    "hl": "en",
                    "gl": "US",
                }
            },
        }
        return client_map.get(player_client)

    # ------------------------------------------------------------------ #
    # Credential parsing (kept for future use / OAuth flow)
    # ------------------------------------------------------------------ #
    def _parse_credentials(self, user: Any) -> dict[str, Any] | None:
        """Decrypt and parse the user's stored Google credential blob.

        Returns a dict with ``type`` = "username_password" or "refresh_token",
        or None if no credentials are stored / parsing fails.
        """
        if not user.encrypted_google_refresh_token:
            return None
        try:
            raw = self._cipher.decrypt(user.encrypted_google_refresh_token)
        except Exception:
            # Not a Fernet-encrypted blob — treat as a raw refresh token.
            return {"type": "refresh_token", "token": user.encrypted_google_refresh_token}
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "type" in data:
                return data
        except Exception:
            pass
        # Not JSON — treat as a raw refresh token.
        return {"type": "refresh_token", "token": raw}

    # ------------------------------------------------------------------ #
    # Stub fallback
    # ------------------------------------------------------------------ #
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
        is_stub = token.startswith("stub-pot-")
        return PoTokenResponse(
            po_token=token,
            player_client=player_client,
            video_id=video_id,
            generated_at=gen,
            expires_at=exp,
            gvs_po_token=token,
            metadata={
                "generator": "stub" if is_stub else "bgutil",
                "bgutil_url": self._bgutil_url,
                "bgutil_available": self._bgutil_available,
            },
        )

    async def status(self) -> dict[str, Any]:
        """Report generator status (for /api/v1/status)."""
        return {
            "backend": "bgutil" if self._bgutil_available else "stub",
            "bgutil_url": self._bgutil_url,
            "bgutil_available": self._bgutil_available,
            "cache_ttl_seconds": self._settings.po_cache_ttl,
            "player_clients": self._settings.player_client_list,
        }
