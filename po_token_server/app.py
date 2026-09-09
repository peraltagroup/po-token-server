"""FastAPI application factory.

Wires together configuration, storage, security, OAuth, and the PO token
generator; registers routers, middleware (CORS, security headers, rate
limiting, request logging), and lifecycle handlers.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .config import Settings, get_settings
from .oauth import OAuthService
from .potoken import POTokenGenerator
from .routers import admin, auth, tokens
from .security import JWTService, SecretCipher, redact_json
from .storage import Storage

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Simple in-memory sliding-window rate limiter (per IP)
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Fixed-window rate limiter keyed by client IP.

    In-memory and per-process; sufficient for a single-node HA add-on. For
    horizontal scaling, swap for a shared store (e.g. Redis).
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        dq = self._hits[key]
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # --- startup ----------------------------------------------------- #
        storage = Storage(settings.resolved_database_url)
        await storage.connect()
        cipher = SecretCipher(settings.secret_key)
        jwt_service = JWTService(settings)
        oauth = OAuthService(settings, storage, jwt_service, cipher)
        potoken = POTokenGenerator(settings, storage, cipher)
        await potoken.start()

        app.state.settings = settings
        app.state.storage = storage
        app.state.cipher = cipher
        app.state.jwt = jwt_service
        app.state.oauth = oauth
        app.state.potoken = potoken
        app.state.rate_limiter = RateLimiter()

        problems = settings.validate_for_production()
        if problems:
            for p in problems:
                logger.warning("Production config warning: %s", p)
        logger.info(
            "PO Token Server v%s started (port=%s, oidc_configured=%s)",
            __version__,
            settings.port,
            oauth.configured,
        )
        yield
        # --- shutdown ---------------------------------------------------- #
        await potoken.stop()
        await storage.close()
        logger.info("PO Token Server stopped")

    app = FastAPI(
        title="PO Token Server",
        version=__version__,
        description=(
            "Self-hosted, multi-user PO Token server with OAuth 2.0 / OIDC "
            "login, stateless JWT sessions, and a yt-dlp-compatible /get_token "
            "endpoint."
        ),
        lifespan=lifespan,
        debug=settings.debug,
    )

    # --- CORS ------------------------------------------------------------ #
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,  # we use Bearer headers, not cookies
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Security headers + rate limiting + logging ---------------------- #
    @app.middleware("http")
    async def security_and_ratelimit(request: Request, call_next):
        # Rate limit auth + token endpoints per IP.
        path = request.url.path
        limiter: RateLimiter = request.app.state.rate_limiter
        if path.startswith("/auth/"):
            if not limiter.allow(
                _client_ip(request), settings.rate_limit_auth, settings.rate_limit_window
            ):
                return JSONResponse(
                    {"detail": "Too many requests"}, status_code=429
                )
        elif path in ("/get_token",) or path.startswith("/api/v1/tokens"):
            if not limiter.allow(
                _client_ip(request), settings.rate_limit_token, settings.rate_limit_window
            ):
                return JSONResponse(
                    {"detail": "Too many requests"}, status_code=429
                )

        start = time.perf_counter()
        response: Response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Security headers.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if settings.public_url.startswith("https://"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        response.headers.setdefault("Cache-Control", "no-store")

        if request.method != "GET" or path.startswith("/auth/"):
            logger.info(
                "%s %s -> %d (%.1fms)",
                request.method,
                path,
                response.status_code,
                elapsed_ms,
            )
        return response

    # --- Routers --------------------------------------------------------- #
    app.include_router(auth.router)
    app.include_router(tokens.router)
    app.include_router(admin.router)

    # --- Health / readiness --------------------------------------------- #
    @app.get("/health", tags=["health"])
    async def health(request: Request) -> dict[str, Any]:
        storage: Storage = request.app.state.storage
        users = await storage.count_users()
        return {
            "status": "ok",
            "version": __version__,
            "oidc_configured": request.app.state.oauth.configured,
            "users": users,
        }

    @app.get("/ready", tags=["health"])
    async def ready() -> dict[str, str]:
        return {"status": "ready"}

    return app


app = create_app()
