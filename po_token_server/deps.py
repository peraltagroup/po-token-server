"""FastAPI dependencies: authentication & service access.

Provides :func:`get_current_user` which accepts either a ``Bearer <jwt>``
access token **or** a per-user API key (``X-API-Key`` header) for headless
clients such as Music Assistant provider instances.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status

from .models import User
from .security import JWTError, JWTService
from .storage import Storage


@dataclass
class AuthContext:
    """The authenticated principal for a request."""

    user: User
    # How the request was authenticated.
    via: str  # "jwt" | "api_key"
    jti: str | None = None


def _hash_api_key(key: str) -> str:
    """Store/lookup API keys by SHA-256 hash (never store the raw key)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


async def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthContext:
    """Resolve the current user from a Bearer JWT or an X-API-Key header."""
    storage: Storage = request.app.state.storage
    jwt_service: JWTService = request.app.state.jwt
    cipher = request.app.state.cipher

    # --- API key path (headless clients) -------------------------------- #
    if x_api_key:
        key_hash = _hash_api_key(x_api_key)
        api_key = await storage.get_api_key_by_hash(key_hash)
        if api_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        user = await storage.get_user(api_key.user_id)
        if user is None or user.status.value != "active":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or suspended",
            )
        await storage.touch_api_key(api_key.id)
        return AuthContext(user=user, via="api_key")

    # --- Bearer JWT path ------------------------------------------------ #
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            claims = jwt_service.decode(token)
        except JWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if await storage.is_jti_revoked(claims.jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await storage.get_user(claims.sub)
        if user is None or user.status.value != "active":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or suspended",
            )
        return AuthContext(user=user, via="jwt", jti=claims.jti)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin(
    request: Request,
    ctx: AuthContext = Depends(get_current_user),
) -> AuthContext:
    """Dependency that restricts access to admin users."""
    if not ctx.user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return ctx
