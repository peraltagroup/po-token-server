"""Pydantic schemas shared across the API and storage layers."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class User(BaseModel):
    """A registered user, identified by their IdP ``sub``."""

    id: str = Field(description="Stable IdP subject identifier")
    email: str | None = None
    name: str | None = None
    picture: str | None = None
    status: UserStatus = UserStatus.ACTIVE
    is_admin: bool = False
    # Encrypted Google refresh token (or cookie blob) used to mint PO tokens.
    encrypted_google_refresh_token: str | None = None
    google_refresh_token_expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class RefreshTokenRecord(BaseModel):
    """A stored (encrypted) refresh token belonging to a user.

    Refresh tokens are rotated on use; ``family_id`` groups all tokens in a
    rotation chain so reuse of an old token revokes the whole family.

    ``token_hash`` is a deterministic SHA-256 of the raw token used for fast
    lookup; ``encrypted_token`` is the Fernet-encrypted raw token (the actual
    secret, never used for lookup since Fernet ciphertexts are non-deterministic).
    """

    jti: str = Field(description="Unique token id")
    user_id: str
    family_id: str
    token_hash: str = Field(description="SHA-256 hex of the raw token (lookup key)")
    encrypted_token: str
    expires_at: datetime
    revoked: bool = False
    replaced_by: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class PoTokenCacheEntry(BaseModel):
    """A cached PO token for a user + player client."""

    user_id: str
    player_client: str
    token: str
    generated_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime


class ApiKey(BaseModel):
    """A per-user API key for headless clients (e.g. MA provider instances)."""

    id: str
    user_id: str
    name: str
    encrypted_key: str
    last_used_at: datetime | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    revoked: bool = False


class TokenResponse(BaseModel):
    """OAuth-style token response returned by /auth/token and /auth/refresh."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


class PoTokenRequest(BaseModel):
    """Parameters for a PO token request (yt-dlp compatible)."""

    video_id: str | None = None
    player_client: str | None = None
    # yt-dlp sometimes sends these; accepted for compatibility.
    url: str | None = None
    format_id: str | None = None


class PoTokenResponse(BaseModel):
    """PO token payload returned to yt-dlp / Music Assistant."""

    po_token: str
    player_client: str
    video_id: str | None = None
    generated_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime
    # Extra fields some clients expect.
    gvs_po_token: str | None = None
    visitor_data: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UserSummary(BaseModel):
    """Public (non-secret) view of a user for the admin API."""

    id: str
    email: str | None
    name: str | None
    status: UserStatus
    is_admin: bool
    created_at: datetime
    has_google_credentials: bool = False
    active_sessions: int = 0


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    time: datetime = Field(default_factory=_utcnow)
    oidc_configured: bool
    users: int = 0
