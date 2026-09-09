"""Environment-driven configuration for the PO Token server.

All settings are read from environment variables (or a local ``.env`` file) and
validated with :mod:`pydantic_settings`. Secrets are never logged.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration.

    Every field can be overridden by an environment variable of the same name
    (case-insensitive), e.g. ``PO_JWT_SECRET``.
    """

    model_config = SettingsConfigDict(
        env_prefix="PO_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Server -----------------------------------------------------------
    host: str = Field(default="0.0.0.0", description="Bind host")
    port: int = Field(default=4416, description="Bind port (matches the bgutil add-on)")
    public_url: str = Field(
        default="http://localhost:4416",
        description="Public base URL used to build absolute redirect URIs",
    )
    debug: bool = Field(default=False)

    # --- Security / signing ----------------------------------------------
    jwt_secret: str = Field(
        default_factory=lambda: secrets.token_urlsafe(48),
        description="HMAC secret for signing JWTs. MUST be set in production.",
    )
    jwt_algorithm: Literal["HS256", "RS256"] = "HS256"
    jwt_issuer: str = "po-token-server"
    jwt_audience: str = "po-token-clients"
    access_token_ttl: int = Field(
        default=15 * 60, description="Access token lifetime in seconds"
    )
    refresh_token_ttl: int = Field(
        default=30 * 24 * 60 * 60, description="Refresh token lifetime in seconds (30 days)"
    )
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(48),
        description="Fernet key material for encrypting stored secrets at rest.",
    )

    # --- OAuth 2.0 / OIDC client -----------------------------------------
    # Defaults to Google, matching the existing YouTube Music use case. Any
    # OIDC provider can be used by overriding these.
    oidc_discovery_url: str = Field(
        default="https://accounts.google.com/.well-known/openid-configuration",
        description="OpenID Connect discovery document URL",
    )
    oauth_client_id: str = Field(default="", description="OAuth client id")
    oauth_client_secret: str = Field(default="", description="OAuth client secret")
    oauth_scopes: str = Field(
        default="openid email profile",
        description="Space-separated OAuth scopes",
    )
    oauth_redirect_path: str = Field(
        default="/auth/callback", description="Redirect path (relative) for the IdP"
    )

    # --- Storage ----------------------------------------------------------
    data_dir: str = Field(default="./data", description="Directory for SQLite + keys")
    database_url: str | None = Field(
        default=None,
        description=(
            "Async aiosqlite database URL. If unset, defaults to "
            "'sqlite+aiosqlite:///<data_dir>/po_token.db' so PO_DATA_DIR is honoured."
        ),
    )

    # --- PO token generation ---------------------------------------------
    po_cache_ttl: int = Field(
        default=6 * 60 * 60,
        description="How long a generated PO token is cached per user (seconds)",
    )
    po_player_clients: str = Field(
        default="web_music,web,android",
        description="Comma-separated yt-dlp player clients to pre-generate",
    )
    bgutil_url: str = Field(
        default="http://127.0.0.1:4417",
        description="Base URL of the bgutil Node.js PO token server",
    )

    # --- Rate limiting ----------------------------------------------------
    rate_limit_auth: int = Field(
        default=20, description="Max /auth/* requests per IP per window"
    )
    rate_limit_token: int = Field(
        default=120, description="Max /get_token requests per IP per window"
    )
    rate_limit_window: int = Field(default=60, description="Rate limit window (seconds)")

    # --- CORS -------------------------------------------------------------
    cors_origins: str = Field(
        default="*", description="Comma-separated allowed CORS origins"
    )

    @field_validator("public_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @property
    def redirect_uri(self) -> str:
        """Absolute redirect URI registered with the IdP."""
        return f"{self.public_url}{self.oauth_redirect_path}"

    @property
    def resolved_database_url(self) -> str:
        """The effective aiosqlite URL.

        Defaults to a file under ``data_dir`` so that ``PO_DATA_DIR`` is
        honoured (important in Docker, where the data dir is a writable volume).
        """
        if self.database_url:
            return self.database_url
        return f"sqlite+aiosqlite:///{self.data_dir.rstrip('/')}/po_token.db"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def player_client_list(self) -> list[str]:
        return [c.strip() for c in self.po_player_clients.split(",") if c.strip()]

    def validate_for_production(self) -> list[str]:
        """Return a list of problems that would be unsafe in production."""
        problems: list[str] = []
        if self.jwt_secret == secrets.token_urlsafe(48) or len(self.jwt_secret) < 32:
            problems.append("PO_JWT_SECRET is not set (a random ephemeral key is in use)")
        if not self.oauth_client_id:
            problems.append("PO_OAUTH_CLIENT_ID is not set")
        if not self.oauth_client_secret:
            problems.append("PO_OAUTH_CLIENT_SECRET is not set")
        return problems


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
