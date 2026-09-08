"""Security primitives: JWT sign/verify, Fernet encryption, secret redaction.

Design goals
------------
* **Stateless access tokens** — signed JWTs validated without any server-side
  session store.
* **Encrypted secrets at rest** — Google refresh tokens / cookies are encrypted
  with a Fernet key derived from :data:`Settings.secret_key`.
* **No secrets in logs** — :func:`redact` scrubs known secret fields.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken

from .config import Settings

# Fields that must never appear in logs.
_SECRET_FIELDS = {
    "refresh_token",
    "access_token",
    "id_token",
    "client_secret",
    "code_verifier",
    "code",
    "cookie",
    "password",
    "token",
}


# --------------------------------------------------------------------------- #
# Fernet (symmetric) encryption for secrets at rest
# --------------------------------------------------------------------------- #
class SecretCipher:
    """Encrypt/decrypt secrets using a Fernet key derived from a passphrase.

    Fernet requires a 32-byte url-safe base64 key. We derive one deterministically
    from the configured ``secret_key`` via SHA-256 so operators can supply any
    string.
    """

    def __init__(self, key_material: str) -> None:
        digest = hashlib.sha256(key_material.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")

    def is_valid_token(self, token: str) -> bool:
        try:
            self._fernet.decrypt(token.encode("ascii"))
            return True
        except (InvalidToken, ValueError):
            return False


# --------------------------------------------------------------------------- #
# JWT access tokens
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TokenClaims:
    """Decoded, validated claims from an access token."""

    sub: str
    email: str | None
    name: str | None
    jti: str
    exp: int
    iat: int
    scope: str | None = None
    is_admin: bool = False


class JWTError(Exception):
    """Raised when a JWT cannot be validated."""


def _now() -> int:
    return int(time.time())


class JWTService:
    """Sign and verify stateless access tokens."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def create_access_token(
        self,
        sub: str,
        email: str | None = None,
        name: str | None = None,
        scope: str | None = None,
        is_admin: bool = False,
        ttl: int | None = None,
    ) -> str:
        now = _now()
        payload: dict[str, Any] = {
            "iss": self._settings.jwt_issuer,
            "aud": self._settings.jwt_audience,
            "sub": sub,
            "iat": now,
            "exp": now + (ttl or self._settings.access_token_ttl),
            "jti": uuid.uuid4().hex,
        }
        if email:
            payload["email"] = email
        if name:
            payload["name"] = name
        if scope:
            payload["scope"] = scope
        if is_admin:
            payload["admin"] = True
        return jwt.encode(payload, self._settings.jwt_secret, algorithm=self._settings.jwt_algorithm)

    def decode(self, token: str) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._settings.jwt_secret,
                algorithms=[self._settings.jwt_algorithm],
                issuer=self._settings.jwt_issuer,
                audience=self._settings.jwt_audience,
                options={"require": ["exp", "iat", "sub", "jti"]},
            )
        except jwt.PyJWTError as exc:  # pragma: no cover - re-raised below
            raise JWTError(str(exc)) from exc
        return TokenClaims(
            sub=payload["sub"],
            email=payload.get("email"),
            name=payload.get("name"),
            jti=payload["jti"],
            exp=payload["exp"],
            iat=payload["iat"],
            scope=payload.get("scope"),
            is_admin=bool(payload.get("admin", False)),
        )


# --------------------------------------------------------------------------- #
# Opaque refresh tokens
# --------------------------------------------------------------------------- #
def generate_opaque_token(nbytes: int = 48) -> str:
    """Generate a high-entropy opaque token (used for refresh tokens / API keys)."""
    return base64.urlsafe_b64encode(hashlib.sha256(uuid.uuid4().bytes + nbytes * b"\0").digest() * 2)[: nbytes].decode("ascii")


def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time string comparison to avoid timing side channels."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Log redaction
# --------------------------------------------------------------------------- #
def redact(obj: Any) -> Any:
    """Return a copy of ``obj`` with secret fields masked.

    Works recursively on dicts / lists. Non-dict values pass through unchanged.
    """
    if isinstance(obj, dict):
        return {
            k: ("***REDACTED***" if k.lower() in _SECRET_FIELDS else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def redact_json(obj: Any) -> str:
    """Serialize ``obj`` to JSON with secrets redacted (for logging)."""
    return json.dumps(redact(obj), ensure_ascii=False, default=str)
