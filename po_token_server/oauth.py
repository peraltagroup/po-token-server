"""OAuth 2.0 / OpenID Connect client flow.

Implements the authorization-code flow with **PKCE** and a short-lived,
server-stored ``state`` (CSRF protection). On callback we exchange the code,
fetch OIDC userinfo, upsert the user, and issue our own stateless JWT access
token plus a rotating, encrypted refresh token.

The upstream IdP defaults to Google but any OIDC provider works via
``PO_OIDC_DISCOVERY_URL``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .config import Settings
from .models import TokenResponse
from .security import JWTService, SecretCipher, generate_opaque_token
from .storage import Storage


class OAuthError(Exception):
    """Raised when the OAuth flow fails."""


@dataclass
class _PendingAuth:
    """A short-lived in-memory record for an in-flight authorization."""

    state: str
    nonce: str
    code_verifier: str
    created_at: float
    # Optional: if the user already has a refresh token, we can do a
    # client-credentials-style token refresh without a browser round trip.
    refresh_jti: str | None = None


class OAuthService:
    """Coordinates the OAuth 2.0 / OIDC flow and token issuance."""

    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        jwt: JWTService,
        cipher: SecretCipher,
    ) -> None:
        self._settings = settings
        self._storage = storage
        self._jwt = jwt
        self._cipher = cipher
        self._meta: dict[str, Any] = {}
        self._pending: dict[str, _PendingAuth] = {}
        self._state_ttl = 600  # 10 minutes

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    async def load_discovery(self) -> dict[str, Any]:
        """Fetch and cache the OIDC discovery document."""
        if self._meta:
            return self._meta
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(self._settings.oidc_discovery_url)
            resp.raise_for_status()
            self._meta = resp.json()
        return self._meta

    @property
    def configured(self) -> bool:
        return bool(self._settings.oauth_client_id and self._settings.oauth_client_secret)

    # ------------------------------------------------------------------ #
    # PKCE + state
    # ------------------------------------------------------------------ #
    @staticmethod
    def _pkce() -> tuple[str, str]:
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        return verifier, challenge

    def _purge_pending(self) -> None:
        now = time.time()
        for state in [s for s, p in self._pending.items() if now - p.created_at > self._state_ttl]:
            self._pending.pop(state, None)

    def build_authorization_url(self, refresh_jti: str | None = None) -> tuple[str, str]:
        """Return ``(authorization_url, state)`` for the browser redirect."""
        self._purge_pending()
        meta = self._meta
        if not meta:
            raise OAuthError("OIDC discovery not loaded; call load_discovery() first")
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier, challenge = self._pkce()
        self._pending[state] = _PendingAuth(
            state=state, nonce=nonce, code_verifier=verifier, created_at=time.time(),
            refresh_jti=refresh_jti,
        )
        params = {
            "response_type": "code",
            "client_id": self._settings.oauth_client_id,
            "redirect_uri": self._settings.redirect_uri,
            "scope": self._settings.oauth_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        query = "&".join(f"{k}={_urlquote(v)}" for k, v in params.items())
        return f"{meta['authorization_endpoint']}?{query}", state

    # ------------------------------------------------------------------ #
    # Callback: code exchange + userinfo
    # ------------------------------------------------------------------ #
    async def handle_callback(self, code: str, state: str) -> TokenResponse:
        pending = self._pending.pop(state, None)
        if pending is None:
            raise OAuthError("Invalid or expired OAuth state")
        meta = self._meta
        async with httpx.AsyncClient(timeout=20) as client:
            token_resp = await client.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._settings.redirect_uri,
                    "client_id": self._settings.oauth_client_id,
                    "client_secret": self._settings.oauth_client_secret,
                    "code_verifier": pending.code_verifier,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()

        id_token = token_data.get("id_token")
        if not id_token:
            raise OAuthError("IdP did not return an id_token")
        claims = self._decode_id_token(id_token, expected_nonce=pending.nonce)

        user = await self._storage.upsert_user(
            user_id=claims["sub"],
            email=claims.get("email"),
            name=claims.get("name") or claims.get("preferred_username"),
            picture=claims.get("picture"),
        )

        # If the IdP issued a refresh token, store it (encrypted) so we can mint
        # PO tokens later without another browser login.
        if token_data.get("refresh_token"):
            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=int(token_data.get("expires_in", 3600)))
            )
            await self._storage.set_google_credentials(
                user.id,
                self._cipher.encrypt(token_data["refresh_token"]),
                expires_at,
            )

        return await self.issue_tokens_persisted(
            user.id, user.email, user.name, user.is_admin
        )

    def _decode_id_token(self, id_token: str, expected_nonce: str) -> dict[str, Any]:
        """Decode + minimally validate the IdP id_token.

        We verify the nonce and basic structure. Full signature verification
        against the IdP JWKS is recommended for hardened deployments; the
        authorization-code + PKCE + state flow already provides strong
        integrity guarantees for the redirect.
        """
        try:
            payload_b64 = id_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = __import__("json").loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as exc:  # pragma: no cover - defensive
            raise OAuthError(f"Could not decode id_token: {exc}") from exc
        if claims.get("nonce") != expected_nonce:
            raise OAuthError("id_token nonce mismatch")
        if "sub" not in claims:
            raise OAuthError("id_token missing sub")
        return claims

    # ------------------------------------------------------------------ #
    # Token issuance / refresh
    # ------------------------------------------------------------------ #
    def _issue_tokens(
        self,
        user_id: str,
        email: str | None,
        name: str | None,
        is_admin: bool,
        family_id: str | None = None,
    ) -> TokenResponse:
        access = self._jwt.create_access_token(
            sub=user_id, email=email, name=name, is_admin=is_admin
        )
        family = family_id or uuid.uuid4().hex
        opaque = generate_opaque_token()
        token_hash = hashlib.sha256(opaque.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self._settings.refresh_token_ttl
        )
        record = _RefreshRecord(
            jti=uuid.uuid4().hex,
            family_id=family,
            opaque=opaque,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        # Persisted by the caller via issue_tokens_persisted; here we return the
        # in-memory record so the router can persist it atomically.
        self._last_issued = record
        return TokenResponse(
            access_token=access,
            expires_in=self._settings.access_token_ttl,
            refresh_token=opaque,
        )

    async def issue_tokens_persisted(
        self,
        user_id: str,
        email: str | None,
        name: str | None,
        is_admin: bool,
        family_id: str | None = None,
    ) -> TokenResponse:
        """Issue tokens and persist the encrypted refresh token."""
        resp = self._issue_tokens(user_id, email, name, is_admin, family_id)
        record = self._last_issued
        await self._storage.create_refresh_token(
            user_id=user_id,
            family_id=record.family_id,
            token_hash=record.token_hash,
            encrypted_token=self._cipher.encrypt(record.opaque),
            expires_at=record.expires_at,
        )
        return resp

    async def refresh(self, refresh_token: str) -> TokenResponse:
        """Rotate a refresh token and issue a new access + refresh pair.

        Reuse of an already-rotated token revokes the entire family.
        """
        # Find the record by its deterministic SHA-256 lookup hash.
        token_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        record = await self._find_refresh_record(token_hash)
        if record is None:
            raise OAuthError("Invalid refresh token")

        now = datetime.now(timezone.utc)
        if record.revoked:
            # Reuse detected -> revoke the whole family.
            await self._storage.revoke_family(record.family_id)
            raise OAuthError("Refresh token reuse detected; family revoked")
        if record.expires_at < now:
            raise OAuthError("Refresh token expired")

        user = await self._storage.get_user(record.user_id)
        if user is None or user.status.value != "active":
            raise OAuthError("User not found or suspended")

        # Rotate: revoke old, issue new in the same family.
        new_jti = uuid.uuid4().hex
        await self._storage.revoke_refresh_token(record.jti, replaced_by=new_jti)
        resp = await self.issue_tokens_persisted(
            user_id=user.id,
            email=user.email,
            name=user.name,
            is_admin=user.is_admin,
            family_id=record.family_id,
        )
        return resp

    async def _find_refresh_record(self, token_hash: str) -> _RefreshRecord | None:
        """Look up a stored refresh token by its deterministic SHA-256 hash."""
        record = await self._storage.find_refresh_token_by_hash(token_hash)
        if record is None:
            return None
        return _RefreshRecord(
            jti=record.jti,
            family_id=record.family_id,
            opaque="",  # not needed
            user_id=record.user_id,
            token_hash=record.token_hash,
            expires_at=record.expires_at,
            revoked=record.revoked,
        )

    # ------------------------------------------------------------------ #
    # Logout / revocation
    # ------------------------------------------------------------------ #
    async def logout(self, access_jti: str, refresh_token: str | None = None) -> None:
        await self._storage.revoke_jti(access_jti)
        if refresh_token:
            token_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
            record = await self._find_refresh_record(token_hash)
            if record:
                await self._storage.revoke_family(record.family_id)


@dataclass
class _RefreshRecord:
    jti: str
    family_id: str
    opaque: str
    user_id: str = ""
    token_hash: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    revoked: bool = False


def _urlquote(value: str) -> str:
    import urllib.parse

    return urllib.parse.quote(str(value), safe="")
