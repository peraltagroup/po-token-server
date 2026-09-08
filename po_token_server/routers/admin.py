"""Admin router: user management, API keys, session revocation.

All endpoints require an admin JWT (``require_admin``).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..deps import AuthContext, require_admin
from ..models import UserStatus, UserSummary
from ..security import generate_opaque_token
from ..storage import Storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


def _storage(request: Request) -> Storage:
    return request.app.state.storage


def _cipher(request: Request):
    return request.app.state.cipher


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class CreateApiKeyRequest(BaseModel):
    name: str = Field(default="default", min_length=1, max_length=64)


class SetStatusRequest(BaseModel):
    status: UserStatus


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
@router.get("/users", response_model=list[UserSummary])
async def list_users(request: Request, _: AuthContext = Depends(require_admin)):
    storage = _storage(request)
    users = await storage.list_users()
    out: list[UserSummary] = []
    for u in users:
        sessions = await storage.count_active_sessions(u.id)
        out.append(
            UserSummary(
                id=u.id,
                email=u.email,
                name=u.name,
                status=u.status,
                is_admin=u.is_admin,
                created_at=u.created_at,
                has_google_credentials=bool(u.encrypted_google_refresh_token),
                active_sessions=sessions,
            )
        )
    return out


@router.post("/users/{user_id}/status")
async def set_user_status(
    user_id: str,
    body: SetStatusRequest,
    request: Request,
    _: AuthContext = Depends(require_admin),
):
    storage = _storage(request)
    user = await storage.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    await storage.set_user_status(user_id, body.status)
    return {"id": user_id, "status": body.status.value}


@router.post("/users/{user_id}/revoke-sessions")
async def revoke_user_sessions(
    user_id: str, request: Request, _: AuthContext = Depends(require_admin)
):
    """Revoke all refresh-token families for a user (forces re-login)."""
    storage = _storage(request)
    user = await storage.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # Revoke every family the user has.
    async with storage.db.execute(
        "SELECT DISTINCT family_id FROM refresh_tokens WHERE user_id = ?", (user_id,)
    ) as cur:
        rows = await cur.fetchall()
    count = 0
    for row in rows:
        count += await storage.revoke_family(row["family_id"])
    return {"user_id": user_id, "revoked_tokens": count}


# --------------------------------------------------------------------------- #
# API keys (for headless clients like MA provider instances)
# --------------------------------------------------------------------------- #
@router.get("/users/{user_id}/api-keys")
async def list_api_keys(
    user_id: str, request: Request, _: AuthContext = Depends(require_admin)
):
    storage = _storage(request)
    keys = await storage.list_api_keys(user_id)
    return [
        {
            "id": k.id,
            "name": k.name,
            "created_at": k.created_at.isoformat(),
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "revoked": k.revoked,
        }
        for k in keys
    ]


@router.post("/users/{user_id}/api-keys")
async def create_api_key(
    user_id: str,
    body: CreateApiKeyRequest,
    request: Request,
    _: AuthContext = Depends(require_admin),
):
    """Create a new API key. The raw key is returned ONCE — store it securely."""
    storage = _storage(request)
    cipher = _cipher(request)
    user = await storage.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    raw_key = f"pot_{generate_opaque_token(32)}"
    # Store the SHA-256 hash (lookup is by hash), not the raw key.
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    record = await storage.create_api_key(
        user_id=user_id, name=body.name, encrypted_key=key_hash
    )
    logger.info("Created API key %s for user %s", record.id, user_id)
    return {
        "id": record.id,
        "name": record.name,
        "api_key": raw_key,  # returned once only
        "created_at": record.created_at.isoformat(),
        "warning": "Store this key now; it cannot be retrieved again.",
    }


@router.delete("/users/{user_id}/api-keys/{key_id}")
async def revoke_api_key(
    user_id: str,
    key_id: str,
    request: Request,
    _: AuthContext = Depends(require_admin),
):
    storage = _storage(request)
    keys = await storage.list_api_keys(user_id)
    if not any(k.id == key_id for k in keys):
        raise HTTPException(status_code=404, detail="API key not found")
    await storage.revoke_api_key(key_id)
    return {"id": key_id, "revoked": True}
