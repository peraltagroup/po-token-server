"""Token router: yt-dlp-compatible PO token endpoints.

* ``GET /get_token``        — yt-dlp / Music Assistant compatible endpoint
* ``GET /api/v1/tokens``    — structured PO token request
* ``GET /api/v1/status``    — generator + server status
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .. import __version__
from ..deps import AuthContext, get_current_user
from ..models import PoTokenResponse
from ..potoken import POTokenError, POTokenGenerator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tokens"])


def _get_generator(request: Request) -> POTokenGenerator:
    return request.app.state.potoken


@router.get("/get_token")
async def get_token(
    request: Request,
    ctx: AuthContext = Depends(get_current_user),
    video_id: str | None = Query(default=None),
    player_client: str | None = Query(default=None),
    # Accepted for yt-dlp compatibility (ignored beyond video_id extraction).
    url: str | None = Query(default=None),
    format_id: str | None = Query(default=None),
) -> JSONResponse:
    """yt-dlp-compatible PO token endpoint.

    Mirrors the ``bgutil-ytdlp-pot-provider`` HTTP contract: returns a JSON
    object containing the PO token. When called without a video id it still
    returns a token (some clients request a generic token first).
    """
    gen: POTokenGenerator = request.app.state.potoken
    try:
        result: PoTokenResponse = await gen.get_token(
            user_id=ctx.user.id,
            player_client=player_client,
            video_id=video_id,
        )
    except POTokenError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    # Return the full structured payload; yt-dlp reads po_token / gvs_po_token.
    return JSONResponse(result.model_dump(mode="json"))


@router.get("/api/v1/tokens", response_model=PoTokenResponse)
async def api_tokens(
    request: Request,
    ctx: AuthContext = Depends(get_current_user),
    video_id: str | None = Query(default=None),
    player_client: str | None = Query(default=None),
) -> PoTokenResponse:
    """Structured PO token request (same as /get_token, typed response)."""
    gen: POTokenGenerator = request.app.state.potoken
    try:
        return await gen.get_token(
            user_id=ctx.user.id,
            player_client=player_client,
            video_id=video_id,
        )
    except POTokenError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/v1/status")
async def status(request: Request) -> dict[str, Any]:
    """Generator + server status (public, no auth required)."""
    gen: POTokenGenerator = request.app.state.potoken
    settings = request.app.state.settings
    gen_status = await gen.status()
    return {
        "status": "ok",
        "version": __version__,
        "oidc_configured": request.app.state.oauth.configured,
        "generator": gen_status,
        "player_clients": settings.player_client_list,
    }
