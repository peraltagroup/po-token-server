"""Token router: yt-dlp-compatible PO token endpoints.

* ``GET|POST /get_token``   — yt-dlp / Music Assistant compatible endpoint
* ``GET /api/v1/tokens``    — structured PO token request
* ``GET /api/v1/status``    — generator + server status
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .. import __version__
from ..deps import AuthContext, get_current_user
from ..models import PoTokenResponse
from ..potoken import POTokenError, POTokenGenerator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tokens"])

# Matches a YouTube video id (11 chars: A-Za-z0-9_-) in a URL or bare string.
_VIDEO_ID_RE = re.compile(r"(?:v=|/v/|youtu\.be/|/embed/|/live/)([A-Za-z0-9_-]{11})")


def _extract_video_id(url: str) -> str | None:
    """Best-effort extraction of a YouTube video id from a URL."""
    m = _VIDEO_ID_RE.search(url)
    if m:
        return m.group(1)
    # Bare 11-char id.
    if len(url) == 11 and re.fullmatch(r"[A-Za-z0-9_-]{11}", url):
        return url
    return None


def _get_generator(request: Request) -> POTokenGenerator:
    return request.app.state.potoken


@router.api_route("/get_token", methods=["GET", "POST"])
async def get_token(
    request: Request,
    ctx: AuthContext = Depends(get_current_user),
) -> JSONResponse:
    """yt-dlp-compatible PO token endpoint.

    Mirrors the ``bgutil-ytdlp-pot-provider`` HTTP contract: returns a JSON
    object containing the PO token. When called without a video id it still
    returns a token (some clients request a generic token first).

    Accepts both GET and POST. Music Assistant's YouTube Music provider calls
    this endpoint with POST; yt-dlp uses GET. Parameters may arrive as query
    params (GET) or a JSON body (POST) — both are handled.
    """
    # Resolve params from the query string first, then fall back to a JSON
    # body (POST). Query params take precedence if present.
    qp = request.query_params
    body: dict[str, Any] = {}
    if request.method == "POST":
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            body = {}

    def _param(name: str) -> str | None:
        val = qp.get(name)
        if val is not None:
            return val
        val = body.get(name)
        return str(val) if val is not None else None

    video_id = _param("video_id")
    player_client = _param("player_client")
    # url / format_id are accepted for yt-dlp compatibility; url is used to
    # extract a video_id when video_id is not explicitly provided.
    if video_id is None:
        url = _param("url")
        if url:
            video_id = _extract_video_id(url)

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
