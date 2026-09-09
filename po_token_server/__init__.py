"""Self-hosted, multi-user PO Token server.

Provides OAuth 2.0 / OpenID Connect login, stateless JWT sessions, automatic
token refresh, concurrent multi-user support, and a yt-dlp-compatible
``/get_token`` endpoint for Music Assistant / yt-dlp clients.
"""

from __future__ import annotations

__version__ = "1.1.3"
__all__ = ["__version__"]
