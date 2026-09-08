"""Command-line entrypoint: ``python -m po_token_server`` or ``po-token-server``."""

from __future__ import annotations

import logging
import sys

import uvicorn

from .app import create_app
from .config import get_settings


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
        stream=sys.stdout,
    )
    # Quiet down noisy third-party loggers.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def main() -> None:
    settings = get_settings()
    _configure_logging(settings.debug)
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="debug" if settings.debug else "info",
        access_log=False,  # we log our own structured lines
    )


if __name__ == "__main__":
    main()
