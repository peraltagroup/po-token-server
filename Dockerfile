# syntax=docker/dockerfile:1
#
# PO Token server — multi-stage build.
#
# Stage 1 (builder): install the package + the optional `pot` extra (the real
#   bgutil PO-token math) into an isolated venv.
# Stage 2 (runtime): a slim, non-root image that copies the venv and runs the
#   server. The SQLite database lives in /data (a volume).

FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Install build deps for any wheels that need compiling (cryptography ships
# wheels for slim, so this is usually a no-op, but keep gcc for safety).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY po_token_server ./po_token_server

# Build a venv with the runtime deps + the real PO token provider.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install ".[pot]"

# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PO_DATA_DIR=/config

# Note: runs as root (like most HAOS add-ons) so it can write to the
# mapped /config volume. The container provides the security isolation.

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/po_token_server /app/po_token_server

EXPOSE 4416

# Healthcheck hits the /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4416/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["po-token-server"]
