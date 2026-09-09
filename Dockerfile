# syntax=docker/dockerfile:1
#
# PO Token server — multi-stage build.
#
# Stage 1 (py-builder): install the Python package into an isolated venv.
# Stage 2 (runtime): python:3.11-slim base with the bgutil-pot static binary
#   downloaded from GitHub releases. Runs both the bgutil server (port 4417,
#   internal) and the Python app (port 4416, external) via a supervisor script.

# ---------------------------------------------------------------------------
# Stage 1: Python builder
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS py-builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY po_token_server ./po_token_server

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install "."

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PO_DATA_DIR=/app \
    PO_BGUTIL_URL=http://127.0.0.1:4417

# Download the bgutil-pot static binary from GitHub releases
# (Rust implementation — no Node.js, no canvas, no native deps)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /usr/local/bin/bgutil-pot \
        "https://github.com/jim60105/bgutil-ytdlp-pot-provider-rs/releases/latest/download/bgutil-pot-linux-x86_64" \
    && chmod +x /usr/local/bin/bgutil-pot

WORKDIR /app

# Python app
COPY --from=py-builder /opt/venv /opt/venv
COPY --from=py-builder /build/po_token_server /app/po_token_server

# Supervisor script: starts bgutil (4417) then Python app (4416)
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 4416

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4416/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
