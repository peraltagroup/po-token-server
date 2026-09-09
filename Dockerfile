# syntax=docker/dockerfile:1
#
# PO Token server — multi-stage build.
#
# Stage 1 (py-builder): install the Python package into an isolated venv.
# Stage 2 (bgutil-builder): build the bgutil Node.js PO token server.
# Stage 3 (runtime): a slim image that runs both the Python app (port 4416)
#   and the bgutil server (port 4417, internal) via a supervisor script.
#   The SQLite database lives in /app (a volume).

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
# Stage 2: bgutil Node.js server builder
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS bgutil-builder

WORKDIR /bgutil

# canvas (native dep) needs these system libs at build time
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libcairo2-dev \
        libpango1.0-dev \
        libjpeg-dev \
        libgif-dev \
        librsvg2-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the bgutil server source (pinned to a known-good commit)
RUN git clone --depth 1 https://github.com/Brainicism/bgutil-ytdlp-pot-provider.git /bgutil-src \
    && cd /bgutil-src/server \
    && npm ci --no-audit --no-fund \
    && npx tsc \
    && mkdir -p /bgutil/build \
    && cp -r build /bgutil/build/ \
    && cp package.json /bgutil/ \
    && cp -r node_modules /bgutil/node_modules/

# ---------------------------------------------------------------------------
# Stage 3: Runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PO_DATA_DIR=/app \
    PO_BGUTIL_URL=http://127.0.0.1:4417

# Runtime system libs needed by canvas (native module)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libcairo2 \
        libpango-1.0-0 \
        libjpeg62-turbo \
        libgif7 \
        librsvg2-2 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Node.js 22 (for the bgutil server)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Python app
COPY --from=py-builder /opt/venv /opt/venv
COPY --from=py-builder /build/po_token_server /app/po_token_server

# bgutil server
COPY --from=bgutil-builder /bgutil/build /app/bgutil/build
COPY --from=bgutil-builder /bgutil/node_modules /app/bgutil/node_modules
COPY --from=bgutil-builder /bgutil/package.json /app/bgutil/package.json

# Supervisor script: starts bgutil (4417) then Python app (4416)
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 4416

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4416/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
