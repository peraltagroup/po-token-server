# syntax=docker/dockerfile:1
#
# Home Assistant add-on build for the PO Token server (amd64).
#
# The build context is the REPO ROOT (see addon/build.sh), so the COPY paths
# below reference pyproject.toml + po_token_server/ at the top level. The
# add-on stores its config in /config (mapped from the host) and receives its
# options as PO_* environment variables (see config.yaml `options`/`schema`).

FROM python:3.11-slim AS builder

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
    && /opt/venv/bin/pip install ".[pot]"

# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PO_DATA_DIR=/config

RUN groupadd -r potoken && useradd -r -g potoken -d /config potoken \
    && mkdir -p /config && chown -R potoken:potoken /config

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/po_token_server /app/po_token_server

USER potoken

EXPOSE 4416

ENTRYPOINT ["po-token-server"]
