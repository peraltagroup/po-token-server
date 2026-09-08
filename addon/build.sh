#!/usr/bin/env bash
#
# Build (and optionally push) the PO Token Server add-on images for every
# architecture listed in $ARCHS, then tag them as the add-on expects.
#
# Usage:
#   ./build.sh                 # build amd64 only (default)
#   ARCHS="amd64 aarch64" REGISTRY=ghcr.io/example ./build.sh --push
#
# Environment:
#   REGISTRY   container registry (default: example)
#   IMAGE      image name (default: po-token-server)
#   VERSION    add-on version (default: 1.0.0)
#   ARCHS      space-separated arch list (default: amd64)
#
# The build context is the repo root (the parent of this script's directory),
# because the Dockerfile COPYs pyproject.toml + po_token_server/ from there.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The per-arch Dockerfiles + config.yaml live under <repo-root>/data/<arch>/.
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REGISTRY="${REGISTRY:-example}"
IMAGE="${IMAGE:-po-token-server}"
VERSION="${VERSION:-1.0.0}"
ARCHS="${ARCHS:-amd64}"
PUSH=0
[[ "${1:-}" == "--push" ]] && PUSH=1

echo ">> Building ${REGISTRY}/${IMAGE} v${VERSION} for: ${ARCHS}"

for arch in ${ARCHS}; do
  echo ">> [${arch}] building..."
  docker buildx build \
    --platform "linux/${arch}" \
    -f "${REPO_ROOT}/data/${arch}/Dockerfile" \
    -t "${REGISTRY}/${IMAGE}:${arch}-${VERSION}" \
    "${REPO_ROOT}"

  if [[ "${PUSH}" -eq 1 ]]; then
    echo ">> [${arch}] pushing..."
    docker push "${REGISTRY}/${IMAGE}:${arch}-${VERSION}"
  fi
done

echo ">> Done. Remember to set the matching 'image:' value in each"
echo ">> data/<arch>/config.yaml (e.g. ${REGISTRY}/${IMAGE}:<arch>-${VERSION})."
