#!/bin/sh
set -e

echo "[entrypoint] Starting bgutil PO token server on port 4417..."
cd /app/bgutil
node build/main.js --port 4417 --host 127.0.0.1 &
BGUTIL_PID=$!

# Wait for bgutil to be ready (up to 30s)
echo "[entrypoint] Waiting for bgutil server to be ready..."
for i in $(seq 1 30); do
    if python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4417/ping', timeout=2)" 2>/dev/null; then
        echo "[entrypoint] bgutil server is ready."
        break
    fi
    sleep 1
done

# Trap SIGTERM/SIGINT to clean up bgutil
trap "kill $BGUTIL_PID 2>/dev/null; wait $BGUTIL_PID 2>/dev/null" TERM INT

echo "[entrypoint] Starting PO Token Server (Python) on port 4416..."
exec po-token-server
