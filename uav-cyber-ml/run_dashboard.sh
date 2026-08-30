#!/usr/bin/env bash
# Launch the UAV Cyber Digital-Twin dashboard.
# Primes sudo once (tcpdump needs it for live network capture) and keeps the
# credential fresh so captures work throughout the session.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8000}"

echo "==> Network capture uses tcpdump (sudo). Priming sudo (Ctrl-C to skip)…"
if sudo -v; then
  ( while true; do sudo -n -v 2>/dev/null || exit; sleep 60; done ) &
  KEEPER=$!
  trap 'kill $KEEPER 2>/dev/null || true' EXIT
else
  echo "!! sudo not primed — network capture will be disabled (physical layer still works)."
fi

echo "==> Dashboard:  http://127.0.0.1:${PORT}"
exec .venv/bin/python -m uvicorn dashboard.server:app --host 127.0.0.1 --port "${PORT}"
