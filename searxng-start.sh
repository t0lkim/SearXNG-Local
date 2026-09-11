#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${HOME}/Library/Logs/searxng-local"
mkdir -p "$LOG_DIR"

exec >> "${LOG_DIR}/searxng.log" 2>&1
echo "$(date '+%Y-%m-%d %H:%M:%S') searxng-start: begin"

export PATH="/opt/homebrew/bin:${PATH}"
export SEARXNG_SKIP_PROXY_WATCH=1

cd "$SCRIPT_DIR"
./setup.sh setup

echo "$(date '+%Y-%m-%d %H:%M:%S') searxng-start: container ready, exec into proxy-manager"
exec bun "$SCRIPT_DIR/proxy-manager.ts" start
