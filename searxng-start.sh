#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${HOME}/Library/Logs/searxng-local"
LOG="${LOG_DIR}/searxng.log"
mkdir -p "$LOG_DIR"

exec >> "$LOG" 2>&1
echo "$(date '+%Y-%m-%d %H:%M:%S') searxng-start: begin"

export PATH="/opt/homebrew/bin:${PATH}"

cd "$SCRIPT_DIR"
./setup.sh setup

echo "$(date '+%Y-%m-%d %H:%M:%S') searxng-start: done"
