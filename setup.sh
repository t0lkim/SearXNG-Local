#!/usr/bin/env bash
set -euo pipefail

# searxng-local setup
# Creates a local SearXNG instance using Podman with persistent configuration.

CONTAINER_NAME="searxng"
VOLUME_NAME="searxng-data"
IMAGE="docker.io/searxng/searxng:latest"
INTERNAL_PORT="${SEARXNG_INTERNAL_PORT:-8082}"
BIND="${SEARXNG_BIND:-127.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="http://localhost:8080/"

info() {
  printf '\033[1;34m==>\033[0m %s\n' "$*"
}

warn() {
  printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2
}

error() {
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

validate_port() {
  [[ "$INTERNAL_PORT" =~ ^[0-9]+$ ]] || error "SEARXNG_INTERNAL_PORT must be a number, got: '${INTERNAL_PORT}'"
  if (( INTERNAL_PORT < 1 || INTERNAL_PORT > 65535 )); then
    error "SEARXNG_INTERNAL_PORT must be between 1 and 65535, got: ${INTERNAL_PORT}"
  fi
}

check_podman() {
  command -v podman >/dev/null 2>&1 || error "podman not found. Install it first:
  macOS:   brew install podman && podman machine init && podman machine start
  Linux:   https://podman.io/docs/installation"
}

check_podman_running() {
  if [[ "$(uname)" == "Darwin" ]]; then
    if ! podman machine info --format '{{.Host.MachineState}}' 2>/dev/null | grep -qi running; then
      info "Starting Podman machine..."
      podman machine start || error "Failed to start Podman machine. Run: podman machine init && podman machine start"
    fi
  fi
}

generate_secret_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
  else
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

create_settings() {
  local settings_file="$1"
  local secret_key
  secret_key="$(generate_secret_key)"

  if [[ -f "$settings_file" ]]; then
    info "Using existing settings: $settings_file"
    return
  fi

  if [[ -f "${SCRIPT_DIR}/settings.yml" ]]; then
    cp "${SCRIPT_DIR}/settings.yml" "$settings_file"
    sed -i.bak "s/secret_key: \".*\"/secret_key: \"${secret_key}\"/" "$settings_file"
    rm -f "${settings_file}.bak"
  else
    cat > "$settings_file" <<EOF
use_default_settings: true

server:
  secret_key: "${secret_key}"
  image_proxy: true
EOF
  fi

  info "Generated settings with unique secret key"
}

setup() {
  validate_port
  check_podman
  check_podman_running

  if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    local state
    state="$(podman container inspect --format '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")"
    if [[ "$state" == "running" ]]; then
      info "SearXNG is already running at ${BASE_URL}"
      start_proxy_watch
      return 0
    fi
    info "Starting existing container..."
    podman start "$CONTAINER_NAME"
    info "SearXNG running at ${BASE_URL}"
    start_proxy_watch
    return 0
  fi

  info "Creating volume ${VOLUME_NAME}..."
  podman volume create "$VOLUME_NAME" 2>/dev/null || true

  info "Pulling ${IMAGE}..."
  podman pull "$IMAGE"

  # Seed settings into the volume via a temporary container.
  # Works on both macOS (volume inside VM) and Linux.
  local seed_cid
  seed_cid="$(podman create --name searxng-seed -v "${VOLUME_NAME}:/etc/searxng" "$IMAGE" true)"

  # Only write settings if the volume doesn't already have them.
  local tmpdir
  tmpdir="$(mktemp -d)"
  if podman cp "${seed_cid}:/etc/searxng/settings.yml" "${tmpdir}/existing.yml" 2>/dev/null; then
    info "Using existing settings from volume."
  else
    create_settings "${tmpdir}/settings.yml"
    podman cp "${tmpdir}/settings.yml" "${seed_cid}:/etc/searxng/settings.yml"
  fi
  rm -rf "$tmpdir"

  podman rm "$seed_cid" >/dev/null

  info "Starting SearXNG..."
  podman run -d \
    --name "$CONTAINER_NAME" \
    --restart always \
    -p "${BIND}:${INTERNAL_PORT}:8080" \
    -v "${VOLUME_NAME}:/etc/searxng" \
    -e "SEARXNG_BASE_URL=${BASE_URL}" \
    "$IMAGE"

  info "SearXNG running at ${BASE_URL}"
  start_proxy_watch
}

stop() {
  stop_proxy_watch
  if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    info "Stopping SearXNG..."
    podman stop "$CONTAINER_NAME"
    info "Stopped."
  else
    info "No SearXNG container found."
  fi
}

teardown() {
  stop_proxy_watch
  stop 2>/dev/null || true
  if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    info "Removing container..."
    podman rm "$CONTAINER_NAME"
  fi
  info "Volume ${VOLUME_NAME} preserved (contains your settings)."
  info "To remove everything: podman volume rm ${VOLUME_NAME}"
}

status() {
  if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    echo "Name:    $(podman container inspect --format '{{.Name}}' "$CONTAINER_NAME")"
    echo "Image:   $(podman container inspect --format '{{.ImageName}}' "$CONTAINER_NAME")"
    echo "Status:  $(podman container inspect --format '{{.State.Status}}' "$CONTAINER_NAME")"
    echo "Started: $(podman container inspect --format '{{.State.StartedAt}}' "$CONTAINER_NAME")"
    echo "Port:    $(podman port "$CONTAINER_NAME" 2>/dev/null | head -1 || echo "none")"
  else
    info "No SearXNG container found."
  fi
}

update() {
  if ! podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    error "No SearXNG container found. Run './setup.sh' first."
  fi

  info "Pulling latest ${IMAGE}..."
  local old_id
  old_id="$(podman container inspect --format '{{.Image}}' "$CONTAINER_NAME" 2>/dev/null)"
  podman pull "$IMAGE"
  local new_id
  new_id="$(podman image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null)"

  if [[ "$old_id" == "$new_id" ]]; then
    info "Already running the latest image."
    return 0
  fi

  info "New image available. Recreating container..."
  podman stop "$CONTAINER_NAME" 2>/dev/null || true
  podman rm "$CONTAINER_NAME"

  podman run -d \
    --name "$CONTAINER_NAME" \
    --restart always \
    -p "${BIND}:${INTERNAL_PORT}:8080" \
    -v "${VOLUME_NAME}:/etc/searxng" \
    -e "SEARXNG_BASE_URL=${BASE_URL}" \
    "$IMAGE"

  info "SearXNG updated and running at ${BASE_URL}"
}

logs() {
  if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    podman logs "${@:---tail=50}" "$CONTAINER_NAME"
  else
    error "No SearXNG container found."
  fi
}

reset() {
  warn "This will destroy the container AND all settings."
  printf "Continue? [y/N] "
  read -r confirm
  if [[ "$confirm" != [yY] ]]; then
    info "Aborted."
    return 0
  fi

  stop 2>/dev/null || true
  if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
    podman rm "$CONTAINER_NAME"
  fi
  if podman volume exists "$VOLUME_NAME" 2>/dev/null; then
    podman volume rm "$VOLUME_NAME"
  fi
  info "Removed container and volume. Run './setup.sh' to start fresh."
}

has_vpn_configs() {
  compgen -G "${SCRIPT_DIR}/vpn-configs/*.conf" >/dev/null 2>&1
}

PROXY_PID_FILE="${SCRIPT_DIR}/.runtime/proxy-watch.pid"

start_proxy_watch() {
  if ! has_vpn_configs; then return; fi
  if ! command -v bun >/dev/null 2>&1; then
    warn "bun not found — skipping proxy routing. Install: brew install oven-sh/bun/bun"
    return
  fi

  stop_proxy_watch 2>/dev/null

  local logfile="${SCRIPT_DIR}/.runtime/proxy-watch.log"
  mkdir -p "${SCRIPT_DIR}/.runtime"
  info "Starting proxy watch (log: .runtime/proxy-watch.log)..."
  nohup bun "${SCRIPT_DIR}/proxy-manager.ts" watch >> "$logfile" 2>&1 &
  echo $! > "$PROXY_PID_FILE"
}

stop_proxy_watch() {
  if [[ -f "$PROXY_PID_FILE" ]]; then
    local pid
    pid="$(cat "$PROXY_PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null || true
      info "Proxy watch stopped."
    fi
    rm -f "$PROXY_PID_FILE"
  fi
}

proxy() {
  local subcmd="${1:-start}"
  if ! command -v bun >/dev/null 2>&1; then
    error "bun not found. Install it: brew install oven-sh/bun/bun"
  fi
  exec bun "${SCRIPT_DIR}/proxy-manager.ts" "$subcmd"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [command]

Commands:
  setup     Create and start SearXNG (default)
  start     Start an existing container
  stop      Stop the container
  update    Pull latest image and recreate container (preserves settings)
  logs      Show container logs (pass podman logs flags after)
  status    Show container status
  teardown  Remove the container (preserves settings volume)
  reset     Remove container AND settings volume (destructive)
  proxy     Manage VPN proxy routing (start|stop|probe|status|watch)
  help      Show this message

Environment:
  SEARXNG_INTERNAL_PORT  Internal SearXNG port (default: 8082)
  SEARXNG_BIND           Address to bind (default: 127.0.0.1)

Proxy routing:
  Drop WireGuard .conf files into vpn-configs/ then run:
    ./setup.sh proxy start   — start tunnels, probe engines, apply routes
    ./setup.sh proxy watch   — continuous monitoring (foreground)
    ./setup.sh proxy status  — show health matrix
    ./setup.sh proxy stop    — stop VPN tunnels
EOF
}

case "${1:-setup}" in
  setup)    setup ;;
  start)    setup ;;
  stop)     stop ;;
  update)   update ;;
  logs)     shift; logs "$@" ;;
  teardown) teardown ;;
  reset)    reset ;;
  status)   status ;;
  proxy)    shift; proxy "$@" ;;
  help|-h|--help) usage ;;
  *) error "Unknown command: $1. Run '$(basename "$0") help' for usage." ;;
esac
