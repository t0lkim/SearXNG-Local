#!/usr/bin/env bash
set -euo pipefail

# searxng-local setup
# Creates a local SearXNG instance using Apple's container CLI (macOS)
# or Podman (GNU/Linux), with persistent configuration.

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

# --- Runtime detection ---

RUNTIME=""

detect_runtime() {
  if [[ "$(uname)" == "Darwin" ]] && command -v container >/dev/null 2>&1; then
    RUNTIME="container"
  elif command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
  else
    if [[ "$(uname)" == "Darwin" ]]; then
      error "No container runtime found. Install one:
  Apple container: brew install container
  Podman:          brew install podman"
    else
      error "podman not found. Install it:
  Debian/Ubuntu: sudo apt install podman
  Fedora/RHEL:   sudo dnf install podman"
    fi
  fi
}

ensure_runtime_running() {
  case "$RUNTIME" in
    container)
      if ! container list >/dev/null 2>&1; then
        info "Starting container system service..."
        brew services start container 2>/dev/null \
          || container system start \
          || error "Failed to start container service. Run: brew services start container"
      fi
      ;;
    podman)
      if [[ "$(uname)" == "Darwin" ]]; then
        if ! podman machine info --format '{{.Host.MachineState}}' 2>/dev/null | grep -qi running; then
          info "Starting Podman machine..."
          podman machine start || error "Failed to start Podman machine. Run: podman machine init && podman machine start"
        fi
      fi
      ;;
  esac
}

# --- Runtime-agnostic helpers ---

rt_container_exists() {
  case "$RUNTIME" in
    container) container list -a -q 2>/dev/null | grep -qx "$CONTAINER_NAME" ;;
    podman)    podman container exists "$CONTAINER_NAME" 2>/dev/null ;;
  esac
}

rt_container_state() {
  case "$RUNTIME" in
    container)
      container inspect "$CONTAINER_NAME" 2>/dev/null \
        | sed -n 's/.*"state" *: *"\([^"]*\)".*/\1/p' | head -1
      ;;
    podman)
      podman container inspect --format '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown"
      ;;
  esac
}

rt_start() {
  case "$RUNTIME" in
    container) container start "$CONTAINER_NAME" ;;
    podman)    podman start "$CONTAINER_NAME" ;;
  esac
}

rt_stop() {
  case "$RUNTIME" in
    container) container stop "$CONTAINER_NAME" ;;
    podman)    podman stop "$CONTAINER_NAME" ;;
  esac
}

rt_delete() {
  case "$RUNTIME" in
    container) container delete -f "$CONTAINER_NAME" ;;
    podman)    podman rm "$CONTAINER_NAME" ;;
  esac
}

rt_volume_create() {
  case "$RUNTIME" in
    container) container volume create "$VOLUME_NAME" 2>/dev/null || true ;;
    podman)    podman volume create "$VOLUME_NAME" 2>/dev/null || true ;;
  esac
}

rt_volume_exists() {
  case "$RUNTIME" in
    container) container volume list --format json 2>/dev/null | grep -q "\"$VOLUME_NAME\"" ;;
    podman)    podman volume exists "$VOLUME_NAME" 2>/dev/null ;;
  esac
}

rt_volume_delete() {
  case "$RUNTIME" in
    container) container volume delete "$VOLUME_NAME" ;;
    podman)    podman volume rm "$VOLUME_NAME" ;;
  esac
}

rt_pull() {
  case "$RUNTIME" in
    container) container image pull "$IMAGE" ;;
    podman)    podman pull "$IMAGE" ;;
  esac
}

rt_image_id() {
  case "$RUNTIME" in
    container)
      container image list --format json 2>/dev/null \
        | sed -n 's/.*"digest" *: *"\([^"]*\)".*searxng.*/\1/p' | head -1
      ;;
    podman)
      podman image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null
      ;;
  esac
}

rt_current_image_id() {
  case "$RUNTIME" in
    container)
      container inspect "$CONTAINER_NAME" 2>/dev/null \
        | sed -n 's/.*"digest" *: *"\([^"]*\)".*/\1/p' | head -1
      ;;
    podman)
      podman container inspect --format '{{.Image}}' "$CONTAINER_NAME" 2>/dev/null
      ;;
  esac
}

rt_create_seed() {
  case "$RUNTIME" in
    container)
      # Apple container cp requires a running container, so run with sleep
      container run -d --name searxng-seed -v "${VOLUME_NAME}:/etc/searxng" "$IMAGE" sleep 120 2>/dev/null | tail -1
      ;;
    podman)
      podman create --name searxng-seed -v "${VOLUME_NAME}:/etc/searxng" "$IMAGE" true
      ;;
  esac
}

rt_cp() {
  case "$RUNTIME" in
    container) container copy "$1" "$2" ;;
    podman)    podman cp "$1" "$2" ;;
  esac
}

rt_delete_seed() {
  case "$RUNTIME" in
    container)
      container stop searxng-seed 2>/dev/null || true
      container delete searxng-seed 2>/dev/null || true
      ;;
    podman)
      podman rm searxng-seed >/dev/null
      ;;
  esac
}

rt_run() {
  case "$RUNTIME" in
    container)
      container run -d \
        --name "$CONTAINER_NAME" \
        -p "${BIND}:${INTERNAL_PORT}:8080" \
        -v "${VOLUME_NAME}:/etc/searxng" \
        -e "SEARXNG_BASE_URL=${BASE_URL}" \
        "$IMAGE"
      ;;
    podman)
      podman run -d \
        --name "$CONTAINER_NAME" \
        --restart always \
        -p "${BIND}:${INTERNAL_PORT}:8080" \
        -v "${VOLUME_NAME}:/etc/searxng" \
        -e "SEARXNG_BASE_URL=${BASE_URL}" \
        "$IMAGE"
      ;;
  esac
}

rt_exec() {
  case "$RUNTIME" in
    container) container exec "$@" ;;
    podman)    podman exec "$@" ;;
  esac
}

rt_logs() {
  case "$RUNTIME" in
    container) container logs "$@" "$CONTAINER_NAME" ;;
    podman)    podman logs "$@" "$CONTAINER_NAME" ;;
  esac
}

# --- Core functions ---

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
  detect_runtime
  ensure_runtime_running

  info "Using runtime: ${RUNTIME}"

  if rt_container_exists; then
    local state
    state="$(rt_container_state)"
    if [[ "$state" == "running" ]]; then
      info "SearXNG is already running at ${BASE_URL}"
      start_proxy_watch
      return 0
    fi
    info "Starting existing container..."
    rt_start
    info "SearXNG running at ${BASE_URL}"
    start_proxy_watch
    return 0
  fi

  info "Creating volume ${VOLUME_NAME}..."
  rt_volume_create

  info "Pulling ${IMAGE}..."
  rt_pull

  # Seed settings into the volume via a temporary container.
  rt_create_seed >/dev/null

  local tmpdir
  tmpdir="$(mktemp -d)"
  if rt_cp "searxng-seed:/etc/searxng/settings.yml" "${tmpdir}/existing.yml" 2>/dev/null; then
    info "Using existing settings from volume."
  else
    create_settings "${tmpdir}/settings.yml"
    rt_cp "${tmpdir}/settings.yml" "searxng-seed:/etc/searxng/settings.yml"
  fi
  rm -rf "$tmpdir"

  rt_delete_seed

  info "Starting SearXNG..."
  rt_run

  info "SearXNG running at ${BASE_URL}"
  start_proxy_watch
}

stop() {
  detect_runtime
  stop_proxy_watch
  if rt_container_exists; then
    info "Stopping SearXNG..."
    rt_stop
    info "Stopped."
  else
    info "No SearXNG container found."
  fi
}

restart() {
  stop
  setup
}

teardown() {
  detect_runtime
  stop_proxy_watch
  stop 2>/dev/null || true
  if rt_container_exists; then
    info "Removing container..."
    rt_delete
  fi
  info "Volume ${VOLUME_NAME} preserved (contains your settings)."
  info "To remove everything: ${RUNTIME} volume $([ "$RUNTIME" = "container" ] && echo "delete" || echo "rm") ${VOLUME_NAME}"
}

status() {
  detect_runtime
  if rt_container_exists; then
    local state
    state="$(rt_container_state)"
    echo "Runtime: ${RUNTIME}"
    echo "Name:    ${CONTAINER_NAME}"
    echo "Image:   ${IMAGE}"
    echo "Status:  ${state}"
    if [[ "$RUNTIME" == "container" ]]; then
      echo "Port:    ${BIND}:${INTERNAL_PORT} -> 8080"
    else
      echo "Port:    $(podman port "$CONTAINER_NAME" 2>/dev/null | head -1 || echo "none")"
    fi
  else
    info "No SearXNG container found."
  fi
}

update() {
  detect_runtime
  if ! rt_container_exists; then
    error "No SearXNG container found. Run './setup.sh' first."
  fi

  info "Pulling latest ${IMAGE}..."
  local old_id
  old_id="$(rt_current_image_id)"
  rt_pull
  local new_id
  new_id="$(rt_image_id)"

  if [[ "$old_id" == "$new_id" ]]; then
    info "Already running the latest image."
    return 0
  fi

  info "New image available. Recreating container..."
  rt_stop 2>/dev/null || true
  rt_delete

  rt_run

  info "SearXNG updated and running at ${BASE_URL}"
}

logs() {
  detect_runtime
  if rt_container_exists; then
    if [[ "$RUNTIME" == "container" ]]; then
      rt_logs "${@:--n 50}"
    else
      rt_logs "${@:---tail=50}"
    fi
  else
    error "No SearXNG container found."
  fi
}

reset() {
  detect_runtime
  warn "This will destroy the container AND all settings."
  printf "Continue? [y/N] "
  read -r confirm
  if [[ "$confirm" != [yY] ]]; then
    info "Aborted."
    return 0
  fi

  stop 2>/dev/null || true
  if rt_container_exists; then
    rt_delete
  fi
  if rt_volume_exists; then
    rt_volume_delete
  fi
  info "Removed container and volume. Run './setup.sh' to start fresh."
}

has_vpn_configs() {
  compgen -G "${SCRIPT_DIR}/vpn-configs/*.conf" >/dev/null 2>&1
}

PROXY_PID_FILE="${SCRIPT_DIR}/.runtime/proxy.pid"

start_proxy_watch() {
  if ! has_vpn_configs; then return; fi
  if ! command -v bun >/dev/null 2>&1; then
    warn "bun not found - skipping proxy routing. Install: brew install oven-sh/bun/bun"
    return
  fi

  stop_proxy_watch 2>/dev/null

  local logfile="${SCRIPT_DIR}/.runtime/proxy-watch.log"
  mkdir -p "${SCRIPT_DIR}/.runtime"
  info "Starting proxy watch (log: .runtime/proxy-watch.log)..."
  nohup bun "${SCRIPT_DIR}/proxy-manager.ts" start >> "$logfile" 2>&1 &
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
  restart   Stop and start everything
  update    Pull latest image and recreate container (preserves settings)
  logs      Show container logs (pass log flags after)
  status    Show container status
  teardown  Remove the container (preserves settings volume)
  reset     Remove container AND settings volume (destructive)
  proxy     Manage VPN proxy routing (start|stop|probe|status)
  help      Show this message

Runtime:
  macOS uses Apple's container CLI (brew install container).
  GNU/Linux uses Podman (apt/dnf install podman).

Environment:
  SEARXNG_INTERNAL_PORT  Internal SearXNG port (default: 8082)
  SEARXNG_BIND           Address to bind (default: 127.0.0.1)

Proxy routing:
  Drop WireGuard .conf files into vpn-configs/ then run:
    ./setup.sh proxy start   - start server, tunnels, probe, monitor
    ./setup.sh proxy status  - show health matrix
    ./setup.sh proxy stop    - stop everything
EOF
}

case "${1:-setup}" in
  setup)    setup ;;
  start)    setup ;;
  stop)     stop ;;
  restart)  restart ;;
  update)   update ;;
  logs)     shift; logs "$@" ;;
  teardown) teardown ;;
  reset)    reset ;;
  status)   status ;;
  proxy)    shift; proxy "$@" ;;
  help|-h|--help) usage ;;
  *) error "Unknown command: $1. Run '$(basename "$0") help' for usage." ;;
esac
