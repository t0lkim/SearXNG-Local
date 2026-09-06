# SearXNG-Local
I use this daily so I update it when I find bugs or add features. My current browser of choice for this is [Zen Browser](https://zen-browser.app/).

---

Run [SearXNG](https://searxng.org) locally using Apple's native [container](https://github.com/apple/container) runtime (macOS) or [Podman](https://podman.io) (GNU/Linux), with a self-managing proxy router across multiple VPN exits and Tor.

SearXNG is a privacy-respecting metasearch engine that aggregates results from 70+ search engines without tracking you. Many engines block requests from known VPN and Tor IP ranges. The bundled proxy manager automatically routes each engine through whichever exit isn't blocking it, monitors for changes, and re-routes on the fly.

## Prerequisites

### macOS (Apple Silicon)

[Apple container](https://github.com/apple/container) - native lightweight-VM container runtime, requires macOS 26 (Tahoe):

```bash
brew install container
brew services start container
container system kernel set --recommended
```

### GNU/Linux

[Podman](https://podman.io/docs/installation):

```bash
# Debian/Ubuntu
sudo apt install podman

# Fedora/RHEL/CentOS
sudo dnf install podman
```

## Quick start

```bash
git clone https://github.com/t0lkim/SearXNG-Local.git
cd SearXNG-Local
chmod +x setup.sh
./setup.sh
```

SearXNG is now running at [http://localhost:8080](http://localhost:8080).

The setup script auto-detects your container runtime (Apple container on macOS, Podman on GNU/Linux).

## Proxy routing

The proxy manager routes each search engine through the best available exit (VPN or Tor), avoiding IP-based blocking. It requires:

- [Bun](https://bun.sh) runtime
- [wireproxy](https://github.com/pufferffish/wireproxy) (`go install github.com/pufferffish/wireproxy/cmd/wireproxy@latest`)
- [Tor](https://www.torproject.org/) running locally (`brew install tor && brew services start tor`)
- One or more WireGuard `.conf` files (e.g. from ProtonVPN) dropped into `vpn-configs/`

When `vpn-configs/` contains `.conf` files, `./setup.sh` automatically starts the proxy watch in the background alongside the container. `./setup.sh stop` stops both. Log output goes to `.runtime/proxy-watch.log`.

For manual control:

```bash
./setup.sh proxy start   # Start tunnels, probe engines, apply optimal routes
./setup.sh proxy watch   # Continuous monitoring (foreground, re-probes every 5 min)
./setup.sh proxy status  # Show current health matrix
./setup.sh proxy probe   # Run a one-off health probe
./setup.sh proxy stop    # Stop VPN tunnels
```

### How it works

1. Spawns a wireproxy SOCKS5 instance for each `.conf` file in `vpn-configs/`
2. Probes every enabled engine through every exit concurrently (all exits in parallel, ~15 seconds total)
3. Picks the exit that serves the most engines as the default
4. Routes engines that are blocked on the default to an exit where they work
5. Applies a verification search and re-routes any engine that still fails
6. In watch mode, checks tunnel health and engine availability every 5 minutes

The reverse proxy starts immediately - search is available while the first probe cycle runs in the background. The health matrix is saved to `.runtime/health-matrix.json` and used as a historical fallback when a current probe shows no alternative for a blocked engine.

## Usage

```bash
./setup.sh               # Create and start (or start if already created)
./setup.sh stop          # Stop the container
./setup.sh update        # Pull latest image and recreate (preserves settings)
./setup.sh logs          # Show container logs
./setup.sh status        # Show container status
./setup.sh proxy [cmd]   # Manage VPN/Tor proxy routing (see above)
./setup.sh teardown      # Remove container (preserves settings volume)
./setup.sh reset         # Remove container AND settings (destructive)
./setup.sh help          # Show all commands
```

### Status dashboard

When proxy routing is active, visit [http://localhost:8080/stats](http://localhost:8080/stats) for a live dashboard showing engine routing, tunnel health (with country labels), and the full health matrix. JSON endpoints are available at `/api/status` and `/api/log`.

### Custom bind address

```bash
SEARXNG_BIND=0.0.0.0 ./setup.sh   # Expose to the network (default: 127.0.0.1)
```

## What it does

The setup script:

1. Detects your container runtime (Apple container on macOS, Podman on GNU/Linux)
2. Creates a named volume (`searxng-data`) for persistent configuration
3. Generates a unique `secret_key` and writes `settings.yml` into the volume
4. Pulls the official SearXNG image and starts the container

On subsequent runs it starts the existing container - no duplicate containers, no lost settings.

## Configuration

Settings persist in the `searxng-data` volume. To edit:

```bash
# View current settings (macOS)
container exec searxng cat /etc/searxng/settings.yml

# View current settings (GNU/Linux)
podman exec searxng cat /etc/searxng/settings.yml
```

The bundled `settings.yml` uses SearXNG defaults with `image_proxy` enabled. See the [SearXNG settings documentation](https://docs.searxng.org/admin/settings/) for all options.

## Auto-start (optional)

### macOS (launchd)

With Apple container, the system service runs via `brew services start container`. The SearXNG container itself can be managed by a launchd agent.

Create `~/Library/LaunchAgents/local.searxng.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>local.searxng</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>/path/to/SearXNG-Local/setup.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/searxng.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/searxng.log</string>
</dict>
</plist>
```

Then load it:

```bash
launchctl load ~/Library/LaunchAgents/local.searxng.plist
```

### GNU/Linux (systemd user unit)

Create `~/.config/systemd/user/searxng.service`:

```ini
[Unit]
Description=SearXNG local search
After=default.target

[Service]
Type=oneshot
ExecStart=/path/to/SearXNG-Local/setup.sh
RemainAfterExit=yes
ExecStop=/path/to/SearXNG-Local/setup.sh stop

[Install]
WantedBy=default.target
```

Then enable it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now searxng.service
```

## Updating

```bash
./setup.sh update
```

Pulls the latest SearXNG image. If it's newer than what's running, the container is recreated with the new image. Settings are preserved in the volume.

## Uninstall

```bash
./setup.sh reset                       # Remove container + settings (interactive)
container image delete searxng/searxng # macOS: remove image
# or
podman rmi docker.io/searxng/searxng   # GNU/Linux: remove image
```

Or to keep your settings for later:

```bash
./setup.sh teardown                    # Remove container only
```

## Licence

[MIT](LICENSE)
