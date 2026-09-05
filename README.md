# searxng-local

Run [SearXNG](https://searxng.org) locally in a Podman container with self-managing proxy routing across multiple VPN exits and Tor.

SearXNG is a privacy-respecting metasearch engine that aggregates results from 70+ search engines without tracking you. Many engines block requests from known VPN and Tor IP ranges. The bundled proxy manager automatically routes each engine through whichever exit isn't blocking it, monitors for changes, and re-routes on the fly.

## Prerequisites

- [Podman](https://podman.io/docs/installation) installed and running

### macOS

```bash
brew install podman
podman machine init
podman machine start
```

### GNU/Linux (Debian/Ubuntu)

```bash
sudo apt install podman
```

### GNU/Linux (Fedora/RHEL)

```bash
sudo dnf install podman
```

## Quick start

```bash
git clone https://github.com/t0lkim/searxng-local.git
cd searxng-local
chmod +x setup.sh
./setup.sh
```

SearXNG is now running at [http://localhost:8080](http://localhost:8080).

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
2. Probes every enabled engine through every exit (Tor + all VPNs)
3. Picks the exit that serves the most engines as the default
4. Routes engines that are blocked on the default to an exit where they work
5. Applies a verification search and re-routes any engine that still fails
6. In watch mode, checks tunnel health and engine availability every 5 minutes

The health matrix is saved to `.runtime/health-matrix.json` and used as a historical fallback when a current probe shows no alternative for a blocked engine.

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

When proxy routing is active, visit [http://localhost:8080/stats](http://localhost:8080/stats) for a live dashboard showing engine routing, tunnel health, and the health matrix.

### Custom bind address

```bash
SEARXNG_BIND=0.0.0.0 ./setup.sh   # Expose to the network (default: 127.0.0.1)
```

## What it does

The setup script:

1. Checks that Podman is installed and running (starts the Podman VM on macOS if needed)
2. Creates a named volume (`searxng-data`) for persistent configuration
3. Generates a unique `secret_key` and writes `settings.yml` into the volume
4. Pulls the official SearXNG image and starts the container

On subsequent runs it starts the existing container — no duplicate containers, no lost settings.

## Configuration

Settings persist in the `searxng-data` Podman volume. To edit:

```bash
# View current settings
podman exec searxng cat /etc/searxng/settings.yml

# Edit in-place
podman exec -it searxng vi /etc/searxng/settings.yml

# Or copy out, edit, copy back
podman cp searxng:/etc/searxng/settings.yml ./my-settings.yml
# ... edit my-settings.yml ...
podman cp ./my-settings.yml searxng:/etc/searxng/settings.yml
podman restart searxng
```

The bundled `settings.yml` uses SearXNG defaults with `image_proxy` enabled. See the [SearXNG settings documentation](https://docs.searxng.org/admin/settings/) for all options.

## Auto-start (optional)

The container is created with `--restart always`, so it starts automatically when the Podman runtime is running. To start Podman itself at login/boot:

### macOS (launchd)

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
    <string>/path/to/searxng-local/setup.sh</string>
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

The script waits for the Podman machine before starting the container.

### GNU/Linux (systemd user unit)

Create `~/.config/systemd/user/searxng.service`:

```ini
[Unit]
Description=SearXNG local search
After=default.target

[Service]
Type=oneshot
ExecStart=/path/to/searxng-local/setup.sh
RemainAfterExit=yes
ExecStop=/path/to/searxng-local/setup.sh stop

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
./setup.sh reset                     # Remove container + settings (interactive)
podman rmi docker.io/searxng/searxng # Remove image
```

Or to keep your settings for later:

```bash
./setup.sh teardown                  # Remove container only
```

## Licence

[MIT](LICENSE)
