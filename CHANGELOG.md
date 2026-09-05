# Changelog

## [0.3.0] — 2026-09-05

Self-managing multi-exit proxy router.

- **New:** `proxy-manager.ts` — TypeScript/Bun proxy orchestrator that routes SearXNG engine traffic through multiple VPN exits and Tor
- **New:** `./setup.sh proxy` subcommand (start, stop, probe, status, watch)
- **New:** Per-engine proxy routing via SearXNG `outgoing.networks`
- **New:** Health matrix probing — tests every engine through every exit, picks optimal routes
- **New:** Verification-driven re-routing with historical fallback from saved health data
- **New:** Tunnel health monitoring — auto-restarts dead wireproxy instances individually
- **New:** Watch mode — continuous 5-minute monitoring cycle (tunnel → engine → re-route)
- **New:** Auto-enables disabled-by-default engines (bing, qwant, startpage, yahoo, etc.)
- Update `.gitignore` to exclude `vpn-configs/` and `.runtime/` (contain private keys)
- Update `settings.yml` template comments

## [Unreleased]

### Changed

- Update README with proxy routing documentation

## [0.2.0] — 2026-09-04

Red team hardening, new commands, and test-driven fixes.

- **Security:** bind to `127.0.0.1` by default instead of `0.0.0.0` (configurable via `SEARXNG_BIND`)
- **Security:** replace alpine sidecar with `podman cp` for settings seeding (removes unpinned alpine dependency)
- **Security:** stop suppressing `podman machine start` stderr so failures are diagnosable
- Add `update` command: pulls latest image, recreates container if newer, preserves settings
- Add `logs` command: show container logs (pass podman logs flags through)
- Add `reset` command: interactive destructive removal of container and volume
- Add port validation: `SEARXNG_PORT` must be numeric 1-65535
- Fix settings preservation: check volume for existing settings before seeding
- Fix `status` command: use `podman port` and per-field inspect calls
- Replace `exit 0` with `return 0` inside functions (safe to source)
- Add `warn()` helper

## [0.1.0] — 2026-09-04

Initial release.

- Podman-based SearXNG setup with persistent volume
- Cross-platform support: macOS and GNU/Linux
- Auto-generated secret key on first run
- Setup script with start, stop, teardown, and status commands
- Template `settings.yml` with sensible defaults
- Documentation for auto-start via launchd (macOS) and systemd (Linux)
