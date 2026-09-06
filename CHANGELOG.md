# Changelog

## [0.8.0] - 2026-09-06

Hot-add VPN configs, stable port assignment, tunnel pagination.

- **New:** Stable port assignment - config name hashed to a deterministic port, so adding or removing configs no longer shifts other tunnels' ports
- **New:** Hot-add/remove VPN configs - watch cycle re-scans `vpn-configs/` each cycle; new configs start automatically, removed configs are cleaned up
- **New:** Incremental proxy sync - only starts/stops tunnels that changed, instead of killing all and restarting
- **New:** Tunnel pagination - tunnels table paginated at 10 per page with first/prev/next/last navigation
- Tunnels sorted by country name then by config number
- Dashboard tunnel count shown in section header

## [0.7.4] - 2026-09-06

- Stagger engine probes per exit (500ms between each) to prevent tunnel saturation during parallel probing
- Follow redirects in engine probes (fixes false timeouts on Google consent redirects through EU VPN exits)
- Increase probe timeout from 12s to 15s
- Update README

## [0.7.3] - 2026-09-06

- Fix false CAPTCHA detection on Brave Search (i18n strings containing "captcha" triggered a false positive on valid results pages)
- Tighten CAPTCHA detection to look for actual challenge indicators (reCAPTCHA, hCaptcha, Turnstile, "unusual traffic") rather than the bare word

## [0.7.2] - 2026-09-06

- Show version number on dashboard
- Active engine count on dashboard queries SearXNG `/config` for the real total (was only counting the 13 probed engines)
- Dashboard engine table now shows only engines with issues; "All engines routing OK" when healthy

## [0.7.1] - 2026-09-06

- Dashboard engine table now shows only engines with issues (blocked/error/timeout/unknown); "All engines routing OK" when everything is healthy

## [0.7.0] - 2026-09-06

- **New:** Reprobe button on the dashboard - blocked/error/timeout engines get a one-click reprobe that tests all exits and re-routes if an alternative is found
- **New:** `/api/reprobe?engine=<name>` POST endpoint for programmatic single-engine reprobing
- Increase server idle timeout to 255s (prevents reprobe timeouts on slow exits)
- Use GNU/Linux consistently in README (was bare "Linux" in places)
- Fix unused variable warning in setup.sh (shellcheck clean)

## [0.6.0] - 2026-09-06

Dual-runtime support: Apple container (macOS) + Podman (GNU/Linux).

- **New:** Apple container runtime - native lightweight-VM containers on macOS (Tahoe), no Podman VM needed
- **New:** Auto-detect runtime - uses Apple container on macOS, Podman on Linux
- **New:** Runtime-agnostic helper layer - all container operations route through `rt_*` functions
- Proxy manager detects runtime and uses the correct exec/cp/restart commands
- Rename project to SearXNG-Local
- Rewrite README for dual-runtime setup

## [0.5.1] - 2026-09-05

- Update README to document parallel probing, instant startup, country labels, and JSON API endpoints

## [0.5.0] - 2026-09-05

Parallel probing, country labels, instant startup.

- **New:** Parallel exit probing - all exits probed concurrently via direct curl (was sequential through SearXNG)
- **New:** Country column in tunnel dashboard and JSON API (ISO 3166-1 alpha-2 → full name)
- Reverse proxy starts immediately on launch; probing runs in background
- Startup time reduced from ~3 minutes to ~15 seconds for the probe phase

## [0.4.0] - 2026-09-05

Reverse proxy architecture, status dashboard, and Tor circuit rotation.

- **New:** Reverse proxy - Bun server on :8080 as front door, SearXNG internal on :8082
- **New:** Status dashboard at `/stats` - engine routing, tunnel health, health matrix, activity log
- **New:** JSON API endpoints `/api/status` and `/api/log`
- **New:** Tor circuit rotation via control port - rotates circuits when qwant is CAPTCHAd
- **New:** CAPTCHA-aware re-routing in the verification pass
- SearXNG `/stats` replaced by our dashboard (more comprehensive, same info plus routing)
- Dashboard auto-refreshes every 120s, log panel polls every 10s

## [0.3.0] - 2026-09-05

Self-managing multi-exit proxy router.

- **New:** `proxy-manager.ts` - TypeScript/Bun proxy orchestrator that routes SearXNG engine traffic through multiple VPN exits and Tor
- **New:** `./setup.sh proxy` subcommand (start, stop, probe, status, watch)
- **New:** Per-engine proxy routing via SearXNG `outgoing.networks`
- **New:** Health matrix probing - tests every engine through every exit, picks optimal routes
- **New:** Verification-driven re-routing with historical fallback from saved health data
- **New:** Tunnel health monitoring - auto-restarts dead wireproxy instances individually
- **New:** Watch mode - continuous 5-minute monitoring cycle (tunnel → engine → re-route)
- **New:** Auto-enables disabled-by-default engines (bing, qwant, startpage, yahoo, etc.)
- **New:** Auto-start proxy watch on container startup when `vpn-configs/` has configs
- `stop`, `teardown`, and `reset` now stop the proxy watch and wireproxy tunnels
- Update `.gitignore` to exclude `vpn-configs/` and `.runtime/` (contain private keys)
- Update `settings.yml` template comments
- Update README with proxy routing documentation

## [0.2.0] - 2026-09-04

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

## [0.1.0] - 2026-09-04

Initial release.

- Podman-based SearXNG setup with persistent volume
- Cross-platform support: macOS and GNU/Linux
- Auto-generated secret key on first run
- Setup script with start, stop, teardown, and status commands
- Template `settings.yml` with sensible defaults
- Documentation for auto-start via launchd (macOS) and systemd (Linux)
