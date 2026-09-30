# Changelog

## [0.12.0] - 2026-09-30

- **New:** Tunnels run on UDP 53 by default. Networks that restrict UDP almost always leave DNS open, so tunnels on 53 keep working if such a filter switches on mid-session. Proton accepts WireGuard on 53 with the same configs
- **New:** UDP detection per network: before tunnels start (at startup, on a network change, or when every VPN tunnel is down), one throwaway tunnel tries each port in the ladder 53, 51820, 443, 4500, 1224, 88, 500, and all tunnels use the first that handshakes. Tunnels are stopped first so the probe never shares a live tunnel's key. Also checks whether port 53 is intercepted, by querying an address that runs no DNS server
- **New:** `.runtime/network-events.jsonl` records each network join, detection and loss of all VPN tunnels (interface, MAC, gateway, local IP, per-port results, DNS interception, chosen port, minutes on the network), to diagnose filtering networks from facts
- **New:** Dashboard and `status` show the network class (open, dns-only, restricted, blocked), the tunnel port and when it was checked
- **New:** When a tunnel check fails because Apple's container runtime has stopped, the manager starts it and SearXNG again, but only when `container system status` says it is down
- **Fix:** `bun test` runs without flags: `bunfig.toml` preloads the test environment (the AI panel test failed without `SEARXNG_AI_PROVIDER` set)
- **Known:** Surviving a UDP filter that switches on mid-session is designed for but not yet verified against a live filtering network

## [0.11.0] - 2026-09-30

- **New:** AI overview panel on results pages - a short answer above the results, grounded only in the results on the page, with `[n]` citations linking to them and a follow-up box. Results render immediately; the panel fills in when the answer arrives
- **New:** Two providers, chosen with `SEARXNG_AI_PROVIDER` (`off` by default): `codex` runs OpenAI's Codex CLI on its ChatGPT sign-in; `ollama` uses a local Ollama model (`SEARXNG_OLLAMA_MODEL`). Switchable per query in the panel
- **Security:** Codex runs with shell, browser, computer use, apps and plugins disabled, without user config, in an empty read-only sandbox; model output is rendered as text and only `[n]` citations become links; the overview endpoint refuses cross-origin requests
- **New:** The panel shows who pays for each answer: a green "ChatGPT subscription" badge for a ChatGPT sign-in, amber "OpenAI API key · billed per use" for an API key, red when Codex is signed out, and the local model name for Ollama. Read from `codex login status`, never from Codex's token file
- **New:** `searxng-start.sh` reads machine-local settings from a gitignored `local.env`
- **Fix:** Tunnels that get no handshake at all (e.g. a network blocking UDP) are retried every cycle instead of backing off, since they open no VPN session; they recover within one cycle once UDP is allowed again
- **Fix:** The blocked-search message no longer says "no VPN tunnel" while Tor is up

## [0.10.0] - 2026-09-25

Tunnel health is now measured on the path search actually uses. Before this release the dashboard could show healthy routing while SearXNG had never sent a request through a tunnel.

- **Changed:** Tunnels and engines are probed inside the SearXNG container with SearXNG's own HTTP client (`searx.network.client`), through the exact proxy URL written into `settings.yml`. One function builds that URL for both. The host-side `curl` probe is gone
- **Changed:** A tunnel counts as up only when a request through it returns an exit IP. An exit IP equal to this machine's own IP is flagged `bypass` and never used. TCP-connect liveness is gone
- **New:** Tunnels that carry no data are restarted, including frozen processes whose port still accepts connections. Restarts back off (monitor cycles 1, 2, 4, 8, then every 12, about an hour) because every restart opens a new session on the VPN account
- **New:** Fail closed - with no usable tunnel, SearXNG is routed to a blackhole proxy and `:8080` returns 503 with the reason, instead of searching from your own IP. A proxy-less seed config is replaced with blackhole routes before tunnels start
- **New:** Settings are read back from the container after every apply; only a byte-identical read-back counts as applied. Apply failures show on the dashboard instead of being logged and ignored
- **New:** Each tunnel logs to `.runtime/logs/wp-<name>.log` (rotated at 1 MB). Previously wireproxy stderr went to a pipe that was abandoned after the handshake, losing its logs and risking a blocked tunnel once the pipe filled
- **New:** Dashboard shows each tunnel's status, exit IP, country and check age; the activity log shows the file the running manager writes (`SEARXNG_PROXY_LOG`, set by both launchers)
- **Removed:** Search-query verification as a health signal (it also tripped the SearXNG rate limiter)
- **Fix:** Routing settings never reached the container under Apple `container` - `container copy` exits 0 but writes beneath the `/etc/searxng` volume mount, so SearXNG ran on its default (JSON disabled, no proxies). Settings are streamed in via `container exec -i`; same fix in `setup.sh` seeding
- **Fix:** Under Apple `container`, tunnels bind to the vmnet gateway (host-only bridge, read from `container network list`) instead of loopback, which the container cannot reach; `host.containers.internal` is Podman-only. Podman behaviour unchanged
- **Fix:** Monitor loop could park indefinitely after macOS sleep/wake. It now sleeps against the wall clock, a watchdog exits non-zero after 60 minutes without a tick, and the LaunchAgent restarts it (`KeepAlive.SuccessfulExit=false`); reinstall with `./setup.sh install-agent`
- **Fix:** Tunnel configs and logs are written `0600` (configs hold private keys); only this project's wireproxy processes are killed on stop
- **New:** Under Apple `container`, the manager relays the vmnet gateway's port 9050 to Tor on loopback, so SearXNG can use Tor without any `torrc` change
- **Note:** Proton VPN plans cap simultaneous connections per account (10 on the plan tested). Every file in `vpn-configs/` holds one open connection, alongside your other devices; configs past the cap handshake but carry no data

## [0.9.1] - 2026-09-11

- **Fix:** Replace all blocking `execSync` calls with async `execAsync` and `checkPort` helpers so the HTTP server stays responsive during probe cycles
- **Fix:** `applySettings` failures (e.g. `container copy` timeout) no longer crash the process - caught and logged, proxy routing continues
- **Fix:** `getSecretKey` reads local `.runtime/settings-live.yml` first, falls back to `container exec` with 10s timeout
- **Perf:** Tunnel and port checks now run in parallel via `Promise.all`

## [0.9.0] - 2026-09-11

- **New:** macOS LaunchAgent support - `./setup.sh install-agent` generates and installs a LaunchAgent so SearXNG starts automatically on login; `./setup.sh uninstall-agent` to remove
- **New:** `searxng-start.sh` launcher script for LaunchAgent use
- **Fix:** LaunchAgent now uses Apple `container` CLI (was incorrectly hardcoded to Podman)

## [0.8.5] - 2026-09-07

- **Fix:** Monitor loop no longer stalls on SearXNG rate limiter - liveness check uses `/config` instead of `/search` (which triggered 403 indefinitely, preventing all probe updates)
- **New:** Forced full probe every 30 minutes regardless of liveness check result, so the health matrix can never go stale

## [0.8.4] - 2026-09-06

- **Fix:** False-positive CAPTCHA detection on GMX - tighten pattern matching from bare keywords (`recaptcha`, `hcaptcha`, `captcha`) to specific integration markers (`g-recaptcha`, `recaptcha/api`, `hcaptcha.com`) so that template CSS/JS containing those words no longer triggers a false block
- Document Bing Cloudflare Turnstile blocking in README (affects all VPN/Tor exits, no workaround)

## [0.8.3] - 2026-09-06

- **Fix:** `stop` now kills orphaned proxy-manager processes not tracked by the pidfile (previously `restart` left the old process running)
- **Fix:** Crowdview probe URL corrected from `www.crowdview.ai` to `crowdview.ai` (the `www` subdomain has no DNS record, causing 100% timeout on every exit)
- Improve 403 verification-skip message to explain SearXNG rate limiter is the cause
- Add screenshots to README (search interface and proxy status dashboard)

## [0.8.2] - 2026-09-06

- Add `restart` command to setup.sh (stop + start in one step)
- Remove `watch` references from README proxy section

## [0.8.1] - 2026-09-06

CLI simplification, dead code removal, 403 rate-limit fix.

- **Breaking:** `watch` subcommand removed - `start` now does everything (server, tunnels, probes, monitoring)
- **Fix:** 403 from SearXNG rate limiter no longer triggers cascading re-probes that kill tunnels
- **Fix:** Verification step handles non-JSON responses (403/HTML) without crashing
- Server starts immediately on `start` - dashboard available in seconds, probes run behind it
- Engine Issues table paginated (10 per page, pager only when >10) matching tunnel table
- Fixed-height table containers (20rem) prevent layout shift when fewer than 10 rows
- Remove dead `probeExit`/`settingsForProbe` (~50 lines) - Tor circuit rotation now uses `directProbeEngine`
- Remove `sleep` utility - use `Bun.sleep` directly
- Remove unused `_secretKey` param from `fullProbe`
- Collapse triplicated IPv6 filter to single array check
- Extract `getTunnelStatus()` and `loadHealthMatrix()` helpers - deduplicates statusJson/statusPage
- ~103 lines removed total

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
