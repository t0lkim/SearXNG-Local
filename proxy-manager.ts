#!/usr/bin/env bun

import { readdir, readFile, writeFile, mkdir, unlink, stat, rename, chmod } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { createServer, connect } from "node:net";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { aiEnabled, handleAiStatus, handleOverview, injectPanel, setAiRuntimeDir } from "./ai-overview.ts";
import { PORT_LADDER, currentNetwork, detectPorts, networkKey, recordEvidence, withEndpointPort, type Detection, type NetInfo } from "./udp-network.ts";

const VERSION = "0.12.0";

const ROOT = import.meta.dir;
const VPN_DIR = join(ROOT, "vpn-configs");
const RUNTIME_DIR = join(ROOT, ".runtime");
const TUNNEL_LOG_DIR = join(RUNTIME_DIR, "logs");
const HEALTH_FILE = join(RUNTIME_DIR, "health-matrix.json");
// One JSON line per network join, detection and loss of all VPN tunnels: the facts for diagnosing a filtering network
const EVIDENCE_FILE = join(RUNTIME_DIR, "network-events.jsonl");
const REDETECT_MIN_INTERVAL = 600_000;
// The file this manager's own output goes to; launchers set it so the dashboard shows the live log
const LOG_FILE = process.env.SEARXNG_PROXY_LOG || join(RUNTIME_DIR, "proxy-watch.log");
setAiRuntimeDir(RUNTIME_DIR);
const SEARXNG_INTERNAL_PORT = 8082;
const SEARXNG_URL = `http://localhost:${SEARXNG_INTERNAL_PORT}`;
const CONTAINER_NAME = "searxng";
const CONTAINER_SETTINGS = "/etc/searxng/settings.yml";
const SEARXNG_HOME = "/usr/local/searxng";
const SEARXNG_PYTHON = `${SEARXNG_HOME}/.venv/bin/python3`;
const TOR_PORT = 9050;
const WP_BASE_PORT = 10801;
const WP_BIN = join(process.env.HOME!, "go", "bin", "wireproxy");
const TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace";
// IPv4 literal: tunnels are IPv4-only, so the host IP they are compared with must be IPv4 too
const HOST_TRACE_URL = "https://1.1.1.1/cdn-cgi/trace";
// Matches SearXNG's own request_timeout: a tunnel slower than this would fail real searches too
const TRACE_TIMEOUT = 10;
const ENGINE_TIMEOUT = 15;
const HANDSHAKE_TIMEOUT = 10_000;
const READY_TIMEOUT = 30_000;
const MONITOR_INTERVAL = 300_000;
const FORCED_PROBE_INTERVAL = 1_800_000;
const PROXY_PORT = 8080;
const TOR_CONTROL_PORT = 9051;
const TOR_CONTROL_PASS = "searxng-local";
const TOR_RETRY_MAX = 5;
// A tunnel that keeps carrying no data is restarted after 1, 2, 4, 8 then every 12 monitor cycles (5 min each):
// every restart is a new session on the VPN account, so a dead tunnel must not reconnect every cycle
const RESTART_BACKOFF_MAX_CYCLES = 12;
const TUNNEL_LOG_MAX = 1_000_000;
// Nothing listens here inside the container: used when no tunnel carries data, so search fails instead of going direct
const BLACKHOLE_PROXY = "socks5h://127.0.0.1:9";
// Monitor loop must tick at least this often (wall clock) or the process exits for launchd to restart it
const WATCHDOG_STALL_LIMIT = 3_600_000;
const SLEEP_SLICE = 10_000;

// ─── Process helpers (argv only, never a shell) ─────────────

interface RunResult { code: number; stdout: string; stderr: string }

async function run(argv: string[], opts: { stdin?: string; timeout?: number } = {}): Promise<RunResult> {
  const proc = Bun.spawn(argv, {
    stdin: opts.stdin !== undefined ? new Blob([opts.stdin]) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const out = new Response(proc.stdout).text();
  const err = new Response(proc.stderr).text();
  const result = await Promise.race([
    proc.exited,
    Bun.sleep(opts.timeout ?? 30_000).then(() => "timeout" as const),
  ]);
  if (result === "timeout") {
    proc.kill(9);
    throw new Error(`timed out after ${opts.timeout ?? 30_000}ms: ${argv.slice(0, 3).join(" ")}`);
  }
  return { code: result, stdout: (await out).trim(), stderr: (await err).trim() };
}

async function runOk(argv: string[], opts: { stdin?: string; timeout?: number } = {}): Promise<string> {
  const r = await run(argv, opts);
  if (r.code !== 0) throw new Error(`${argv.slice(0, 3).join(" ")} exited ${r.code}: ${r.stderr.slice(0, 200)}`);
  return r.stdout;
}

// ─── Runtime and addressing ─────────────────────────────────

function detectRuntime(): "container" | "podman" {
  const forced = process.env.SEARXNG_RUNTIME;
  if (forced === "container" || forced === "podman") return forced;
  if (process.platform === "darwin" && Bun.which("container")) return "container";
  if (Bun.which("podman")) return "podman";
  throw new Error("No container runtime found (container or podman)");
}

const CONTAINER_RUNTIME = detectRuntime();

// Apple container reaches the host only via its vmnet gateway (host-only bridge, not the LAN);
// Podman resolves host.containers.internal and forwards to host loopback
function vmnetGateway(): string {
  const r = Bun.spawnSync(["container", "network", "list", "--format", "json"]);
  const nets = JSON.parse(r.stdout.toString() || "[]");
  const gw = nets.find((n: { id: string }) => n.id === "default")?.status?.ipv4Gateway;
  if (!gw) throw new Error("container network \"default\" has no ipv4Gateway - is the container service running?");
  return gw;
}
const TUNNEL_HOST = process.env.SEARXNG_TUNNEL_HOST
  || (CONTAINER_RUNTIME === "container" ? vmnetGateway() : "127.0.0.1");
const CONTAINER_HOST = CONTAINER_RUNTIME === "container" ? TUNNEL_HOST : "host.containers.internal";

// The one place a proxy URL is built: SearXNG's settings and the probe both use it, so what is measured is what search uses
function proxyUrl(exit: Exit): string {
  return `socks5h://${CONTAINER_HOST}:${exit.port}`;
}

const COUNTRY_NAMES: Record<string, string> = {
  AT: "Austria", AU: "Australia", BE: "Belgium", BG: "Bulgaria", BR: "Brazil",
  CA: "Canada", CH: "Switzerland", CZ: "Czech Republic", DE: "Germany", DK: "Denmark",
  EE: "Estonia", ES: "Spain", FI: "Finland", FR: "France", GB: "United Kingdom",
  GR: "Greece", HK: "Hong Kong", HR: "Croatia", HU: "Hungary", ID: "Indonesia",
  IE: "Ireland", IL: "Israel", IN: "India", IS: "Iceland", IT: "Italy",
  JP: "Japan", KR: "South Korea", LT: "Lithuania", LU: "Luxembourg",
  LV: "Latvia", MY: "Malaysia", MX: "Mexico", NL: "Netherlands", NO: "Norway",
  NZ: "New Zealand", PH: "Philippines", PL: "Poland", PT: "Portugal",
  RO: "Romania", RS: "Serbia", SE: "Sweden", SG: "Singapore", SK: "Slovakia",
  TH: "Thailand", TR: "Turkey", TW: "Taiwan", UA: "Ukraine", US: "United States",
  VN: "Vietnam", ZA: "South Africa",
};

// Engines disabled by default in SearXNG that we want enabled
const ENABLE_ENGINES = [
  "bing", "boardreader", "crowdview", "gmx", "mojeek", "mwmbl",
  "privacywall", "qwant", "vuhuv", "wiby", "yahoo", "yep",
];

const ENGINE_URLS: [string, string][] = [
  ["bing", "https://www.bing.com/search?q=test"],
  ["brave", "https://search.brave.com/search?q=test"],
  ["crowdview", "https://crowdview.ai/?q=test"],
  ["duckduckgo", "https://html.duckduckgo.com/html/?q=test"],
  ["gmx", "https://search.gmx.net/web?q=test"],
  ["google", "https://www.google.com/search?q=test"],
  ["mojeek", "https://www.mojeek.com/search?q=test"],
  ["mwmbl", "https://mwmbl.org/?q=test"],
  ["qwant", "https://www.qwant.com/?q=test"],
  ["startpage", "https://www.startpage.com/sp/search?query=test"],
  ["wiby", "https://wiby.me/?q=test"],
  ["yahoo", "https://search.yahoo.com/search?p=test"],
  ["yep", "https://yep.com/web?q=test"],
];

// ─── Types and state ────────────────────────────────────────

interface Exit {
  name: string;
  type: "tor" | "vpn";
  port: number;
  configFile?: string;
  country?: string;
}

interface EngineResult {
  engine: string;
  status: "ok" | "blocked" | "captcha" | "timeout" | "error";
  detail?: string;
}

interface ExitProbe {
  exit: string;
  engines: EngineResult[];
}

// up: carried data on SearXNG's path with an exit IP that is not the host's
// down: no data; bypass: exit IP equals the host's own IP; unverified: host IP unknown, so bypass cannot be ruled out
type TunnelStatus = "up" | "down" | "bypass" | "unverified";

interface TunnelState {
  status: TunnelStatus;
  checkedAt: string;
  exitIp?: string;
  loc?: string;
  detail?: string;
}

interface ApplyResult {
  at: string;
  ok: boolean;
  detail: string;
}

interface NetworkState {
  key: string;
  joinedAt: string;
  tunnelPort: number;
  detection: Detection | null;
}

interface HealthMatrix {
  network?: NetworkState;
  timestamp: string;
  probes: ExitProbe[];
  assignments: Record<string, string>;
  tunnels: Record<string, TunnelState>;
  apply: ApplyResult | null;
}

type Subprocess = ReturnType<typeof Bun.spawn>;
const processes = new Map<string, Subprocess>();

function emptyMatrix(): HealthMatrix {
  return { timestamp: "", probes: [], assignments: {}, tunnels: {}, apply: null };
}

async function loadHealthMatrix(): Promise<HealthMatrix | null> {
  try {
    const m = JSON.parse(await readFile(HEALTH_FILE, "utf-8"));
    return { ...emptyMatrix(), ...m, tunnels: m.tunnels ?? {}, apply: m.apply ?? null };
  } catch { return null; }
}

let state: HealthMatrix = emptyMatrix();
// Search through :8080 is served only once routes are applied, read back and backed by at least one up tunnel
let routingReady = false;
// True once this process has completed its first routing cycle; reprobe is refused before that
let firstRouteDone = false;

// Serialises tunnel checks, routing cycles and reprobes: each can restart the container under the others
let lockTail: Promise<void> = Promise.resolve();
let lockHeld = false;
async function exclusive<T>(fn: () => Promise<T>): Promise<T> {
  const prev = lockTail;
  let release!: () => void;
  lockTail = new Promise<void>(r => { release = r; });
  await prev;
  lockHeld = true;
  try { return await fn(); } finally { lockHeld = false; release(); }
}

async function saveState(): Promise<void> {
  await writeFile(HEALTH_FILE, JSON.stringify(state, null, 2));
}

function isUp(name: string): boolean {
  return state.tunnels[name]?.status === "up";
}

function log(msg: string): void {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

// ─── In-container probe ─────────────────────────────────────
// Runs inside the SearXNG container with SearXNG's own HTTP client (searx.network.client, curl_cffi
// with browser impersonation), through the same proxy URL written into settings.yml.

const PROBE_PY = String.raw`
import asyncio, json, sys
from searx.network.client import new_client

CAPTCHA = ("g-recaptcha", "recaptcha/api", "hcaptcha.com", "cf-turnstile",
           "please verify you are a human", "unusual traffic")

def client(proxy):
    return new_client(enable_http=False, verify=True, enable_http2=True, enable_http3=False,
                      max_connections=10, proxies={"all://": proxy}, local_address=None, max_redirects=5)

async def trace(c, url, timeout):
    try:
        r = await c.request("GET", url, timeout=timeout)
    except Exception as e:
        return {"ok": False, "detail": (type(e).__name__ + ": " + str(e))[:200]}
    kv = dict(l.split("=", 1) for l in r.text.splitlines() if "=" in l)
    if r.status_code == 200 and kv.get("ip"):
        return {"ok": True, "ip": kv["ip"], "loc": kv.get("loc")}
    return {"ok": False, "detail": "HTTP %d" % r.status_code}

async def engine(c, name, url, timeout):
    try:
        r = await c.request("GET", url, timeout=timeout)
    except Exception as e:
        return {"engine": name, "status": "timeout", "detail": type(e).__name__}
    code = r.status_code
    if code in (403, 429, 503):
        return {"engine": name, "status": "blocked", "detail": "HTTP %d" % code}
    if 200 <= code < 400:
        body = r.text.lower()
        if any(m in body for m in CAPTCHA):
            return {"engine": name, "status": "captcha", "detail": "CAPTCHA detected"}
        return {"engine": name, "status": "ok"}
    return {"engine": name, "status": "error", "detail": "HTTP %d" % code}

async def one(t, job):
    c = client(t["proxy"])
    try:
        res = {"name": t["name"], "trace": await trace(c, job["trace_url"], job["trace_timeout"])}
        if job["engines"] and res["trace"]["ok"]:
            out = []
            for i, (name, url) in enumerate(job["engines"]):
                if i:
                    await asyncio.sleep(0.5)
                out.append(await engine(c, name, url, job["engine_timeout"]))
            res["engines"] = out
        return res
    finally:
        await c.aclose()

async def main():
    job = json.load(sys.stdin)
    work = asyncio.gather(*(one(t, job) for t in job["tunnels"]))
    print(json.dumps(await asyncio.wait_for(work, job["deadline"])))

asyncio.run(main())
`;

interface ProbeOutput {
  name: string;
  trace: { ok: boolean; ip?: string; loc?: string; detail?: string };
  engines?: EngineResult[];
}

async function containerProbe(exits: Exit[], engines: [string, string][]): Promise<ProbeOutput[]> {
  if (exits.length === 0) return [];
  const job = {
    tunnels: exits.map(e => ({ name: e.name, proxy: proxyUrl(e) })),
    engines,
    trace_url: TRACE_URL,
    trace_timeout: TRACE_TIMEOUT,
    engine_timeout: ENGINE_TIMEOUT,
  };
  const budget = 60_000 + engines.length * (ENGINE_TIMEOUT + 1) * 1000;
  // Python gives up 15s before the host does, so it never outlives the exec client
  Object.assign(job, { deadline: (budget - 15_000) / 1000 });
  const out = await runOk(
    [CONTAINER_RUNTIME, "exec", "-i", "-w", SEARXNG_HOME, CONTAINER_NAME, SEARXNG_PYTHON, "-c", PROBE_PY],
    { stdin: JSON.stringify(job), timeout: budget },
  );
  return JSON.parse(out.split("\n").pop()!);
}

// The host's own public IP, fetched directly: a tunnel exiting with this address is not a tunnel.
// A failed lookup falls back to the last known value (up to 24h old) rather than blackholing search.
let lastHostIp: { ip: string; at: number } | null = null;
async function hostPublicIp(): Promise<string | null> {
  try {
    const res = await fetch(HOST_TRACE_URL, { signal: AbortSignal.timeout(8000) });
    const ip = (await res.text()).match(/^ip=(.+)$/m)?.[1];
    if (ip) lastHostIp = { ip, at: Date.now() };
  } catch { /* fall back below */ }
  if (lastHostIp && Date.now() - lastHostIp.at < 86_400_000) return lastHostIp.ip;
  return null;
}

function classifyTunnel(trace: ProbeOutput["trace"], hostIp: string | null): TunnelState {
  const checkedAt = new Date().toISOString();
  if (!trace.ok || !trace.ip) return { status: "down", checkedAt, detail: trace.detail ?? "no data" };
  const base = { checkedAt, exitIp: trace.ip, loc: trace.loc };
  if (!hostIp) return { ...base, status: "unverified", detail: "host IP unknown - cannot rule out bypass" };
  if (trace.ip === hostIp) return { ...base, status: "bypass", detail: "exit IP is this machine's own IP" };
  return { ...base, status: "up" };
}

// ─── Tor relay ──────────────────────────────────────────────
// Under Apple container the SearXNG VM cannot reach the Mac's loopback, where Tor listens. Relay the
// vmnet gateway's port 9050 (host-only, not the LAN) to Tor, so torrc stays untouched. pipe() carries backpressure.

function startTorRelay(): void {
  if (TUNNEL_HOST === "127.0.0.1") return;
  const server = createServer(client => {
    const upstream = connect(TOR_PORT, "127.0.0.1");
    client.pipe(upstream);
    upstream.pipe(client);
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
    client.on("close", () => upstream.destroy());
    upstream.on("close", () => client.destroy());
  });
  server.on("error", (e: Error) => log(`✗ Tor relay on ${TUNNEL_HOST}:${TOR_PORT} failed: ${e.message}`));
  server.listen(TOR_PORT, TUNNEL_HOST, () => console.log(`Tor relay: ${TUNNEL_HOST}:${TOR_PORT} → 127.0.0.1:${TOR_PORT}`));
}

// ─── Tor circuit rotation ──────────────────────────────────

async function rotateTorCircuit(): Promise<boolean> {
  try {
    const socket = await Bun.connect({
      hostname: "127.0.0.1",
      port: TOR_CONTROL_PORT,
      socket: {
        data(_, data) { socket.data += data.toString(); },
        open(socket) { socket.data = ""; },
        error() {},
        close() {},
      },
    });
    // Small delay for the banner
    await Bun.sleep(200);

    socket.write(`AUTHENTICATE "${TOR_CONTROL_PASS}"\r\n`);
    await Bun.sleep(200);

    socket.write("SIGNAL NEWNYM\r\n");
    await Bun.sleep(200);

    const response = socket.data as string;
    socket.end();

    return response.includes("250 OK");
  } catch {
    return false;
  }
}

// For an engine that works on no exit and hits a CAPTCHA on Tor, try fresh Tor circuits
async function rotateTorForEngine(tor: Exit, engine: string): Promise<EngineResult | null> {
  const url = ENGINE_URLS.find(([e]) => e === engine)?.[1];
  if (!url) return null;
  for (let attempt = 1; attempt <= TOR_RETRY_MAX; attempt++) {
    console.log(`  Tor circuit rotation for ${engine}, attempt ${attempt}/${TOR_RETRY_MAX}...`);
    if (!await rotateTorCircuit()) {
      console.log("    ✗ circuit rotation failed (control port)");
      return null;
    }
    await Bun.sleep(3000);
    const [res] = await containerProbe([tor], [[engine, url]]);
    const result = res?.engines?.[0];
    if (result?.status === "ok") {
      console.log(`    ✓ ${engine} works on new Tor circuit`);
      return result;
    }
    console.log(`    ✗ ${engine} still ${result?.status ?? "unreachable"}`);
  }
  return null;
}

// ─── WireGuard → wireproxy config ───────────────────────────

// UDP port every tunnel uses; set by detection, 53 until then (survives DNS-only filters)
let tunnelPort = PORT_LADDER[0];

function wgToWireproxyConfig(wgContent: string, socksPort: number): string {
  const lines: string[] = [];
  for (const raw of wgContent.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;

    const key = ["Address", "DNS", "AllowedIPs"].find(k => line.startsWith(k));
    if (key) {
      const v4 = line.split("=")[1].split(",").map(s => s.trim()).filter(s => !s.includes(":"));
      lines.push(`${key} = ${v4.join(", ")}`);
    } else {
      lines.push(line);
    }
  }
  lines.push("", "[Socks5]", `BindAddress = ${TUNNEL_HOST}:${socksPort}`, "");
  return withEndpointPort(lines.join("\n"), tunnelPort);
}

// ─── Exit discovery ─────────────────────────────────────────

function stablePort(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash + name.charCodeAt(i)) | 0;
  }
  return WP_BASE_PORT + (Math.abs(hash) % 1000);
}

async function discoverExits(): Promise<Exit[]> {
  const exits: Exit[] = [{ name: "tor", type: "tor", port: TOR_PORT }];

  let files: string[];
  try {
    files = await readdir(VPN_DIR);
  } catch {
    return exits;
  }

  const configs = files.filter(f => f.endsWith(".conf")).sort();
  const usedPorts = new Set<number>([TOR_PORT]);
  for (const file of configs) {
    const base = file.replace(/\.conf$/, "");
    const name = base.replace(/^wg-/, "").toLowerCase();
    const country = base.match(/^wg-([A-Z]{2})-/i)?.[1]?.toUpperCase();
    let port = stablePort(name);
    while (usedPorts.has(port)) port++;
    usedPorts.add(port);
    exits.push({
      name,
      type: "vpn",
      port,
      configFile: join(VPN_DIR, file),
      country,
    });
  }
  return exits;
}

// ─── Tunnel processes ───────────────────────────────────────

function killOrphanTunnels(): void {
  // Only wireproxy instances running our own runtime configs
  Bun.spawnSync(["pkill", "-9", "-f", join(RUNTIME_DIR, "wp-")]);
}

async function stopTunnel(name: string): Promise<void> {
  const proc = processes.get(name);
  processes.delete(name);
  if (!proc) return;
  // SIGKILL, because a frozen (stopped) process never acts on SIGTERM
  proc.kill(9);
  await Promise.race([proc.exited, Bun.sleep(3000)]);
}

// Log text written after a byte offset. The offset comes from stat().size (bytes), and wireproxy writes
// multi-byte "…" in peer lines, so slicing the decoded string would skip past new lines on every restart.
function textSince(buf: Buffer, byteOffset: number): string {
  return buf.subarray(byteOffset).toString("utf-8");
}

// Tunnel stderr goes to .runtime/logs/wp-<name>.log (append, rotated at 1 MB) - never an unread pipe
async function startTunnel(exit: Exit): Promise<boolean> {
  await stopTunnel(exit.name);
  const conf = join(RUNTIME_DIR, `wp-${exit.name}.conf`);
  const wg = await readFile(exit.configFile!, "utf-8");
  await writeFile(conf, wgToWireproxyConfig(wg, exit.port), { mode: 0o600 });
  await chmod(conf, 0o600); // holds the private key; mode above only applies to new files

  const logPath = join(TUNNEL_LOG_DIR, `wp-${exit.name}.log`);
  let offset = 0;
  try {
    const size = (await stat(logPath)).size;
    if (size > TUNNEL_LOG_MAX) await rename(logPath, `${logPath}.1`);
    else offset = size;
  } catch { /* no log yet */ }

  const fd = openSync(logPath, "a", 0o600);
  await chmod(logPath, 0o600);
  const proc = Bun.spawn([WP_BIN, "-c", conf], { stdout: "ignore", stderr: fd });
  closeSync(fd);

  const deadline = Date.now() + HANDSHAKE_TIMEOUT;
  while (Date.now() < deadline) {
    await Bun.sleep(250);
    if (proc.exitCode !== null) break;
    const text = textSince(await readFile(logPath), offset);
    if (text.includes("Received handshake response")) {
      processes.set(exit.name, proc);
      return true;
    }
  }
  proc.kill(9);
  return false;
}

async function startTunnels(exits: Exit[]): Promise<void> {
  const vpn = exits.filter(e => e.type === "vpn" && e.configFile);
  const results = await Promise.all(vpn.map(async exit => ({ exit, ok: await startTunnel(exit) })));
  for (const { exit, ok } of results) {
    console.log(ok ? `  ✓ ${exit.name} handshake (port ${exit.port})` : `  ✗ ${exit.name}: no handshake`);
  }
}

// Remove tunnels whose config was deleted; start tunnels for new configs
async function syncTunnels(exits: Exit[]): Promise<void> {
  const wanted = new Set(exits.filter(e => e.type === "vpn").map(e => e.name));
  for (const name of [...processes.keys()]) {
    if (wanted.has(name)) continue;
    console.log(`  removing ${name} (config deleted)`);
    await stopTunnel(name);
    delete state.tunnels[name];
    try { await unlink(join(RUNTIME_DIR, `wp-${name}.conf`)); } catch { /* fine */ }
  }
  await startTunnels(exits.filter(e => e.type === "vpn" && !processes.has(e.name)));
}

// .runtime/wp-*.conf are derived copies holding private keys: drop ones whose vpn-configs source is gone
async function sweepRuntimeConfigs(exits: Exit[]): Promise<void> {
  const wanted = new Set(exits.filter(e => e.type === "vpn").map(e => `wp-${e.name}.conf`));
  for (const file of await readdir(RUNTIME_DIR)) {
    if (!/^wp-.+\.conf$/.test(file)) continue;
    const path = join(RUNTIME_DIR, file);
    if (wanted.has(file)) await chmod(path, 0o600);
    else { await unlink(path); console.log(`  removed stale ${file} (no matching vpn-configs entry)`); }
  }
}

async function stopAllTunnels(): Promise<void> {
  for (const name of [...processes.keys()]) await stopTunnel(name);
  killOrphanTunnels();
}

// ─── Tunnel health (data path) ──────────────────────────────

// Measures every exit through SearXNG's own client; with restart, VPN tunnels that carry no data are
// restarted once and measured again. Tor is a system service and is only measured.
// Consecutive failed restarts per tunnel and how many cycles remain until the next one
const restartBackoff = new Map<string, { failures: number; wait: number }>();

function restartDue(name: string): boolean {
  const b = restartBackoff.get(name);
  if (!b) {
    restartBackoff.set(name, { failures: 1, wait: 1 });
    return true;
  }
  if (--b.wait > 0) return false;
  b.failures++;
  b.wait = Math.min(2 ** (b.failures - 1), RESTART_BACKOFF_MAX_CYCLES);
  return true;
}

async function checkTunnels(exits: Exit[], opts: { restart: boolean }): Promise<void> {
  const hostIp = await hostPublicIp();
  let results: ProbeOutput[];
  try {
    // A dead container runtime fails every probe; one recovery attempt, then the same probe again
    results = await containerProbe(exits, []).catch(async (e: unknown) => {
      if (!await recoverRuntime()) throw e;
      return containerProbe(exits, []);
    });
  } catch (e: unknown) {
    const detail = `probe failed: ${e instanceof Error ? e.message : e}`;
    log(`✗ tunnel check ${detail}`);
    for (const exit of exits) {
      state.tunnels[exit.name] = { status: "down", checkedAt: new Date().toISOString(), detail };
    }
    await saveState();
    return;
  }
  for (const r of results) state.tunnels[r.name] = classifyTunnel(r.trace, hostIp);

  for (const exit of exits) {
    if (state.tunnels[exit.name]?.status !== "down") restartBackoff.delete(exit.name);
  }
  // Drop state for exits whose config was removed, so no reader shows a tunnel that no longer exists
  const names = new Set(exits.map(e => e.name));
  for (const name of Object.keys(state.tunnels)) if (!names.has(name)) delete state.tunnels[name];

  if (opts.restart) {
    const dead = exits.filter(e => e.type === "vpn" && e.configFile && state.tunnels[e.name]?.status === "down"
      && restartDue(e.name));
    const waiting = exits.filter(e => e.type === "vpn" && state.tunnels[e.name]?.status === "down" && !dead.includes(e));
    for (const e of waiting) {
      const b = restartBackoff.get(e.name)!;
      console.log(`    ${e.name}: no data, next restart in ${b.wait} cycle(s)`);
    }
    if (dead.length > 0) {
      log(`restarting ${dead.length} tunnel(s) with no data: ${dead.map(e => e.name).join(", ")}`);
      const started = await Promise.all(dead.map(e => startTunnel(e)));
      // No handshake means no session was opened on the VPN account, so there is nothing to back off from:
      // retry next cycle, so tunnels recover promptly when the network allows WireGuard again
      dead.forEach((e, i) => { if (!started[i]) restartBackoff.delete(e.name); });
      const again = await containerProbe(dead, []).catch(() => [] as ProbeOutput[]);
      for (const r of again) state.tunnels[r.name] = classifyTunnel(r.trace, hostIp);
    }
  }
  await saveState();

  const counts: Record<string, number> = {};
  for (const exit of exits) {
    const s = state.tunnels[exit.name]?.status ?? "down";
    counts[s] = (counts[s] ?? 0) + 1;
  }
  log(`tunnels: ${Object.entries(counts).map(([s, n]) => `${n} ${s}`).join(", ")}`);
  for (const exit of exits) {
    const t = state.tunnels[exit.name];
    if (t && t.status !== "up") console.log(`    ${exit.name}: ${t.status}${t.detail ? ` (${t.detail})` : ""}`);
  }
}

// ─── Network detection ──────────────────────────────────────

let lastDetectAt = 0;
let anyVpnWasUp = false;

// Stops every tunnel, finds which UDP port reaches the VPN servers on this network, then starts them on it.
// Tunnels are stopped first so the probe never shares a live tunnel's key.
async function redetect(exits: Exit[], reason: string): Promise<void> {
  const vpn = exits.filter(e => e.type === "vpn" && e.configFile);
  if (vpn.length === 0) return;
  await stopAllTunnels();
  const info = await currentNetwork();
  log(`detecting UDP (${reason}) on ${info.iface ?? "?"} via ${vpn[0].name}...`);
  const wg = await readFile(vpn[0].configFile!, "utf-8");
  const d = await detectPorts(wgToWireproxyConfig(wg, 0), WP_BIN, RUNTIME_DIR);
  if (d.chosenPort !== null) tunnelPort = d.chosenPort;
  const key = networkKey(info);
  state.network = {
    key,
    joinedAt: state.network?.key === key ? state.network.joinedAt : new Date().toISOString(),
    tunnelPort,
    detection: d,
  };
  lastDetectAt = Date.now();
  const portList = PORT_LADDER.map(p => `${p}${d.ports[p] ? "✓" : "✗"}`).join(" ");
  log(`network ${d.netClass}: ${portList}; DNS intercepted: ${d.dnsIntercepted ?? "unknown"}; tunnels on UDP ${tunnelPort}`);
  await recordEvidence(EVIDENCE_FILE, "detect", info, { reason, ...d, tunnelPort });
  await saveState();
  await startTunnels(exits);
}

// Runs each cycle before the tunnel check: a new network (gateway or address) means a fresh detection
async function watchNetwork(exits: Exit[]): Promise<void> {
  const info = await currentNetwork();
  if (networkKey(info) === state.network?.key) return;
  log(`network changed: ${info.iface ?? "?"} gateway ${info.gateway ?? "?"}`);
  await recordEvidence(EVIDENCE_FILE, "network-changed", info, { previous: state.network?.key ?? null });
  await redetect(exits, "network changed");
}

// Runs each cycle after the tunnel check: losing every VPN tunnel is recorded, and triggers a fresh detection
async function watchVpnLoss(exits: Exit[]): Promise<void> {
  const vpn = exits.filter(e => e.type === "vpn");
  if (vpn.length === 0) return;
  const anyUp = vpn.some(e => isUp(e.name));
  if (!anyUp && anyVpnWasUp) {
    const joined = state.network ? new Date(state.network.joinedAt).getTime() : Date.now();
    await recordEvidence(EVIDENCE_FILE, "vpn-lost", await currentNetwork(), {
      tunnelPort, minutesOnNetwork: Math.round((Date.now() - joined) / 60_000),
    });
  }
  anyVpnWasUp = anyUp;
  if (!anyUp && Date.now() - lastDetectAt >= REDETECT_MIN_INTERVAL) {
    await redetect(exits, "all VPN tunnels down");
    await checkTunnels(exits, { restart: false });
    anyVpnWasUp = vpn.some(e => isUp(e.name));
  }
}

// ─── Container settings ─────────────────────────────────────

async function readContainerSettings(): Promise<string | null> {
  try {
    return await runOk([CONTAINER_RUNTIME, "exec", CONTAINER_NAME, "cat", CONTAINER_SETTINGS], { timeout: 15_000 });
  } catch { return null; }
}

async function getSecretKey(): Promise<string> {
  for (const source of [readContainerSettings(), readFile(join(RUNTIME_DIR, "settings-live.yml"), "utf-8").catch(() => null)]) {
    const match = (await source)?.match(/secret_key:\s*"([^"]+)"/);
    if (match) return match[1];
  }
  return randomBytes(16).toString("hex");
}

// `container system status` output, read literally: "running", "down" only when it says so, else "unknown"
type RuntimeStatus = "running" | "down" | "unknown";
function parseRuntimeStatus(code: number, out: string): RuntimeStatus {
  if (/not running|not registered|^status\s+stopped\b/im.test(out)) return "down";
  if (code === 0 && /^status\s+running\b/im.test(out)) return "running";
  return "unknown";
}

async function runtimeStatus(): Promise<{ status: RuntimeStatus; detail: string }> {
  try {
    const r = await run(["container", "system", "status"], { timeout: 15_000 });
    const out = `${r.stdout}\n${r.stderr}`.trim();
    return { status: parseRuntimeStatus(r.code, out), detail: out.split("\n")[0] ?? "" };
  } catch (e: unknown) {
    return { status: "unknown", detail: e instanceof Error ? e.message : String(e) };
  }
}

// After a container command fails: asks the runtime whether it is running, and starts it (then SearXNG)
// only when status says it is down. True means the runtime was down and is now back.
async function recoverRuntime(): Promise<boolean> {
  if (CONTAINER_RUNTIME !== "container") return false;
  const before = await runtimeStatus();
  if (before.status !== "down") {
    log(`container runtime ${before.status} (${before.detail}): not starting it, the failure is elsewhere`);
    return false;
  }
  log(`container runtime down (${before.detail}): starting it`);
  try {
    await runOk(["container", "system", "start"], { timeout: 120_000 });
  } catch (e: unknown) {
    log(`✗ container system start failed: ${e instanceof Error ? e.message : e}`);
    return false;
  }
  const after = await runtimeStatus();
  if (after.status !== "running") {
    log(`✗ container runtime still ${after.status} after start (${after.detail})`);
    return false;
  }
  await startContainer();
  const ready = await waitForReady();
  log(ready ? "✓ container runtime and SearXNG back" : "✗ runtime back but SearXNG did not become ready");
  return ready;
}

async function startContainer(): Promise<void> {
  await run([CONTAINER_RUNTIME, "start", CONTAINER_NAME], { timeout: 60_000 });
}

async function restartContainer(): Promise<void> {
  if (CONTAINER_RUNTIME === "container") {
    await runOk(["container", "stop", CONTAINER_NAME], { timeout: 60_000 });
    await runOk(["container", "start", CONTAINER_NAME], { timeout: 60_000 });
  } else {
    await runOk(["podman", "restart", CONTAINER_NAME], { timeout: 60_000 });
  }
}

async function waitForReady(timeout = READY_TIMEOUT): Promise<boolean> {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(SEARXNG_URL, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return true;
    } catch { /* not ready */ }
    await Bun.sleep(1000);
  }
  return false;
}

// Writes settings through exec stdin (Apple `container copy` exits 0 but writes beneath the volume mount),
// restarts SearXNG, then reads the file back: only a byte-identical read-back counts as applied.
// The last settings this process saw SearXNG restart on and read back
let confirmedYaml: string | null = null;

async function applySettings(yaml: string): Promise<ApplyResult> {
  const at = new Date().toISOString();
  await writeFile(join(RUNTIME_DIR, "settings-live.yml"), yaml, { mode: 0o600 });
  try {
    let current = await readContainerSettings();
    if (current === null) {
      // exec fails when the container is stopped (e.g. a failed restart): start it rather than wait for a human
      await startContainer();
      await waitForReady();
      current = await readContainerSettings();
    }
    if (current === yaml.trim() && confirmedYaml === yaml) {
      return { at, ok: true, detail: "unchanged" };
    }
    await runOk(
      [CONTAINER_RUNTIME, "exec", "-i", CONTAINER_NAME, "sh", "-c", `cat > ${CONTAINER_SETTINGS}`],
      { stdin: yaml, timeout: 30_000 },
    );
    await restartContainer();
    if (!await waitForReady()) return { at, ok: false, detail: "SearXNG did not come back after restart" };
    const back = await readContainerSettings();
    if (back !== yaml.trim()) return { at, ok: false, detail: "read-back mismatch: container is not running the generated settings" };
    confirmedYaml = yaml;
    return { at, ok: true, detail: "applied and read back" };
  } catch (e: unknown) {
    return { at, ok: false, detail: e instanceof Error ? e.message : String(e) };
  }
}

// ─── Settings generation ────────────────────────────────────

function settingsOptimal(
  secretKey: string,
  exits: Exit[],
  assignments: Record<string, string>,
  defaultExit: string | null,
): string {
  const byName = new Map(exits.map(e => [e.name, e]));
  const usedExits = new Set([...(defaultExit ? [defaultExit] : []), ...Object.values(assignments)]);

  let networks = "";
  for (const name of [...usedExits].sort()) {
    const exit = byName.get(name);
    if (!exit) continue;
    networks += `    ${exit.name}:\n`;
    networks += `      proxies:\n`;
    networks += `        "all://":\n`;
    networks += `          - "${proxyUrl(exit)}"\n`;
  }

  // Merge engine enablements with network assignments
  const routedMap = new Map(
    Object.entries(assignments).filter(([, e]) => e !== defaultExit && byName.has(e)),
  );
  const allEngineNames = new Set([...ENABLE_ENGINES, ...routedMap.keys()]);

  let engineSection = "\nengines:\n";
  for (const name of [...allEngineNames].sort()) {
    engineSection += `  - name: ${name}\n`;
    if (ENABLE_ENGINES.includes(name)) engineSection += `    disabled: false\n`;
    if (routedMap.has(name)) engineSection += `    network: ${routedMap.get(name)}\n`;
  }

  const defaultExitObj = defaultExit ? byName.get(defaultExit) : undefined;
  const defaultProxy = defaultExitObj ? proxyUrl(defaultExitObj) : BLACKHOLE_PROXY;

  return `use_default_settings:
  engines:
    remove:
      - radio browser   # its init() does direct DNS lookups outside outgoing.proxies

server:
  secret_key: "${secretKey}"
  image_proxy: true

search:
  formats:
    - html
    - json

outgoing:
${networks ? `  networks:\n${networks}` : ""}  proxies:
    "all://":
      - "${defaultProxy}"
  request_timeout: 10.0
  max_request_timeout: 15.0
  useragent_suffix: ""
${engineSection}`;
}

// ─── Route optimisation ─────────────────────────────────────

// Only probes of up tunnels are passed in; no probes means no default exit (fail closed)
function optimise(probes: ExitProbe[]): { assignments: Record<string, string>; defaultExit: string | null } {
  if (probes.length === 0) return { assignments: {}, defaultExit: null };

  const exitScores = new Map<string, number>();
  const engineExits = new Map<string, string[]>();

  for (const probe of probes) {
    let okCount = 0;
    for (const eng of probe.engines) {
      if (eng.status === "ok") {
        okCount++;
        if (!engineExits.has(eng.engine)) engineExits.set(eng.engine, []);
        engineExits.get(eng.engine)!.push(probe.exit);
      }
    }
    exitScores.set(probe.exit, okCount);
  }

  // Default exit = most working engines (the tunnel itself works even if every engine blocks it)
  let defaultExit = probes[0].exit;
  let maxScore = -1;
  for (const [exit, score] of exitScores) {
    if (score > maxScore) {
      maxScore = score;
      defaultExit = exit;
    }
  }

  // Route blocked engines to alternatives
  const assignments: Record<string, string> = {};
  for (const [engine, workingExits] of engineExits) {
    if (workingExits.includes(defaultExit)) continue;
    if (workingExits.length > 0) assignments[engine] = workingExits[0];
  }

  return { assignments, defaultExit };
}

// ─── Routing cycle ──────────────────────────────────────────

// Probes every engine through every up tunnel (in-container), picks routes, applies and reads them back
async function routeCycle(exits: Exit[], reason: string): Promise<void> {
  const up = exits.filter(e => isUp(e.name));
  log(`routing (${reason}): probing ${ENGINE_URLS.length} engines through ${up.length} up tunnel(s)...`);

  let probes: ExitProbe[] = [];
  try {
    const results = await containerProbe(up, ENGINE_URLS);
    for (const r of results) {
      if (!r.trace.ok) {
        // Died between the tunnel check and this probe
        state.tunnels[r.name] = classifyTunnel(r.trace, null);
        continue;
      }
      probes.push({ exit: r.name, engines: r.engines ?? [] });
      const ok = (r.engines ?? []).filter(e => e.status === "ok").length;
      console.log(`  probed ${r.name}: ${ok} ok, ${(r.engines?.length ?? 0) - ok} not ok`);
    }
  } catch (e: unknown) {
    log(`✗ engine probe failed: ${e instanceof Error ? e.message : e}`);
    probes = [];
  }

  // Engines no exit can serve, but which hit a CAPTCHA on Tor: try new Tor circuits
  const tor = up.find(e => e.type === "tor");
  const torProbe = probes.find(p => p.exit === "tor");
  if (tor && torProbe) {
    let rotations = 0;
    for (const [engine] of ENGINE_URLS) {
      if (rotations >= 2) break; // each rotation costs up to TOR_RETRY_MAX probes; keep a cycle well inside the watchdog
      const anyOk = probes.some(p => p.engines.some(e => e.engine === engine && e.status === "ok"));
      const idx = torProbe.engines.findIndex(e => e.engine === engine);
      if (anyOk || idx < 0 || torProbe.engines[idx].status !== "captcha") continue;
      rotations++;
      const fixed = await rotateTorForEngine(tor, engine);
      if (fixed) torProbe.engines[idx] = fixed;
    }
  }

  const { assignments, defaultExit } = optimise(probes);
  if (defaultExit) {
    console.log(`  default: ${defaultExit}`);
    for (const [eng, exit] of Object.entries(assignments)) console.log(`  ${eng} → ${exit}`);
  } else {
    console.log("  ✗ no tunnel carries data - routing to blackhole, search is blocked rather than sent directly");
  }

  const yaml = settingsOptimal(await getSecretKey(), exits, assignments, defaultExit);
  const apply = await applySettings(yaml);
  console.log(apply.ok ? `  ✓ settings ${apply.detail}` : `  ✗ settings NOT applied: ${apply.detail}`);

  state = {
    ...state,
    timestamp: new Date().toISOString(),
    probes,
    assignments: defaultExit ? { _default: defaultExit, ...assignments } : {},
    apply,
  };
  routingReady = apply.ok && defaultExit !== null;
  await saveState();
}

// True when the applied routes use a tunnel that is no longer up, or an up tunnel is missing from the last probe
function routesStale(exits: Exit[]): boolean {
  const routed = new Set(Object.values(state.assignments));
  if (routed.size === 0) return exits.some(e => isUp(e.name));
  if ([...routed].some(name => !isUp(name))) return true;
  const probed = new Set(state.probes.map(p => p.exit));
  return exits.some(e => isUp(e.name) && !probed.has(e.name));
}

// ─── Watchdog ───────────────────────────────────────────────

let lastLoopTick = Date.now();
let lastWatchdogTimer = Date.now();

// Timer path: a gap between our own ticks means the machine was suspended, not the loop - grant a fresh window
function watchdogTimer(): void {
  const now = Date.now();
  if (now - lastWatchdogTimer > 180_000) lastLoopTick = now;
  lastWatchdogTimer = now;
  checkWatchdog();
}

function checkWatchdog(): void {
  const stalled = Date.now() - lastLoopTick;
  if (stalled < WATCHDOG_STALL_LIMIT) return;
  log(`watchdog: monitor loop stalled ${Math.round(stalled / 60_000)}m - exiting for restart`);
  stopAllTunnels().finally(() => process.exit(1));
}

// Sleep against the wall clock in short slices, so a timer lost across macOS sleep/wake cannot park the loop
async function sleepWall(ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) await Bun.sleep(Math.min(SLEEP_SLICE, deadline - Date.now()));
}

// ─── CLI commands ───────────────────────────────────────────

async function cmdStart() {
  await mkdir(TUNNEL_LOG_DIR, { recursive: true });
  state = { ...((await loadHealthMatrix()) ?? emptyMatrix()), apply: null };

  // Server starts immediately; search through it stays closed until routes are applied
  startStatusServer();
  startTorRelay();
  setInterval(watchdogTimer, 60_000);
  console.log(`Dashboard: http://localhost:${PROXY_PORT}/stats\n`);

  // Never let SearXNG run with a settings file that has no outgoing proxy (e.g. a fresh install's seed)
  const current = await readContainerSettings();
  if (current !== null && !current.includes("socks5h://")) {
    log("container settings have no outgoing proxy - applying blackhole routes first");
    const apply = await applySettings(settingsOptimal(await getSecretKey(), [], {}, null));
    console.log(apply.ok ? `  ✓ ${apply.detail}` : `  ✗ ${apply.detail}`);
  }

  let exits = await discoverExits();
  console.log(`Exits: ${exits.length} (1 Tor + ${exits.length - 1} VPN), tunnels bind ${TUNNEL_HOST}`);
  console.log("Starting VPN tunnels...");
  killOrphanTunnels();
  await sweepRuntimeConfigs(exits);

  await exclusive(async () => {
    await redetect(exits, "startup");
    await checkTunnels(exits, { restart: true });
    anyVpnWasUp = exits.some(e => e.type === "vpn" && isUp(e.name));
    await routeCycle(exits, "startup");
  });
  firstRouteDone = true;

  let lastFullProbe = Date.now();
  console.log(`\nMonitoring every ${MONITOR_INTERVAL / 1000}s (full engine probe every ${FORCED_PROBE_INTERVAL / 60_000}m or when routes go stale)\n`);

  while (true) {
    lastLoopTick = Date.now();
    await sleepWall(MONITOR_INTERVAL);

    const fresh = await discoverExits();
    const before = exits.map(e => e.name).join();
    const configsChanged = fresh.map(e => e.name).join() !== before;
    if (configsChanged) {
      log(`VPN configs changed (${exits.length - 1} → ${fresh.length - 1})`);
      await syncTunnels(fresh);
      exits = fresh;
    }

    await exclusive(async () => {
      await watchNetwork(exits);
      await checkTunnels(exits, { restart: true });
      await watchVpnLoss(exits);
      const forced = Date.now() - lastFullProbe >= FORCED_PROBE_INTERVAL;
      const stale = routesStale(exits);
      if (configsChanged || forced || stale || !routingReady) {
        await routeCycle(exits, configsChanged ? "configs changed" : stale ? "routes stale" : !routingReady ? "not routing" : "scheduled");
        lastFullProbe = Date.now();
      }
    });
  }
}

async function cmdStop() {
  console.log("Stopping tunnels...");
  await stopAllTunnels();
  console.log("Done.");
}

// One-off check and re-route from a second process: measures and re-routes, but does not own the tunnels
async function cmdProbe() {
  // A second process would race the running manager's container restarts
  const running = await fetch(`http://127.0.0.1:${PROXY_PORT}/api/status`, { signal: AbortSignal.timeout(2000) })
    .then(() => true, () => false);
  if (running) {
    console.log(`The manager is running and re-checks every ${MONITOR_INTERVAL / 60_000} minutes. Use the dashboard's reprobe, or restart it.`);
    return;
  }
  state = (await loadHealthMatrix()) ?? emptyMatrix();
  const exits = await discoverExits();
  await checkTunnels(exits, { restart: false });
  await routeCycle(exits, "manual probe");
}

async function cmdStatus() {
  const matrix = await loadHealthMatrix();
  if (!matrix) {
    console.log("No health matrix. Run: bun proxy-manager.ts start");
    return;
  }

  const det = matrix.network?.detection;
  if (det) {
    console.log(`Network: ${det.netClass}, tunnels on UDP ${matrix.network!.tunnelPort}, DNS intercepted: ${det.dnsIntercepted ?? "unknown"} (${det.at})`);
    console.log(`  ports: ${PORT_LADDER.map(p => `${p}${det.ports[p] ? "✓" : "✗"}`).join(" ")}\n`);
  }
  console.log("Tunnels (data path through SearXNG's client):");
  for (const [name, t] of Object.entries(matrix.tunnels).sort()) {
    const age = Math.round((Date.now() - new Date(t.checkedAt).getTime()) / 60_000);
    console.log(`  ${name.padEnd(12)} ${t.status.padEnd(11)} ${(t.exitIp ?? "").padEnd(16)} ${(t.loc ?? "").padEnd(3)} ${age}m ago${t.detail ? `  ${t.detail}` : ""}`);
  }
  if (matrix.apply) {
    console.log(`\nSettings: ${matrix.apply.ok ? "applied" : "NOT APPLIED"} (${matrix.apply.detail}) at ${matrix.apply.at}`);
  }
  console.log(`Last engine probe: ${matrix.timestamp || "never"}\n`);

  const allEngines = new Set<string>();
  for (const p of matrix.probes) for (const e of p.engines) allEngines.add(e.engine);
  const engines = [...allEngines].sort();
  const exitNames = matrix.probes.map(p => p.exit);

  // Build lookup
  const lookup = new Map<string, Map<string, EngineResult>>();
  for (const probe of matrix.probes) {
    const m = new Map<string, EngineResult>();
    for (const e of probe.engines) m.set(e.engine, e);
    lookup.set(probe.exit, m);
  }

  const col = 14;
  process.stdout.write("".padEnd(18));
  for (const ex of exitNames) process.stdout.write(ex.padEnd(col));
  console.log();

  for (const eng of engines) {
    process.stdout.write(eng.padEnd(18));
    for (const ex of exitNames) {
      const er = lookup.get(ex)?.get(eng);
      if (!er) process.stdout.write("-".padEnd(col));
      else if (er.status === "ok") process.stdout.write("✓".padEnd(col));
      else process.stdout.write(`✗ ${er.status}`.substring(0, col - 2).padEnd(col));
    }
    console.log();
  }

  console.log("\nAssignments:");
  const def = matrix.assignments._default;
  console.log(`  (default) → ${def ?? "none (blackhole)"}`);
  for (const [eng, exit] of Object.entries(matrix.assignments)) {
    if (eng !== "_default") console.log(`  ${eng} → ${exit}`);
  }
}

// ─── Single-engine reprobe ─────────────────────────────────

async function reprobeEngine(url: URL): Promise<Response> {
  if (!firstRouteDone || lockHeld) {
    return Response.json({ ok: false, error: "busy: a tunnel check or routing cycle is running" }, { status: 409 });
  }
  return exclusive(() => reprobeEngineLocked(url));
}

async function reprobeEngineLocked(url: URL): Promise<Response> {
  const engine = url.searchParams.get("engine");
  if (!engine) {
    return Response.json({ ok: false, error: "missing engine param" }, { status: 400 });
  }

  const engineUrl = ENGINE_URLS.find(([e]) => e === engine)?.[1];
  if (!engineUrl) {
    return Response.json({ ok: false, error: `unknown engine: ${engine}` }, { status: 400 });
  }

  const exits = await discoverExits();
  const up = exits.filter(e => isUp(e.name));
  if (up.length === 0) {
    return Response.json({ ok: false, error: "no tunnel is carrying data" });
  }

  let results: ProbeOutput[];
  try {
    results = await containerProbe(up, [[engine, engineUrl]]);
  } catch (e: unknown) {
    return Response.json({ ok: false, error: `probe failed: ${e instanceof Error ? e.message : e}` });
  }

  const working = results.filter(r => r.engines?.[0]?.status === "ok").map(r => r.name);
  console.log(`[reprobe] ${engine}: ${working.length}/${results.length} exits ok`);

  // Update engine status in existing probes
  for (const r of results) {
    const result = r.engines?.[0];
    const probe = state.probes.find(p => p.exit === r.name);
    if (!probe || !result) continue;
    const idx = probe.engines.findIndex(e => e.engine === engine);
    if (idx >= 0) probe.engines[idx] = result;
    else probe.engines.push(result);
  }

  const defaultExit = state.assignments._default ?? null;
  let assignedExit: string | null = null;

  if (working.length > 0 && defaultExit) {
    if (working.includes(defaultExit)) {
      delete state.assignments[engine];
      assignedExit = defaultExit;
    } else {
      state.assignments[engine] = working[0];
      assignedExit = working[0];
    }

    const { _default, ...engineAssignments } = state.assignments;
    const apply = await applySettings(settingsOptimal(await getSecretKey(), exits, engineAssignments, defaultExit));
    state.apply = apply;
    routingReady = apply.ok;
    if (!apply.ok) console.log(`[reprobe] ✗ settings NOT applied: ${apply.detail}`);
  }
  await saveState();

  if (working.length === 0) {
    return Response.json({ ok: false, error: `${engine}: no working exit found` });
  }
  return Response.json({ ok: state.apply?.ok ?? false, engine, exit: assignedExit });
}

// ─── Status dashboard ──────────────────────────────────────

// Only the dashboard and results pages served from this origin may call state-changing endpoints
function crossOrigin(req: Request): boolean {
  const site = req.headers.get("sec-fetch-site");
  const origin = req.headers.get("origin");
  const sameOrigin = origin === null || origin === `http://localhost:${PROXY_PORT}` || origin === `http://127.0.0.1:${PROXY_PORT}`;
  return Boolean(site && site !== "same-origin" && site !== "none") || !sameOrigin;
}

function gateMessage(): string {
  if (!state.apply) return "Routes are not applied yet - the first tunnel probe is still running.";
  if (!state.apply.ok) return `Routing settings failed to apply: ${state.apply.detail}`;
  return "No tunnel (VPN or Tor) is carrying traffic, so search is blocked rather than sent from this machine's own IP.";
}

function startStatusServer() {
  Bun.serve({
    port: PROXY_PORT,
    hostname: "127.0.0.1",
    idleTimeout: 255,
    async fetch(req) {
      checkWatchdog();
      const url = new URL(req.url);

      if (url.pathname === "/stats" || url.pathname === "/stats/") {
        return statusPage();
      }
      if (url.pathname === "/api/status") {
        return statusJson();
      }
      if (url.pathname === "/api/log") {
        return statusLog(url);
      }
      if (url.pathname === "/api/reprobe" && req.method === "POST") {
        // Reprobe restarts the container; only this origin may trigger it
        if (crossOrigin(req)) return Response.json({ ok: false, error: "cross-origin request refused" }, { status: 403 });
        return reprobeEngine(url);
      }
      if (url.pathname === "/api/overview" && req.method === "POST") {
        // Sends the query to the chosen AI provider; only this origin may trigger it
        if (crossOrigin(req)) return Response.json({ ok: false, error: "cross-origin request refused" }, { status: 403 });
        return handleOverview(req);
      }
      if (url.pathname === "/api/ai-status") {
        return handleAiStatus();
      }
      if (url.pathname === "/ai-overview.js" || url.pathname === "/ai-overview.css") {
        const type = url.pathname.endsWith(".js") ? "text/javascript" : "text/css";
        return new Response(Bun.file(join(ROOT, url.pathname.slice(1))), { headers: { "Content-Type": `${type}; charset=utf-8` } });
      }

      if (!routingReady) {
        return new Response(`SearXNG-Local: search unavailable. ${gateMessage()}\nStatus: http://localhost:${PROXY_PORT}/stats\n`, {
          status: 503,
          headers: { "Content-Type": "text/plain; charset=utf-8", "Retry-After": "60" },
        });
      }

      // Reverse-proxy everything else to SearXNG
      const target = `${SEARXNG_URL}${url.pathname}${url.search}`;
      const isSearch = url.pathname === "/search" && aiEnabled();
      // The search form may POST: buffer its small body so the query can be read and still forwarded
      const bodyText = isSearch && req.method === "POST" ? await req.text() : null;
      try {
        const upstream = await fetch(target, {
          method: req.method,
          headers: req.headers,
          body: bodyText ?? (req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined),
          redirect: "manual",
          signal: AbortSignal.timeout(30_000),
        });
        const fwdHeaders = new Headers(upstream.headers);
        fwdHeaders.delete("content-encoding");
        fwdHeaders.delete("content-length");
        if (isSearch && upstream.ok && (upstream.headers.get("content-type") ?? "").includes("text/html")) {
          const query = url.searchParams.get("q") ?? new URLSearchParams(bodyText ?? "").get("q") ?? "";
          return new Response(injectPanel(await upstream.text(), query), {
            status: upstream.status,
            statusText: upstream.statusText,
            headers: fwdHeaders,
          });
        }
        return new Response(upstream.body, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: fwdHeaders,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return new Response(`SearXNG unavailable: ${msg}\n`, { status: 502 });
      }
    },
  });
  console.log(`Proxy listening on http://localhost:${PROXY_PORT}/ (SearXNG on :${SEARXNG_INTERNAL_PORT}, /stats → dashboard)\n`);
}

async function statusLog(url: URL): Promise<Response> {
  const lines = parseInt(url.searchParams.get("lines") ?? "50", 10);
  try {
    const content = await readFile(LOG_FILE, "utf-8");
    const allLines = content.replace(/\n$/, "").split("\n");
    const tail = allLines.slice(-Math.min(lines, 200)).join("\n") + "\n";
    return new Response(tail, {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  } catch {
    return new Response(`No log file yet (${LOG_FILE}).\n`, {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}

interface TunnelRow { name: string; country: string; status: TunnelStatus | "unchecked"; exitIp: string; loc: string; ageMin: number | null; detail: string }

async function getTunnelStatus(): Promise<TunnelRow[]> {
  const exits = await discoverExits();
  return exits.map(exit => {
    const t = state.tunnels[exit.name];
    const country = exit.country ? (COUNTRY_NAMES[exit.country] ?? exit.country) : (exit.type === "tor" ? "Tor network" : "-");
    return {
      name: exit.name,
      country,
      status: t?.status ?? "unchecked",
      exitIp: t?.exitIp ?? "",
      loc: t?.loc ?? "",
      ageMin: t ? Math.round((Date.now() - new Date(t.checkedAt).getTime()) / 60_000) : null,
      detail: t?.detail ?? "",
    };
  });
}

async function statusJson(): Promise<Response> {
  const tunnels = await getTunnelStatus();
  return Response.json({ matrix: state, tunnels, routingReady, gate: routingReady ? null : gateMessage() });
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

async function statusPage(): Promise<Response> {
  const matrix = state;
  const tunnels = await getTunnelStatus();

  const defaultExit = matrix.assignments._default ?? "none";
  const assignments = matrix.assignments;

  // Build engine list with routes
  const allEngines = new Set<string>();
  for (const p of matrix.probes) for (const e of p.engines) allEngines.add(e.engine);
  const engines = [...allEngines].sort();

  // Build lookup for the health grid
  const lookup = new Map<string, Map<string, EngineResult>>();
  for (const probe of matrix.probes) {
    const m = new Map<string, EngineResult>();
    for (const e of probe.engines) m.set(e.engine, e);
    lookup.set(probe.exit, m);
  }
  const exitNames = matrix.probes.map(p => p.exit);
  const issueCount = engines.filter(eng => {
    const route = assignments[eng] ?? defaultExit;
    return lookup.get(route)?.get(eng)?.status !== "ok";
  }).length;

  let totalEnabled = 0;
  try {
    const res = await fetch(`http://127.0.0.1:${SEARXNG_INTERNAL_PORT}/config`, { signal: AbortSignal.timeout(3000) });
    const cfg = await res.json() as { engines?: { enabled?: boolean }[] };
    totalEnabled = (cfg.engines ?? []).filter((e: { enabled?: boolean }) => e.enabled !== false).length;
  } catch { /* SearXNG not ready yet */ }
  const activeCount = totalEnabled > 0 ? totalEnabled - issueCount : 0;

  const probeAge = matrix.timestamp
    ? Math.round((Date.now() - new Date(matrix.timestamp).getTime()) / 60_000)
    : null;
  const upCount = tunnels.filter(t => t.status === "up").length;
  const apply = matrix.apply;
  const applyText = !apply ? "not applied yet"
    : apply.ok ? `applied ${Math.round((Date.now() - new Date(apply.at).getTime()) / 60_000)}m ago`
    : `FAILED: ${esc(apply.detail)}`;
  const det = matrix.network?.detection;
  const netText = det
    ? `${det.netClass} · UDP ${matrix.network!.tunnelPort}${det.dnsIntercepted ? " · DNS intercepted" : ""} · checked ${Math.round((Date.now() - new Date(det.at).getTime()) / 60_000)}m ago`
    : "not detected yet";
  const statusRank: Record<string, number> = { down: 0, bypass: 1, unverified: 2, unchecked: 3, up: 4 };

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SearXNG Proxy Status</title>
<style>
  :root { --bg: #0d1117; --fg: #e6edf3; --card: #161b22; --border: #30363d; --ok: #3fb950; --bad: #f85149; --warn: #d29922; --muted: #8b949e; --accent: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--fg); padding: 1.5rem; max-width: 1400px; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  .subtitle { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
  .banner { background: rgba(248,81,73,0.12); border: 1px solid var(--bad); color: var(--fg); border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1.5rem; font-size: 0.9rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
  @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
  .card h2 { font-size: 1rem; margin-bottom: 0.75rem; color: var(--accent); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { padding: 0.35rem 0.6rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; }
  .ok { color: var(--ok); }
  .bad { color: var(--bad); }
  .warn { color: var(--warn); }
  .muted { color: var(--muted); }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .dot.up { background: var(--ok); }
  .dot.down, .dot.bypass { background: var(--bad); }
  .dot.unverified, .dot.unchecked { background: var(--warn); }
  .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 500; }
  .tag.default { background: rgba(88,166,255,0.15); color: var(--accent); }
  .tag.routed { background: rgba(63,185,80,0.15); color: var(--ok); }
  .tag.blocked { background: rgba(248,81,73,0.15); color: var(--bad); }
  .reprobe-btn { background: rgba(88,166,255,0.15); color: var(--accent); border: 1px solid var(--accent); border-radius: 4px; padding: 0.15rem 0.5rem; font-size: 0.75rem; cursor: pointer; white-space: nowrap; }
  .reprobe-btn:hover { background: rgba(88,166,255,0.3); }
  .reprobe-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .health-grid { overflow-x: auto; }
  .health-grid table { min-width: 600px; }
  .health-grid td, .health-grid th { text-align: center; padding: 0.3rem 0.4rem; font-size: 0.78rem; white-space: nowrap; }
  .health-grid td:first-child, .health-grid th:first-child { text-align: left; }
  .refresh { float: right; color: var(--muted); font-size: 0.8rem; cursor: pointer; text-decoration: underline; }
</style>
</head>
<body>
<h1>SearXNG Proxy Status <span class="muted" style="font-size:0.5em; font-weight:normal">v${VERSION}</span></h1>
<p class="subtitle">Network: <strong>${esc(netText)}</strong> &bull; Tunnels carrying data: <strong>${upCount}/${tunnels.length}</strong> &bull; Default exit: <strong>${esc(defaultExit)}</strong> &bull; Settings: <strong class="${apply?.ok ? "" : "bad"}">${applyText}</strong> &bull; Last engine probe: ${probeAge !== null ? `${probeAge}m ago` : "never"} &bull; Active engines: <strong>${activeCount}/${totalEnabled}</strong> <a class="refresh" onclick="location.reload()">refresh</a></p>
${routingReady ? "" : `<div class="banner"><strong>Search is blocked.</strong> ${esc(gateMessage())}</div>`}

<div class="grid">
  <div class="card">
    <h2>Engine Issues</h2>
    <div id="engine-container" style="min-height: 20rem;">
    <table>
      <tr><th>Engine</th><th>Exit</th><th>Status</th><th></th></tr>
      <tbody id="engine-rows">
      ${engines.filter(eng => {
        const route = assignments[eng] ?? defaultExit;
        const probe = lookup.get(route)?.get(eng);
        return probe?.status !== "ok";
      }).map(eng => {
        const route = assignments[eng] ?? defaultExit;
        const isCustom = eng in assignments && eng !== "_default";
        const probe = lookup.get(route)?.get(eng);
        const status = probe?.status ?? "unknown";
        const statusClass = status === "timeout" ? "warn" : status === "unknown" ? "muted" : "bad";
        const tagClass = isCustom ? "routed" : "default";
        return `<tr class="engine-row"><td>${esc(eng)}</td><td><span class="tag ${tagClass}">${esc(route)}</span></td><td class="${statusClass}">${status}</td><td><button class="reprobe-btn" onclick="reprobe('${esc(eng)}', this)">reprobe</button></td></tr>`;
      }).join("\n      ") || '<tr><td colspan="4" class="ok">All engines routing OK</td></tr>'}
      </tbody>
    </table>
    </div>
    ${`<div id="engine-pager" style="display:none; align-items:center; justify-content:center; gap:0.5rem; margin-top:0.5rem; font-size:0.8rem;">
      <button class="reprobe-btn" onclick="enginePage(0)" title="First">&laquo;</button>
      <button class="reprobe-btn" onclick="enginePage(engineState.page-1)" title="Previous">&lsaquo;</button>
      <span id="engine-page-info" class="muted"></span>
      <button class="reprobe-btn" onclick="enginePage(engineState.page+1)" title="Next">&rsaquo;</button>
      <button class="reprobe-btn" onclick="enginePage(engineState.pages-1)" title="Last">&raquo;</button>
    </div>`}
  </div>

  <div class="card">
    <h2>Tunnels <span class="muted" style="font-size:0.75em; font-weight:normal">(data path through SearXNG's client)</span></h2>
    <div id="tunnel-container" style="min-height: 20rem;">
    <table>
      <tr><th>Exit</th><th>Country</th><th>Exit IP</th><th>Status</th><th>Checked</th></tr>
      <tbody id="tunnel-rows">
      ${tunnels.sort((a, b) => (statusRank[a.status] - statusRank[b.status]) || a.country.localeCompare(b.country) || a.name.localeCompare(b.name, undefined, { numeric: true })).map(t => {
        const cls = t.status === "up" ? "ok" : t.status === "unverified" || t.status === "unchecked" ? "warn" : "bad";
        return `<tr class="tunnel-row" title="${esc(t.detail)}"><td><span class="dot ${t.status}"></span>${esc(t.name)}</td><td class="muted">${esc(t.country)}</td><td class="muted">${esc(t.exitIp)}${t.loc ? ` (${esc(t.loc)})` : ""}</td><td class="${cls}">${t.status}</td><td class="muted">${t.ageMin === null ? "-" : `${t.ageMin}m ago`}</td></tr>`;
      }).join("\n      ")}
      </tbody>
    </table>
    </div>
    ${`<div id="tunnel-pager" style="display:none; align-items:center; justify-content:center; gap:0.5rem; margin-top:0.5rem; font-size:0.8rem;">
      <button class="reprobe-btn" onclick="tunnelPage(0)" title="First">&laquo;</button>
      <button class="reprobe-btn" onclick="tunnelPage(tunnelState.page-1)" title="Previous">&lsaquo;</button>
      <span id="tunnel-page-info" class="muted"></span>
      <button class="reprobe-btn" onclick="tunnelPage(tunnelState.page+1)" title="Next">&rsaquo;</button>
      <button class="reprobe-btn" onclick="tunnelPage(tunnelState.pages-1)" title="Last">&raquo;</button>
    </div>`}
  </div>
</div>

<div class="card health-grid">
  <h2>Health Matrix</h2>
  <table>
    <tr><th>Engine</th>${exitNames.map(e => `<th>${esc(e)}</th>`).join("")}</tr>
    ${engines.map(eng => {
      const cells = exitNames.map(ex => {
        const er = lookup.get(ex)?.get(eng);
        if (!er) return `<td class="muted">-</td>`;
        if (er.status === "ok") return `<td class="ok">✓</td>`;
        return `<td class="bad" title="${esc(er.detail ?? er.status)}">✗</td>`;
      }).join("");
      return `<tr><td>${esc(eng)}</td>${cells}</tr>`;
    }).join("\n    ")}
  </table>
</div>

<div class="card" style="margin-top: 1.5rem;">
  <h2>Activity Log</h2>
  <pre id="log" style="background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; font-size: 0.78rem; line-height: 1.5; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; color: var(--fg);"></pre>
</div>

<script>
const PAGE_SIZE = 10;
function paginate(rowClass, pagerEl, stateObj) {
  return function(p) {
    const rows = document.querySelectorAll("." + rowClass);
    stateObj.pages = Math.ceil(rows.length / PAGE_SIZE);
    stateObj.page = Math.max(0, Math.min(p, stateObj.pages - 1));
    const start = stateObj.page * PAGE_SIZE;
    rows.forEach((r, i) => r.style.display = (i >= start && i < start + PAGE_SIZE) ? "" : "none");
    const info = pagerEl.querySelector("span");
    if (info) info.textContent = (stateObj.page + 1) + " / " + stateObj.pages;
    pagerEl.style.display = stateObj.pages > 1 ? "flex" : "none";
  };
}
const tunnelState = { page: 0, pages: 0 };
const tunnelPage = paginate("tunnel-row", document.getElementById("tunnel-pager"), tunnelState);
if (document.querySelectorAll(".tunnel-row").length > 0) tunnelPage(0);
const engineState = { page: 0, pages: 0 };
const enginePage = paginate("engine-row", document.getElementById("engine-pager"), engineState);
if (document.querySelectorAll(".engine-row").length > 0) enginePage(0);

async function refreshLog() {
  try {
    const res = await fetch("/api/log?lines=80");
    const text = await res.text();
    const el = document.getElementById("log");
    el.textContent = text;
    el.scrollTop = el.scrollHeight;
  } catch {}
}
async function reprobe(engine, btn) {
  btn.disabled = true;
  btn.textContent = "probing…";
  try {
    const res = await fetch("/api/reprobe?engine=" + encodeURIComponent(engine), { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      btn.textContent = data.exit ? ("✓ " + data.exit) : "✓ done";
      setTimeout(() => location.reload(), 1500);
    } else {
      btn.textContent = data.error || "failed";
      setTimeout(() => { btn.textContent = "reprobe"; btn.disabled = false; }, 3000);
    }
  } catch {
    btn.textContent = "error";
    setTimeout(() => { btn.textContent = "reprobe"; btn.disabled = false; }, 3000);
  }
}
refreshLog();
setInterval(refreshLog, 10000);
setTimeout(() => location.reload(), 120000);
</script>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function usage() {
  console.log(`Usage: bun proxy-manager.ts <command>

Commands:
  start   Start server, tunnels, probe, monitor (foreground)
  stop    Stop everything
  probe   Re-check tunnels and re-route (from a second shell)
  status  Show tunnel health, health matrix and routes

Prerequisites:
  wireproxy   go install github.com/windtf/wireproxy/cmd/wireproxy@latest
  tor         brew install tor && brew services start tor
  searxng     ./setup.sh (container must be running)
  configs     Drop WireGuard .conf files into vpn-configs/
`);
}

export { proxyUrl, classifyTunnel, optimise, settingsOptimal, textSince, restartDue, parseRuntimeStatus, BLACKHOLE_PROXY };
export type { Exit, ExitProbe };

if (import.meta.main) {
  // Cleanup on exit
  process.on("SIGINT", async () => {
    console.log("\nShutting down...");
    await stopAllTunnels();
    process.exit(0);
  });
  process.on("SIGTERM", async () => {
    await stopAllTunnels();
    process.exit(0);
  });

  const cmd = process.argv[2] ?? "help";
  switch (cmd) {
    case "start": await cmdStart(); break;
    case "stop": await cmdStop(); break;
    case "probe": await cmdProbe(); break;
    case "status": await cmdStatus(); break;
    default: usage();
  }
}
