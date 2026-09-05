#!/usr/bin/env bun

import { readdir, readFile, writeFile, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { execSync } from "node:child_process";

const ROOT = import.meta.dir;
const VPN_DIR = join(ROOT, "vpn-configs");
const RUNTIME_DIR = join(ROOT, ".runtime");
const HEALTH_FILE = join(RUNTIME_DIR, "health-matrix.json");
const SEARXNG_URL = "http://localhost:8080";
const CONTAINER_NAME = "searxng";
const TOR_PORT = 9050;
const WP_BASE_PORT = 10801;
const WP_BIN = join(process.env.HOME!, "go", "bin", "wireproxy");
const PROBE_TIMEOUT = 15_000;
const READY_TIMEOUT = 20_000;
const MONITOR_INTERVAL = 300_000;

// Engines disabled by default in SearXNG that we want enabled
const ENABLE_ENGINES = [
  "bing", "boardreader", "crowdview", "gmx", "mojeek", "mwmbl",
  "privacywall", "qwant", "vuhuv", "wiby", "yahoo", "yep",
];

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

interface HealthMatrix {
  timestamp: string;
  probes: ExitProbe[];
  assignments: Record<string, string>;
}

const processes = new Map<string, Subprocess>();
type Subprocess = ReturnType<typeof Bun.spawn>;

// ─── WireGuard → wireproxy config ───────────────────────────

function wgToWireproxyConfig(wgContent: string, socksPort: number): string {
  const lines: string[] = [];
  for (const raw of wgContent.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;

    if (line.startsWith("Address")) {
      const v4 = line.split("=")[1].split(",").map(s => s.trim()).filter(s => !s.includes(":"));
      lines.push(`Address = ${v4.join(", ")}`);
    } else if (line.startsWith("DNS")) {
      const v4 = line.split("=")[1].split(",").map(s => s.trim()).filter(s => !s.includes(":"));
      lines.push(`DNS = ${v4.join(", ")}`);
    } else if (line.startsWith("AllowedIPs")) {
      const v4 = line.split("=")[1].split(",").map(s => s.trim()).filter(s => !s.includes(":"));
      lines.push(`AllowedIPs = ${v4.join(", ")}`);
    } else {
      lines.push(line);
    }
  }
  lines.push("", "[Socks5]", `BindAddress = 127.0.0.1:${socksPort}`, "");
  return lines.join("\n");
}

// ─── Exit discovery ─────────────────────────────────────────

async function discoverExits(): Promise<Exit[]> {
  const exits: Exit[] = [{ name: "tor", type: "tor", port: TOR_PORT }];

  let files: string[];
  try {
    files = await readdir(VPN_DIR);
  } catch {
    return exits;
  }

  const configs = files.filter(f => f.endsWith(".conf")).sort();
  let port = WP_BASE_PORT;
  for (const file of configs) {
    const base = file.replace(/\.conf$/, "");
    const name = base.replace(/^wg-/, "").toLowerCase();
    const country = base.match(/^wg-([A-Z]{2})-/)?.[1];
    exits.push({
      name,
      type: "vpn",
      port: port++,
      configFile: join(VPN_DIR, file),
      country,
    });
  }
  return exits;
}

// ─── Process management ─────────────────────────────────────

async function startProxies(exits: Exit[]): Promise<Exit[]> {
  await mkdir(RUNTIME_DIR, { recursive: true });

  // Kill any leftovers from previous runs
  try { execSync("pkill -f wireproxy 2>/dev/null", { stdio: "ignore" }); } catch { /* fine */ }
  await Bun.sleep(500);

  const vpnExits = exits.filter(e => e.type === "vpn" && e.configFile);
  if (vpnExits.length === 0) return exits.filter(e => e.type === "tor");

  // Generate configs
  for (const exit of vpnExits) {
    const wg = await readFile(exit.configFile!, "utf-8");
    const wp = wgToWireproxyConfig(wg, exit.port);
    await writeFile(join(RUNTIME_DIR, `wp-${exit.name}.conf`), wp);
  }

  // Start all in parallel
  const spawned = vpnExits.map(exit => ({
    exit,
    proc: Bun.spawn([WP_BIN, "-c", join(RUNTIME_DIR, `wp-${exit.name}.conf`)], {
      stdout: "ignore",
      stderr: "pipe",
    }),
  }));

  // Wait for handshakes (up to 10s)
  const results = await Promise.all(
    spawned.map(async ({ exit, proc }) => {
      const ok = await waitForHandshake(proc, 10_000);
      if (ok) {
        processes.set(exit.name, proc);
        console.log(`  ✓ ${exit.name} (port ${exit.port})`);
        return exit;
      }
      proc.kill();
      console.log(`  ✗ ${exit.name}: failed to connect`);
      return null;
    })
  );

  const active = results.filter((e): e is Exit => e !== null);
  return [exits.find(e => e.type === "tor")!, ...active];
}

async function waitForHandshake(proc: Subprocess, timeout: number): Promise<boolean> {
  if (!proc.stderr) return false;
  const reader = (proc.stderr as ReadableStream<Uint8Array>).getReader();
  const decoder = new TextDecoder();
  const deadline = Date.now() + timeout;

  try {
    while (Date.now() < deadline) {
      const remaining = deadline - Date.now();
      const result = await Promise.race([
        reader.read(),
        Bun.sleep(remaining).then(() => ({ done: true as const, value: undefined })),
      ]);
      if (result.done || !result.value) return false;
      if (decoder.decode(result.value).includes("Received handshake response")) return true;
    }
  } catch { /* stream error */ }
  return false;
}

async function restartDeadTunnels(exits: Exit[]): Promise<number> {
  let restarted = 0;
  for (const exit of exits) {
    if (exit.type !== "vpn" || !exit.configFile) continue;
    try {
      execSync(`nc -z -G 2 127.0.0.1 ${exit.port}`, { stdio: "ignore", timeout: 3000 });
    } catch {
      console.log(`  ⚠ ${exit.name} dead — restarting...`);
      const old = processes.get(exit.name);
      if (old) { try { old.kill(); } catch { /* already dead */ } }
      processes.delete(exit.name);

      const wpConf = join(RUNTIME_DIR, `wp-${exit.name}.conf`);
      try { await readFile(wpConf); } catch {
        const wg = await readFile(exit.configFile!, "utf-8");
        await writeFile(wpConf, wgToWireproxyConfig(wg, exit.port));
      }
      const proc = Bun.spawn([WP_BIN, "-c", wpConf], { stdout: "ignore", stderr: "pipe" });
      if (await waitForHandshake(proc, 10_000)) {
        processes.set(exit.name, proc);
        console.log(`  ✓ ${exit.name} back up`);
        restarted++;
      } else {
        proc.kill();
        console.log(`  ✗ ${exit.name} failed to reconnect`);
      }
    }
  }
  return restarted;
}

async function stopProxies(): Promise<void> {
  for (const [name, proc] of processes) {
    proc.kill();
    console.log(`  stopped ${name}`);
  }
  processes.clear();
  try { execSync("pkill -f wireproxy 2>/dev/null", { stdio: "ignore" }); } catch { /* fine */ }
}

// ─── Container management ───────────────────────────────────

async function getSecretKey(): Promise<string> {
  try {
    const out = execSync(
      `podman exec ${CONTAINER_NAME} grep secret_key /etc/searxng/settings.yml 2>/dev/null`,
      { encoding: "utf-8" },
    ).trim();
    const match = out.match(/secret_key:\s*"([^"]+)"/);
    if (match) return match[1];
  } catch { /* container not running or no settings */ }
  return execSync("openssl rand -hex 16", { encoding: "utf-8" }).trim();
}

async function applySettings(yaml: string): Promise<void> {
  const tmp = join(RUNTIME_DIR, "settings-live.yml");
  await writeFile(tmp, yaml);
  execSync(`podman cp "${tmp}" ${CONTAINER_NAME}:/etc/searxng/settings.yml`);
  execSync(`podman restart ${CONTAINER_NAME}`);
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

// ─── Settings generation ────────────────────────────────────

function engineEnablements(): string {
  return ENABLE_ENGINES.map(e => `  - name: ${e}\n    disabled: false`).join("\n");
}

function settingsForProbe(secretKey: string, proxyUrl: string): string {
  return `use_default_settings: true

server:
  secret_key: "${secretKey}"
  image_proxy: true

search:
  formats:
    - html
    - json

outgoing:
  proxies:
    "all://":
      - "${proxyUrl}"
  request_timeout: 10.0
  max_request_timeout: 15.0
  useragent_suffix: ""

engines:
${engineEnablements()}
`;
}

function settingsOptimal(
  secretKey: string,
  exits: Exit[],
  assignments: Record<string, string>,
  defaultExit: string,
): string {
  const usedExits = new Set([defaultExit, ...Object.values(assignments)]);

  let networks = "";
  for (const exit of exits) {
    if (!usedExits.has(exit.name)) continue;
    networks += `    ${exit.name}:\n`;
    networks += `      proxies:\n`;
    networks += `        "all://":\n`;
    networks += `          - "socks5h://host.containers.internal:${exit.port}"\n`;
  }

  // Merge engine enablements with network assignments
  const routedMap = new Map(
    Object.entries(assignments).filter(([, e]) => e !== defaultExit),
  );
  const allEngineNames = new Set([...ENABLE_ENGINES, ...routedMap.keys()]);

  let engineSection = "\nengines:\n";
  for (const name of [...allEngineNames].sort()) {
    engineSection += `  - name: ${name}\n`;
    if (ENABLE_ENGINES.includes(name)) engineSection += `    disabled: false\n`;
    if (routedMap.has(name)) engineSection += `    network: ${routedMap.get(name)}\n`;
  }

  const defaultPort = exits.find(e => e.name === defaultExit)?.port ?? TOR_PORT;

  return `use_default_settings: true

server:
  secret_key: "${secretKey}"
  image_proxy: true

search:
  formats:
    - html
    - json

outgoing:
  networks:
${networks}  proxies:
    "all://":
      - "socks5h://host.containers.internal:${defaultPort}"
  request_timeout: 10.0
  max_request_timeout: 15.0
  useragent_suffix: ""
${engineSection}`;
}

// ─── Health probing ─────────────────────────────────────────

async function probeExit(exit: Exit, secretKey: string): Promise<ExitProbe> {
  const proxyUrl = `socks5h://host.containers.internal:${exit.port}`;
  process.stdout.write(`  probing ${exit.name}...`);

  await applySettings(settingsForProbe(secretKey, proxyUrl));
  if (!(await waitForReady())) {
    console.log(" ⚠ SearXNG didn't come up");
    return { exit: exit.name, engines: [] };
  }

  try {
    const res = await fetch(`${SEARXNG_URL}/search?q=test&format=json`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT),
    });
    if (!res.ok) {
      console.log(` ⚠ HTTP ${res.status}`);
      return { exit: exit.name, engines: [] };
    }

    const data = (await res.json()) as {
      results?: { engine: string }[];
      unresponsive_engines?: [string, string][];
    };

    const engines: EngineResult[] = [];
    const ok = new Set<string>();
    for (const r of data.results ?? []) ok.add(r.engine);
    for (const e of ok) engines.push({ engine: e, status: "ok" });

    for (const [name, reason] of data.unresponsive_engines ?? []) {
      const lower = reason.toLowerCase();
      let status: EngineResult["status"] = "blocked";
      if (lower.includes("captcha")) status = "captcha";
      else if (lower.includes("timeout")) status = "timeout";
      engines.push({ engine: name, status, detail: reason });
    }

    console.log(` ✓ ${ok.size} ok, ${(data.unresponsive_engines ?? []).length} blocked`);
    return { exit: exit.name, engines };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(` ✗ ${msg}`);
    return { exit: exit.name, engines: [] };
  }
}

async function fullProbe(exits: Exit[], secretKey: string): Promise<ExitProbe[]> {
  const probes: ExitProbe[] = [];
  for (const exit of exits) {
    probes.push(await probeExit(exit, secretKey));
  }
  return probes;
}

// ─── Route optimisation ─────────────────────────────────────

function optimise(probes: ExitProbe[]): { assignments: Record<string, string>; defaultExit: string } {
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

  // Default exit = most working engines
  let defaultExit = "tor";
  let maxScore = 0;
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

// ─── CLI commands ───────────────────────────────────────────

async function cmdStart() {
  await mkdir(RUNTIME_DIR, { recursive: true });

  console.log("Discovering exits...");
  const allExits = await discoverExits();
  console.log(`  ${allExits.length} exits (1 Tor + ${allExits.length - 1} VPN)\n`);

  // Check Tor
  console.log("Checking Tor...");
  try {
    execSync(`nc -z -G 2 127.0.0.1 ${TOR_PORT}`, { stdio: "ignore", timeout: 3000 });
    console.log(`  ✓ Tor SOCKS5 on port ${TOR_PORT}\n`);
  } catch {
    console.log("  ⚠ Tor not running — start it: brew services start tor\n");
  }

  // Start VPN tunnels
  console.log("Starting VPN tunnels...");
  const activeExits = await startProxies(allExits);
  console.log(`\n${activeExits.length} active exits\n`);

  // Probe
  const secretKey = await getSecretKey();
  console.log("Running health probe (one SearXNG search per exit)...");
  const probes = await fullProbe(activeExits, secretKey);

  // Optimise
  console.log("\nOptimising routes...");
  const { assignments, defaultExit } = optimise(probes);
  console.log(`  default: ${defaultExit}`);
  for (const [eng, exit] of Object.entries(assignments)) {
    console.log(`  ${eng} → ${exit}`);
  }

  // Apply
  console.log("\nApplying optimal routes...");
  const yaml = settingsOptimal(secretKey, activeExits, assignments, defaultExit);
  await applySettings(yaml);
  if (await waitForReady()) {
    console.log("✓ SearXNG running with optimal proxy routes\n");
  } else {
    console.log("⚠ SearXNG may not have started correctly\n");
  }

  // Verify and re-route engines that fail on the default despite passing the probe
  console.log("Verifying...");
  try {
    const res = await fetch(`${SEARXNG_URL}/search?q=test&format=json`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT),
    });
    const data = (await res.json()) as {
      results?: unknown[];
      unresponsive_engines?: [string, string][];
    };
    const ok = new Set((data.results as { engine: string }[])?.map(r => r.engine) ?? []);
    const blocked = data.unresponsive_engines ?? [];
    console.log(`  ${ok.size} engines responding, ${blocked.length} unresponsive`);

    // Re-route engines that failed verification but have working alternatives
    let rerouted = false;
    let savedProbes: ExitProbe[] = [];
    try {
      savedProbes = (JSON.parse(await readFile(HEALTH_FILE, "utf-8")) as HealthMatrix).probes;
    } catch { /* no saved matrix */ }

    for (const [name, reason] of blocked) {
      if (assignments[name]) continue;
      const engineProbes = probes.flatMap(p =>
        p.engines.filter(e => e.engine === name && e.status === "ok").map(() => p.exit),
      );
      let alt = engineProbes.find(e => e !== defaultExit);
      // Fall back to historical probe data
      if (!alt && savedProbes.length > 0) {
        for (const p of savedProbes) {
          if (p.exit === defaultExit) continue;
          if (p.engines.some(e => e.engine === name && e.status === "ok")) { alt = p.exit; break; }
        }
      }
      if (alt) {
        console.log(`    ✗ ${name}: ${reason} → re-routing to ${alt}`);
        assignments[name] = alt;
        rerouted = true;
      } else {
        console.log(`    ✗ ${name}: ${reason} (no alternative)`);
      }
    }

    if (rerouted) {
      console.log("\n  Re-applying with corrected routes...");
      const fixedYaml = settingsOptimal(secretKey, activeExits, assignments, defaultExit);
      await applySettings(fixedYaml);
      await waitForReady();
      console.log("  ✓ Routes corrected");
    }
  } catch (err: unknown) {
    console.log(`  ⚠ verification failed: ${err instanceof Error ? err.message : err}`);
  }

  // Save matrix
  const matrix: HealthMatrix = {
    timestamp: new Date().toISOString(),
    probes,
    assignments: { _default: defaultExit, ...assignments },
  };
  await writeFile(HEALTH_FILE, JSON.stringify(matrix, null, 2));
  console.log(`\nHealth matrix saved to .runtime/health-matrix.json`);
}

async function cmdStop() {
  console.log("Stopping proxies...");
  await stopProxies();
  console.log("Done.");
}

async function cmdProbe() {
  const exits = await discoverExits();
  const reachable: Exit[] = [];

  for (const exit of exits) {
    try {
      execSync(`nc -z -G 2 127.0.0.1 ${exit.port}`, { stdio: "ignore", timeout: 3000 });
      reachable.push(exit);
    } catch {
      console.log(`  skip ${exit.name} (port ${exit.port} unreachable)`);
    }
  }

  if (reachable.length === 0) {
    console.log("No active exits. Run: bun proxy-manager.ts start");
    return;
  }

  const secretKey = await getSecretKey();
  console.log(`Re-probing ${reachable.length} exits...`);
  const probes = await fullProbe(reachable, secretKey);
  const { assignments, defaultExit } = optimise(probes);

  const yaml = settingsOptimal(secretKey, exits, assignments, defaultExit);
  await applySettings(yaml);
  await waitForReady();

  const matrix: HealthMatrix = {
    timestamp: new Date().toISOString(),
    probes,
    assignments: { _default: defaultExit, ...assignments },
  };
  await writeFile(HEALTH_FILE, JSON.stringify(matrix, null, 2));
  console.log("✓ Routes updated");
}

async function cmdStatus() {
  let raw: string;
  try {
    raw = await readFile(HEALTH_FILE, "utf-8");
  } catch {
    console.log("No health matrix. Run: bun proxy-manager.ts start");
    return;
  }
  const matrix: HealthMatrix = JSON.parse(raw);
  console.log(`Last probe: ${matrix.timestamp}\n`);

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
      if (!er) process.stdout.write("—".padEnd(col));
      else if (er.status === "ok") process.stdout.write("✓".padEnd(col));
      else process.stdout.write(`✗ ${er.status}`.substring(0, col - 2).padEnd(col));
    }
    console.log();
  }

  console.log("\nAssignments:");
  const def = matrix.assignments._default;
  console.log(`  (default) → ${def}`);
  for (const [eng, exit] of Object.entries(matrix.assignments)) {
    if (eng !== "_default") console.log(`  ${eng} → ${exit}`);
  }
}

async function cmdWatch() {
  console.log("Starting proxy manager in watch mode...\n");
  await cmdStart();

  const allExits = await discoverExits();
  console.log(`\nMonitoring every ${MONITOR_INTERVAL / 1000}s... (Ctrl-C to stop)\n`);

  while (true) {
    await Bun.sleep(MONITOR_INTERVAL);
    const ts = new Date().toISOString();

    // Tunnel health first
    process.stdout.write(`[${ts}] tunnel check...`);
    const revived = await restartDeadTunnels(allExits);
    if (revived > 0) {
      console.log(` ${revived} tunnel(s) restarted — re-probing`);
      await cmdProbe();
      continue;
    }
    console.log(" tunnels ok");

    // Engine health
    process.stdout.write(`[${ts}] engine check...`);
    try {
      const res = await fetch(`${SEARXNG_URL}/search?q=test&format=json`, {
        signal: AbortSignal.timeout(PROBE_TIMEOUT),
      });
      if (!res.ok) {
        console.log(` ⚠ HTTP ${res.status} — re-probing`);
        await cmdProbe();
        continue;
      }
      const data = (await res.json()) as { unresponsive_engines?: [string, string][] };
      const bad = data.unresponsive_engines ?? [];
      if (bad.length > 0) {
        console.log(` ⚠ ${bad.length} down — re-probing`);
        await cmdProbe();
      } else {
        console.log(" ✓ all healthy");
      }
    } catch (err: unknown) {
      console.log(` ✗ ${err instanceof Error ? err.message : err} — re-probing`);
      await cmdProbe();
    }
  }
}

function usage() {
  console.log(`Usage: bun proxy-manager.ts <command>

Commands:
  start   Start proxies, probe engines, apply optimal routes
  stop    Stop all wireproxy instances
  probe   Re-probe and re-optimise (proxies must be running)
  status  Show current health matrix and route assignments
  watch   Start + continuous monitoring (foreground)

Prerequisites:
  wireproxy   go install github.com/windtf/wireproxy/cmd/wireproxy@latest
  tor         brew install tor && brew services start tor
  searxng     ./setup.sh (container must be running)
  configs     Drop WireGuard .conf files into vpn-configs/
`);
}

// Cleanup on exit
process.on("SIGINT", async () => {
  console.log("\nShutting down...");
  await stopProxies();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  await stopProxies();
  process.exit(0);
});

const cmd = process.argv[2] ?? "help";
switch (cmd) {
  case "start": await cmdStart(); break;
  case "stop": await cmdStop(); break;
  case "probe": await cmdProbe(); break;
  case "status": await cmdStatus(); break;
  case "watch": await cmdWatch(); break;
  default: usage();
}
