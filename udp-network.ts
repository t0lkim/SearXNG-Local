// UDP resilience: which WireGuard port gets through on the current network, detected before tunnels
// start, plus an evidence log of every network the tunnels ran on.
//
// Ports are Proton endpoint ports proven to carry WireGuard data (2026-09-29): 53 first, because
// networks that restrict UDP almost always leave DNS open, so tunnels on 53 survive a filter that
// switches on mid-session. 123 handshakes but carries no data, so it is not in the ladder.

import { appendFile, readFile, writeFile, rm } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { join } from "node:path";

export const PORT_LADDER = [53, 51820, 443, 4500, 1224, 88, 500];
const HANDSHAKE_WAIT = 5_000;
// TEST-NET-2 (RFC 5737): no DNS server exists there, so any answer means port 53 is being intercepted
const NO_DNS_ADDRESS = "198.51.100.1";

export interface NetInfo { iface: string | null; gateway: string | null; localIp: string | null; mac: string | null }
export type NetClass = "open" | "dns-only" | "restricted" | "blocked";

export interface Detection {
  at: string;
  ports: Record<number, boolean>;
  dnsIntercepted: boolean | null;
  netClass: NetClass;
  chosenPort: number | null;
}

async function out(argv: string[], timeout = 5_000): Promise<string> {
  try {
    const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" });
    const text = new Response(proc.stdout).text();
    const done = await Promise.race([proc.exited, Bun.sleep(timeout).then(() => "timeout" as const)]);
    if (done === "timeout") { proc.kill(9); return ""; }
    return await text;
  } catch { return ""; }
}

export async function currentNetwork(): Promise<NetInfo> {
  const route = await out(["route", "-n", "get", "default"]);
  const iface = route.match(/interface:\s*(\S+)/)?.[1] ?? null;
  const gateway = route.match(/gateway:\s*(\S+)/)?.[1] ?? null;
  const localIp = iface ? (await out(["ipconfig", "getifaddr", iface])).trim() || null : null;
  const mac = iface ? (await out(["ifconfig", iface])).match(/ether\s+([0-9a-f:]{17})/i)?.[1] ?? null : null;
  return { iface, gateway, localIp, mac };
}

// Same network means same gateway and same local address; a new DHCP lease with a new address counts as a change
export function networkKey(n: NetInfo): string {
  return `${n.iface}|${n.gateway}|${n.localIp}`;
}

export function parseDigAnswer(digOutput: string): boolean {
  return digOutput.split("\n").some(l => /^\d{1,3}(\.\d{1,3}){3}$/.test(l.trim()));
}

export async function dnsIntercepted(): Promise<boolean | null> {
  const r = await out(["dig", `@${NO_DNS_ADDRESS}`, "example.com", "+time=2", "+tries=1", "+short"], 6_000);
  if (!r) return null;
  return parseDigAnswer(r);
}

export function classify(ports: Record<number, boolean>): { netClass: NetClass; chosenPort: number | null } {
  const chosenPort = PORT_LADDER.find(p => ports[p]) ?? null;
  const netClass: NetClass = ports[51820] ? "open"
    : ports[53] && !PORT_LADDER.some(p => p !== 53 && ports[p]) ? "dns-only"
    : chosenPort !== null ? "restricted"
    : "blocked";
  return { netClass, chosenPort };
}

// Rewrites a wireproxy config's Endpoint port and SOCKS bind for a throwaway probe
export function withEndpointPort(conf: string, port: number, bind?: string): string {
  let s = conf.replace(/^(Endpoint\s*=\s*[^:\s]+):\d+\s*$/m, `$1:${port}`);
  if (bind) s = s.replace(/^BindAddress\s*=.*$/m, `BindAddress = ${bind}`);
  return s;
}

// Tries each ladder port with one throwaway tunnel. The caller guarantees no live tunnel uses this key:
// two sessions with one key make the server roam between them and disrupt the live one.
export async function detectPorts(conf: string, wireproxyBin: string, workDir: string): Promise<Detection> {
  const ports: Record<number, boolean> = {};
  const probeConf = join(workDir, "udp-probe.conf");
  const probeLog = join(workDir, "udp-probe.log");
  for (const port of PORT_LADDER) {
    await writeFile(probeConf, withEndpointPort(conf, port, "127.0.0.1:19899"), { mode: 0o600 });
    await writeFile(probeLog, "", { mode: 0o600 });
    const fd = openSync(probeLog, "a");
    const proc = Bun.spawn([wireproxyBin, "-c", probeConf], { stdout: "ignore", stderr: fd });
    closeSync(fd);
    let ok = false;
    const deadline = Date.now() + HANDSHAKE_WAIT;
    while (Date.now() < deadline && proc.exitCode === null) {
      await Bun.sleep(200);
      if ((await readFile(probeLog, "utf-8")).includes("Received handshake response")) { ok = true; break; }
    }
    proc.kill(9);
    await Promise.race([proc.exited, Bun.sleep(2_000)]);
    ports[port] = ok;
  }
  await rm(probeConf, { force: true });
  await rm(probeLog, { force: true });
  const intercepted = await dnsIntercepted();
  return { at: new Date().toISOString(), ports, dnsIntercepted: intercepted, ...classify(ports) };
}

export async function recordEvidence(file: string, event: string, net: NetInfo, extra: Record<string, unknown>): Promise<void> {
  const line = JSON.stringify({ at: new Date().toISOString(), event, ...net, ...extra });
  await appendFile(file, line + "\n", { mode: 0o600 });
}
