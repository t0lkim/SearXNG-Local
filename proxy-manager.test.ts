// Run with: SEARXNG_RUNTIME=podman bun test
// (forces the Podman addressing path so tests never call the container CLI)
import { expect, test } from "bun:test";
import { proxyUrl, classifyTunnel, optimise, settingsOptimal, textSince, restartDue, parseRuntimeStatus, BLACKHOLE_PROXY, type Exit } from "./proxy-manager.ts";

const exits: Exit[] = [
  { name: "tor", type: "tor", port: 9050 },
  { name: "de-1", type: "vpn", port: 10900, configFile: "x", country: "DE" },
  { name: "fr-2", type: "vpn", port: 10901, configFile: "y", country: "FR" },
];

test("settings use exactly the proxy URL the probe uses", () => {
  const yaml = settingsOptimal("k", exits, { qwant: "fr-2" }, "de-1");
  expect(yaml).toContain(`- "${proxyUrl(exits[1])}"`);
  expect(yaml).toContain(`- "${proxyUrl(exits[2])}"`);
  expect(yaml.match(/socks5h:\/\/[^"]+/g)!.every(u => exits.some(e => proxyUrl(e) === u))).toBe(true);
});

test("a tunnel exiting with the host's own IP is bypass, never up", () => {
  expect(classifyTunnel({ ok: true, ip: "203.0.113.9", loc: "SG" }, "203.0.113.9").status).toBe("bypass");
});

test("a tunnel with no data is down", () => {
  expect(classifyTunnel({ ok: false, detail: "Timeout" }, "203.0.113.9").status).toBe("down");
});

test("a tunnel is up only with an exit IP that differs from the host's", () => {
  const t = classifyTunnel({ ok: true, ip: "198.51.100.4", loc: "DE" }, "203.0.113.9");
  expect(t.status).toBe("up");
  expect(t.exitIp).toBe("198.51.100.4");
  expect(t.loc).toBe("DE");
});

test("an unknown host IP means bypass cannot be ruled out", () => {
  expect(classifyTunnel({ ok: true, ip: "198.51.100.4" }, null).status).toBe("unverified");
});

test("no up tunnels means no default exit", () => {
  expect(optimise([])).toEqual({ assignments: {}, defaultExit: null });
});

test("a tunnel that carries data stays the default even when every engine blocks it", () => {
  const r = optimise([{ exit: "de-1", engines: [{ engine: "bing", status: "blocked" }] }]);
  expect(r.defaultExit).toBe("de-1");
});

test("engines route to an exit where they work", () => {
  const r = optimise([
    { exit: "de-1", engines: [{ engine: "a", status: "ok" }, { engine: "b", status: "ok" }, { engine: "q", status: "blocked" }] },
    { exit: "fr-2", engines: [{ engine: "q", status: "ok" }] },
  ]);
  expect(r.defaultExit).toBe("de-1");
  expect(r.assignments).toEqual({ q: "fr-2" });
});

test("with no default exit, settings still send everything through a proxy (blackhole)", () => {
  const yaml = settingsOptimal("k", exits, {}, null);
  expect(yaml).toContain(`proxies:\n    "all://":\n      - "${BLACKHOLE_PROXY}"`);
  expect(yaml).not.toContain("networks:");
});

test("settings never route an engine to an unknown exit", () => {
  const yaml = settingsOptimal("k", exits, { qwant: "gone-9" }, "de-1");
  expect(yaml).not.toContain("gone-9");
});

test("radio browser is removed: its init() resolves DNS outside the proxy", () => {
  expect(settingsOptimal("k", exits, {}, "de-1")).toContain("remove:\n      - radio browser");
});

test("log text after a byte offset survives multi-byte characters (restart handshake detection)", () => {
  const old = "DEBUG: peer(UR8v…89D8) - Receiving keepalive packet\n".repeat(500);
  const fresh = "DEBUG: peer(UR8v…89D8) - Received handshake response\n";
  const buf = Buffer.from(old + fresh);
  expect(textSince(buf, Buffer.byteLength(old))).toBe(fresh);
});

test("a tunnel that stays dead is restarted on cycles 1, 2, 4, 8, 16, then every 12", () => {
  const due: number[] = [];
  for (let cycle = 1; cycle <= 40; cycle++) if (restartDue("dead-1")) due.push(cycle);
  expect(due).toEqual([1, 2, 4, 8, 16, 28, 40]);
});

// Real `container system status` output, captured 2026-09-30 (client 1.5.0)
test("runtime status: down only when status says so, running only when it says so", () => {
  expect(parseRuntimeStatus(1, "apiserver is not running and not registered with launchd")).toBe("down");
  expect(parseRuntimeStatus(0, "FIELD               VALUE\nstatus              running\nclient.version      1.5.0")).toBe("running");
  // Anything else is unknown, and unknown never starts the runtime
  expect(parseRuntimeStatus(0, "")).toBe("unknown");
  expect(parseRuntimeStatus(1, "XPC connection error: Connection invalid")).toBe("unknown");
  expect(parseRuntimeStatus(1, "status              running")).toBe("unknown");
});
