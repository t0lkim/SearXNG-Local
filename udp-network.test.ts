import { expect, test } from "bun:test";
import { PORT_LADDER, classify, networkKey, parseDigAnswer, withEndpointPort } from "./udp-network.ts";

const all = (v: boolean) => Object.fromEntries(PORT_LADDER.map(p => [p, v]));

test("port 53 is tried first, so tunnels survive a DNS-only filter that appears later", () => {
  expect(PORT_LADDER[0]).toBe(53);
  expect(PORT_LADDER).not.toContain(123);
});

test("open network: 51820 works, tunnels still use 53", () => {
  expect(classify(all(true))).toEqual({ netClass: "open", chosenPort: 53 });
});

test("DNS-only network: only 53 works", () => {
  expect(classify({ ...all(false), 53: true })).toEqual({ netClass: "dns-only", chosenPort: 53 });
});

test("53 blocked but WireGuard's port open: falls back to 51820", () => {
  expect(classify({ ...all(true), 53: false })).toEqual({ netClass: "open", chosenPort: 51820 });
});

test("only an unusual port works: restricted, uses it", () => {
  expect(classify({ ...all(false), 4500: true })).toEqual({ netClass: "restricted", chosenPort: 4500 });
});

test("nothing works: blocked, no port chosen", () => {
  expect(classify(all(false))).toEqual({ netClass: "blocked", chosenPort: null });
});

test("endpoint port and probe bind are rewritten, nothing else", () => {
  const conf = "[Interface]\nAddress = 198.51.100.2/32\n[Peer]\nEndpoint = 203.0.113.7:51820\n\n[Socks5]\nBindAddress = 192.0.2.1:10882\n";
  const out = withEndpointPort(conf, 53, "127.0.0.1:19899");
  expect(out).toContain("Endpoint = 203.0.113.7:53");
  expect(out).toContain("BindAddress = 127.0.0.1:19899");
  expect(out).toContain("Address = 198.51.100.2/32");
});

test("an answer from an address with no DNS server means interception", () => {
  expect(parseDigAnswer("93.184.215.14\n")).toBe(true);
  expect(parseDigAnswer(";; connection timed out; no servers could be reached\n")).toBe(false);
});

test("a new DHCP address on the same gateway counts as a new network", () => {
  const a = { iface: "en0", gateway: "gw", localIp: "a", mac: "m" };
  expect(networkKey(a)).not.toBe(networkKey({ ...a, localIp: "b" }));
  expect(networkKey(a)).toBe(networkKey({ ...a, mac: "other" }));
});
