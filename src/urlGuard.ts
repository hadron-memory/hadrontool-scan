/**
 * SSRF guard for the scan URL. The only caller is hadron-server over the
 * bearer-gated internal plane, and the URL it sends is a presigned GET it
 * minted itself — but a fetch-capable service must still refuse to be
 * steered at private sockets, so a compromised or misconfigured caller
 * can't turn /ops/scan into an internal-network byte reader
 * (capability-tool pattern: SSRF-guard if it fetches URLs).
 *
 * Enforcement is CONNECTION-TIME, not check-time: `buildDispatcher`
 * returns an undici Agent whose lookup callback classifies every address
 * on every connection, so a DNS-rebinding hostname (public at validation,
 * private at connect) cannot slip through (PR-1 review, Codex/Copilot
 * P1). Address classification is CIDR-aware — the earlier prefix
 * string-matching missed IPv4-mapped IPv6 literals in canonical hex form
 * (`[::ffff:127.0.0.1]` serializes to `[::ffff:7f00:1]`) and special
 * ranges like CGNAT 100.64.0.0/10.
 *
 * SCAN_ALLOW_PRIVATE_NETWORKS=true is the supported self-hosted/dev
 * posture (local MinIO), mirroring hadrontool-home-assistant's flag.
 */

import dns from 'node:dns';
import { isIP } from 'node:net';
import { Agent, type Dispatcher } from 'undici';

/** IPv4 ranges that are not publicly routable destinations. */
const V4_DENY: Array<[number, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local / cloud metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 anycast
  ['192.168.0.0', 16],
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
].map(([net, bits]) => [v4ToInt(net as string), bits as number]);

function v4ToInt(ip: string): number {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return -1;
  }
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

function isPublicV4(ip: string): boolean {
  const v = v4ToInt(ip);
  if (v < 0) return false; // unparseable → fail closed
  return !V4_DENY.some(
    ([net, bits]) => (v >>> (32 - bits)) === (net >>> (32 - bits)),
  );
}

/** Expand an IPv6 literal to its 8 hextets, or null if unparseable. */
function v6Hextets(ip: string): number[] | null {
  let body = ip;
  // Trailing dotted-quad form (::ffff:127.0.0.1) → fold into two hextets.
  const dotted = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(body);
  if (dotted) {
    const v4 = v4ToInt(dotted[2]);
    if (v4 < 0) return null;
    body = `${dotted[1]}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = body.split('::');
  if (halves.length > 2) return null;
  const parse = (s: string) =>
    s === '' ? [] : s.split(':').map((h) => parseInt(h, 16));
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(missing).fill(0), ...tail];
  return groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)
    ? null
    : groups;
}

function isPublicV6(ip: string): boolean {
  const g = v6Hextets(ip);
  if (!g) return false; // unparseable → fail closed
  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96): classify the
  // embedded IPv4 — this is the canonical-hex bypass the review caught.
  const isMapped =
    g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff;
  const isNat64 = g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0;
  if (isMapped || isNat64) {
    const v4 = `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
    return isPublicV4(v4);
  }
  // Everything else: public ⇔ global unicast 2000::/3. Strictly tighter
  // than a denylist — loopback, unique-local, link-local, multicast,
  // documentation, and any future special range all fail closed.
  return (g[0] & 0xe000) === 0x2000;
}

/** True when `ip` (v4 or v6 literal) is a publicly routable address. */
export function isPublicAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPublicV4(ip);
  if (family === 6) return isPublicV6(ip);
  return false;
}

/**
 * Parse + shape-check the scan URL: must be a syntactically valid
 * http(s) URL. Throws on failure — the op maps this to a 400
 * validation error (malformed input is a caller bug, not retryable
 * engine trouble).
 */
export function parseScanUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('url is not a valid URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('url must be http(s)');
  }
  return url;
}

/**
 * Pre-connection literal check: an IP-literal hostname never hits DNS
 * (so the dispatcher's lookup guard cannot see it) and must be
 * classified here. Hostname URLs pass — the dispatcher guards their
 * every resolution. Throws on a refused address.
 */
export function assertUrlAddressAllowed(url: URL, allowPrivateNetworks: boolean): void {
  if (allowPrivateNetworks) return;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) && !isPublicAddress(host)) {
    throw new Error('url resolves to a private address');
  }
}

/** dns.lookup that fails unless EVERY resolved address is public — one
 * private A/AAAA record fails the whole name (no resolution roulette). */
export const guardedLookup: typeof dns.lookup = ((
  hostname: string,
  options: dns.LookupOptions | ((...a: never[]) => void),
  callback?: (...a: never[]) => void,
) => {
  const opts = (typeof options === 'function' ? {} : options) as dns.LookupOptions;
  const cb = (typeof options === 'function' ? options : callback) as (
    err: NodeJS.ErrnoException | null,
    address?: string | dns.LookupAddress[],
    family?: number,
  ) => void;
  dns.lookup(hostname, { ...opts, all: true }, (err, addresses) => {
    if (err) {
      cb(err);
      return;
    }
    const list = addresses as dns.LookupAddress[];
    if (list.length === 0 || list.some((a) => !isPublicAddress(a.address))) {
      const refuse = new Error(
        `refusing to connect: ${hostname} resolves to a non-public address`,
      ) as NodeJS.ErrnoException;
      refuse.code = 'EPRIVATEADDRESS';
      cb(refuse);
      return;
    }
    if (opts.all) cb(null, list);
    else cb(null, list[0].address, list[0].family);
  });
}) as unknown as typeof dns.lookup;

/**
 * Dispatcher for the scan fetch. With the guard on, every connection's
 * DNS resolution goes through guardedLookup — the rebinding-proof
 * enforcement point. With SCAN_ALLOW_PRIVATE_NETWORKS=true, a plain
 * agent (self-hosted/dev posture).
 */
export function buildDispatcher(allowPrivateNetworks: boolean): Dispatcher {
  return allowPrivateNetworks
    ? new Agent()
    : new Agent({ connect: { lookup: guardedLookup } });
}
