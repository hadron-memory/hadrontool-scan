/**
 * SSRF guard for the scan URL. The only caller is hadron-server over the
 * bearer-gated internal plane, and the URL it sends is a presigned GET it
 * minted itself — but a fetch-capable service must still refuse to be
 * steered at private sockets, so a compromised or misconfigured caller
 * can't turn /ops/scan into an internal-network byte reader
 * (capability-tool pattern: SSRF-guard if it fetches URLs).
 *
 * SCAN_ALLOW_PRIVATE_NETWORKS=true is the supported self-hosted/dev
 * posture (local MinIO), mirroring hadrontool-home-assistant's flag.
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

function isPrivateV4(ip: string): boolean {
  const o = ip.split('.').map(Number);
  return (
    o[0] === 10 ||
    o[0] === 127 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    (o[0] === 169 && o[1] === 254) || // link-local / cloud metadata
    o[0] === 0
  );
}

function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique-local fc00::/7
  if (lower.startsWith('fe80')) return true; // link-local
  if (lower.startsWith('::ffff:')) return isPrivateV4(lower.slice(7)); // v4-mapped
  return false;
}

function isPrivateAddress(ip: string): boolean {
  return isIP(ip) === 4 ? isPrivateV4(ip) : isPrivateV6(ip);
}

/**
 * Validate the scan URL. Returns the parsed URL or throws a message safe
 * to surface to the (internal) caller. When private networks are blocked,
 * every resolved address must be public — one private A record fails the
 * whole URL (no lucky-resolution roulette).
 */
export async function assertFetchableUrl(
  raw: string,
  allowPrivateNetworks: boolean,
): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('url is not a valid URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('url must be http(s)');
  }
  if (allowPrivateNetworks) return url;

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) {
    if (isPrivateAddress(host)) throw new Error('url resolves to a private address');
    return url;
  }
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host, { all: true });
  } catch {
    throw new Error('url hostname does not resolve');
  }
  if (addresses.length === 0 || addresses.some((a) => isPrivateAddress(a.address))) {
    throw new Error('url resolves to a private address');
  }
  return url;
}
