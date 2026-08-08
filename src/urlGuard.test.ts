import { describe, it, expect } from 'vitest';
import {
  parseScanUrl,
  isPublicAddress,
  assertUrlAddressAllowed,
  guardedLookup,
} from './urlGuard.js';

describe('parseScanUrl', () => {
  it('accepts http(s) URLs', () => {
    expect(parseScanUrl('https://nbg1.your-objectstorage.com/b/k?sig=abc').hostname).toBe(
      'nbg1.your-objectstorage.com',
    );
    expect(parseScanUrl('http://minio:9000/b/k').port).toBe('9000');
  });

  it('rejects non-http(s) schemes and garbage', () => {
    expect(() => parseScanUrl('file:///etc/passwd')).toThrow(/http/);
    expect(() => parseScanUrl('gopher://x')).toThrow(/http/);
    expect(() => parseScanUrl('not a url')).toThrow(/valid URL/);
  });
});

describe('isPublicAddress', () => {
  it('classifies private, special, and loopback v4 ranges as non-public', () => {
    for (const ip of [
      '127.0.0.1',
      '10.0.0.5',
      '192.168.1.10',
      '172.16.0.1',
      '169.254.169.254', // cloud metadata
      '100.64.0.1', // CGNAT (PR-1 review, Copilot)
      '0.0.0.0',
      '198.18.0.1',
      '224.0.0.1',
      '255.255.255.255',
    ]) {
      expect(isPublicAddress(ip), ip).toBe(false);
    }
  });

  it('classifies real public v4 as public', () => {
    for (const ip of ['8.8.8.8', '95.217.1.1', '198.17.255.255']) {
      expect(isPublicAddress(ip), ip).toBe(true);
    }
  });

  it('rejects v4-mapped v6 in BOTH dotted and canonical hex form', () => {
    // The PR-1 P1: URL canonicalizes [::ffff:127.0.0.1] to hex.
    expect(isPublicAddress('::ffff:127.0.0.1')).toBe(false);
    expect(isPublicAddress('::ffff:7f00:1')).toBe(false);
    expect(isPublicAddress('::ffff:a00:1')).toBe(false); // 10.0.0.1
    // Mapped PUBLIC v4 stays public.
    expect(isPublicAddress('::ffff:808:808')).toBe(true); // 8.8.8.8
  });

  it('rejects NAT64-embedded private v4', () => {
    expect(isPublicAddress('64:ff9b::7f00:1')).toBe(false);
    expect(isPublicAddress('64:ff9b::808:808')).toBe(true);
  });

  it('allows only global-unicast v6 otherwise', () => {
    expect(isPublicAddress('::1')).toBe(false);
    expect(isPublicAddress('::')).toBe(false);
    expect(isPublicAddress('fd12:3456::1')).toBe(false); // unique-local
    expect(isPublicAddress('fe80::1')).toBe(false); // link-local
    expect(isPublicAddress('ff02::1')).toBe(false); // multicast
    expect(isPublicAddress('2606:4700::1111')).toBe(true);
  });

  it('fails closed on non-IP input', () => {
    expect(isPublicAddress('localhost')).toBe(false);
    expect(isPublicAddress('')).toBe(false);
  });
});

describe('assertUrlAddressAllowed', () => {
  it('rejects private IP-literal hosts when the guard is on', () => {
    for (const bad of [
      'http://127.0.0.1:9000/b/k',
      'http://10.0.0.5/k',
      'http://169.254.169.254/latest/meta-data',
      'http://[::1]/k',
      'http://[::ffff:7f00:1]/k', // canonical-hex mapped loopback
    ]) {
      expect(() => assertUrlAddressAllowed(parseScanUrl(bad), false), bad).toThrow(
        /private/,
      );
    }
  });

  it('passes hostname URLs through (the dispatcher guards their DNS)', () => {
    expect(() =>
      assertUrlAddressAllowed(parseScanUrl('http://localhost:9000/k'), false),
    ).not.toThrow();
  });

  it('allows anything when the self-hosted flag is on', () => {
    expect(() =>
      assertUrlAddressAllowed(parseScanUrl('http://127.0.0.1:9000/b/k'), true),
    ).not.toThrow();
  });
});

describe('guardedLookup', () => {
  it('refuses hostnames that resolve to non-public addresses', async () => {
    await expect(
      new Promise((resolve, reject) =>
        guardedLookup('localhost', { all: false }, (err, address) =>
          err ? reject(err) : resolve(address),
        ),
      ),
    ).rejects.toThrow(/non-public/);
  });
});
