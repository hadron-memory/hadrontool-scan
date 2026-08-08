import { describe, it, expect } from 'vitest';
import { assertFetchableUrl } from './urlGuard.js';

describe('assertFetchableUrl', () => {
  it('accepts a public https URL', async () => {
    const url = await assertFetchableUrl(
      'https://nbg1.your-objectstorage.com/bucket/key?sig=abc',
      false,
    );
    expect(url.hostname).toBe('nbg1.your-objectstorage.com');
  });

  it('rejects non-http(s) schemes', async () => {
    await expect(assertFetchableUrl('file:///etc/passwd', false)).rejects.toThrow(
      /http/,
    );
    await expect(assertFetchableUrl('gopher://x', false)).rejects.toThrow(/http/);
  });

  it('rejects garbage', async () => {
    await expect(assertFetchableUrl('not a url', false)).rejects.toThrow();
  });

  it('rejects private and loopback literals when the flag is off', async () => {
    for (const bad of [
      'http://127.0.0.1:9000/bucket/key',
      'http://10.0.0.5/k',
      'http://192.168.1.10/k',
      'http://172.16.0.1/k',
      'http://169.254.169.254/latest/meta-data', // cloud metadata
      'http://[::1]/k',
    ]) {
      await expect(assertFetchableUrl(bad, false)).rejects.toThrow(/private/);
    }
  });

  it('rejects hostnames resolving to private addresses (localhost)', async () => {
    await expect(assertFetchableUrl('http://localhost:9000/k', false)).rejects.toThrow(
      /private/,
    );
  });

  it('allows private addresses when the self-hosted flag is on', async () => {
    const url = await assertFetchableUrl('http://127.0.0.1:9000/bucket/key', true);
    expect(url.port).toBe('9000');
  });
});
