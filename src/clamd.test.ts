import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Readable } from 'node:stream';
import { ping, scanStream, version, parseScanReply } from './clamd.js';
import { startFakeClamd, type FakeClamd } from './testutil/fakeClamd.js';

let fake: FakeClamd;

beforeAll(async () => {
  fake = await startFakeClamd();
});
afterAll(async () => {
  await fake.close();
});

const addr = () => ({ host: '127.0.0.1', port: fake.port });

describe('parseScanReply', () => {
  it('maps the three reply families', () => {
    expect(parseScanReply('stream: OK')).toEqual({ verdict: 'clean' });
    expect(parseScanReply('stream: Eicar-Signature FOUND')).toEqual({
      verdict: 'infected',
      signature: 'Eicar-Signature',
    });
    expect(parseScanReply('INSTREAM size limit exceeded. ERROR').verdict).toBe(
      'error',
    );
    expect(parseScanReply('').verdict).toBe('error');
  });
});

describe('clamd client against a fake daemon', () => {
  it('pings', async () => {
    expect(await ping(addr())).toBe(true);
  });

  it('reports the engine version', async () => {
    expect(await version(addr())).toContain('ClamAV');
  });

  it('scans a clean stream', async () => {
    const result = await scanStream(addr(), Readable.from([Buffer.from('hello world')]));
    expect(result).toEqual({ verdict: 'clean' });
  });

  it('flags an infected stream with the signature name', async () => {
    const result = await scanStream(
      addr(),
      Readable.from([Buffer.from('X5O!...EICAR-STANDARD-ANTIVIRUS-TEST-FILE!...')]),
    );
    expect(result).toEqual({ verdict: 'infected', signature: 'Eicar-Signature' });
  });

  it('frames multi-chunk streams correctly', async () => {
    const chunks = ['aaa', 'bbb', 'EIC', 'AR', 'ccc'].map((s) => Buffer.from(s));
    const result = await scanStream(addr(), Readable.from(chunks));
    expect(result).toEqual({ verdict: 'infected', signature: 'Eicar-Signature' });
  });

  it('returns an error verdict when the daemon is unreachable', async () => {
    const result = await scanStream(
      { host: '127.0.0.1', port: 1 },
      Readable.from([Buffer.from('x')]),
    );
    expect(result.verdict).toBe('error');
    expect(await ping({ host: '127.0.0.1', port: 1 })).toBe(false);
  });
});
