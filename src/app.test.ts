/**
 * End-to-end app tests: supertest → /ops/scan → real fetch of a local
 * byte server → fake clamd. Env is pinned BEFORE the config-importing
 * modules load (config validates at import), hence the dynamic imports.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { startFakeClamd, type FakeClamd } from './testutil/fakeClamd.js';

const TOKEN = 'test-bearer';
let fake: FakeClamd;
let byteServer: http.Server;
let bytesBase: string;
let app: import('express').Express;

beforeAll(async () => {
  fake = await startFakeClamd();

  byteServer = http.createServer((req, res) => {
    if (req.url === '/clean.bin') {
      res.writeHead(200).end(Buffer.from('perfectly ordinary bytes'));
    } else if (req.url === '/infected.bin') {
      res.writeHead(200).end(Buffer.from('X5O!...EICAR-STANDARD-ANTIVIRUS-TEST-FILE!...'));
    } else if (req.url === '/huge.bin') {
      res.writeHead(200);
      res.end(Buffer.alloc(2048, 0x41));
    } else {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((r) => byteServer.listen(0, '127.0.0.1', r));
  bytesBase = `http://127.0.0.1:${(byteServer.address() as AddressInfo).port}`;

  // Local byte server + fake clamd live on loopback — the dev/self-hosted
  // posture the flag exists for.
  process.env.SCAN_ALLOW_PRIVATE_NETWORKS = 'true';
  process.env.CLAMD_HOST = '127.0.0.1';
  process.env.CLAMD_PORT = String(fake.port);
  process.env.SCAN_MAX_BYTES = '1024';
  const { createApp } = await import('./app.js');
  app = createApp({ serviceToken: TOKEN });
});

afterAll(async () => {
  await fake.close();
  await new Promise<void>((r) => byteServer.close(() => r()));
});

const auth = { authorization: `Bearer ${TOKEN}` };

describe('auth + surface', () => {
  it('serves /healthz without auth', async () => {
    await request(app).get('/healthz').expect(200, { status: 'ok' });
  });

  it('is ready when clamd pings', async () => {
    const res = await request(app).get('/readyz').expect(200);
    expect(res.body.status).toBe('ok');
  });

  it('401s /info and /ops without the bearer', async () => {
    await request(app).get('/info').expect(401);
    await request(app).post('/ops/scan').send({ url: 'x' }).expect(401);
  });

  it('describes itself on /info', async () => {
    const res = await request(app).get('/info').set(auth).expect(200);
    expect(res.body).toMatchObject({
      name: 'hadrontool-scan',
      contract: 'scan@1',
      operations: ['scan'],
      engine: { name: 'clamav', reachable: true },
    });
  });

  it('404s unknown operations with the catalog', async () => {
    const res = await request(app).post('/ops/frobnicate').set(auth).send({}).expect(404);
    expect(res.body.operations).toEqual(['scan']);
  });

  it('400s malformed input', async () => {
    const res = await request(app).post('/ops/scan').set(auth).send({}).expect(400);
    expect(res.body.error).toBe('validation_error');
  });

  it('400s an unparseable or non-http url (contract: malformed input is 4xx)', async () => {
    for (const url of ['not a url', 'file:///etc/passwd']) {
      const res = await request(app).post('/ops/scan').set(auth).send({ url }).expect(400);
      expect(res.body.error).toBe('validation_error');
    }
  });
});

describe('scan verdicts', () => {
  it('returns clean for clean bytes', async () => {
    const res = await request(app)
      .post('/ops/scan')
      .set(auth)
      .send({ url: `${bytesBase}/clean.bin`, filename: 'clean.bin' })
      .expect(200);
    expect(res.body).toMatchObject({ contract: 'scan@1', verdict: 'clean' });
    expect(res.body.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('returns infected with the signature', async () => {
    const res = await request(app)
      .post('/ops/scan')
      .set(auth)
      .send({ url: `${bytesBase}/infected.bin` })
      .expect(200);
    expect(res.body).toMatchObject({
      verdict: 'infected',
      signature: 'Eicar-Signature',
    });
  });

  it('returns a retryable error verdict when the object fetch 404s', async () => {
    const res = await request(app)
      .post('/ops/scan')
      .set(auth)
      .send({ url: `${bytesBase}/missing.bin` })
      .expect(200);
    expect(res.body.verdict).toBe('error');
    expect(res.body.message).toMatch(/404/);
  });

  it('refuses a declared size over the cap without fetching', async () => {
    const res = await request(app)
      .post('/ops/scan')
      .set(auth)
      .send({ url: `${bytesBase}/clean.bin`, sizeBytes: 10_000_000 })
      .expect(200);
    expect(res.body.verdict).toBe('error');
    expect(res.body.message).toMatch(/SCAN_MAX_BYTES/);
  });

  it('caps an oversized stream mid-flight', async () => {
    const res = await request(app)
      .post('/ops/scan')
      .set(auth)
      .send({ url: `${bytesBase}/huge.bin` })
      .expect(200);
    expect(res.body.verdict).toBe('error');
  });
});
