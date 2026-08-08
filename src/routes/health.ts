import { Router } from 'express';
import { config } from '../config.js';
import { ping } from '../clamd.js';

export const healthRouter = Router();

/** Liveness — the process is up and the event loop is responsive. */
healthRouter.get('/healthz', (_req, res) => {
  res.json({ status: 'ok' });
});

/**
 * Readiness — unlike the fully stateless siblings, this tool depends on a
 * daemon: ready means clamd answers PONG (signatures loaded). A booting
 * clamd takes ~30-60s to load its database; report 503 until then so a
 * deploy gate can wait on the real capability.
 */
healthRouter.get('/readyz', async (_req, res) => {
  const ok = await ping(config.clamd);
  res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'engine_unavailable' });
});
