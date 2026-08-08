import express, {
  type Express,
  type NextFunction,
  type Request,
  type Response,
} from 'express';
import { config, VERSION } from './config.js';
import { logger } from './logger.js';
import { requireAuth } from './middleware/auth.js';
import { healthRouter } from './routes/health.js';
import { opsRouter } from './routes/ops.js';
import { ping, version } from './clamd.js';

export interface AppOptions {
  /** Override the bearer token (tests); defaults to config. */
  serviceToken?: string;
}

/**
 * Build the Express app. Exported separately from the server bootstrap so
 * tests can exercise it with supertest without binding a port.
 */
export function createApp(options: AppOptions = {}): Express {
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  app.use(healthRouter);

  const auth = requireAuth(options.serviceToken ?? config.serviceToken);

  app.get('/info', auth, async (_req, res) => {
    const reachable = await ping(config.clamd);
    res.json({
      name: 'hadrontool-scan',
      version: VERSION,
      operations: ['scan'],
      contract: 'scan@1',
      stateless: true,
      engine: {
        name: 'clamav',
        reachable,
        ...(reachable ? { version: await version(config.clamd) } : {}),
      },
      maxBytes: config.maxBytes,
    });
  });

  app.use('/ops', auth, opsRouter());

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    const status =
      (err as { status?: number })?.status ?? (err as { statusCode?: number })?.statusCode;
    if (typeof status === 'number') {
      res.status(status).json({ error: 'bad_request', message: (err as Error).message });
      return;
    }
    logger.error('unhandled error', {
      err: String((err as Error)?.message ?? err).slice(0, 200),
      path: req.path,
    });
    res.status(500).json({ error: 'internal_error' });
  });

  return app;
}
