/**
 * Operations plane — POST /ops/<operation> (internal, bearer-gated).
 *
 * Every response is JSON. Engine/fetch trouble is a 200 with
 * `verdict: 'error'` (retryable by contract — core's sweep owns retries);
 * only malformed input is a 4xx. A scan is idempotent, so unlike the SMS
 * tool there is no retry hazard on the caller side.
 */

import { Router, type Response } from 'express';
import { ZodError, z } from 'zod';
import { logger } from '../logger.js';
import { ScanInput, scanOperation } from '../ops/scan.js';

function respondValidation(res: Response, err: ZodError): void {
  res.status(400).json({
    error: 'validation_error',
    message: 'Invalid input.',
    issues: z.flattenError(err).fieldErrors,
  });
}

export function opsRouter(): Router {
  const router = Router();

  router.post('/scan', async (req, res) => {
    let input;
    try {
      input = ScanInput.parse(req.body ?? {});
    } catch (err) {
      if (err instanceof ZodError) {
        respondValidation(res, err);
        return;
      }
      throw err;
    }
    try {
      res.status(200).json(await scanOperation(input));
    } catch (err) {
      // scanOperation maps expected trouble to error verdicts itself;
      // reaching here is a genuine bug. Log the class, not the input —
      // the URL is a live credential.
      logger.error('scan operation crashed', {
        err: String((err as Error)?.message ?? err).slice(0, 200),
      });
      res.status(500).json({ error: 'internal_error', message: 'Unexpected error.' });
    }
  });

  router.post('/:operation', (_req, res) => {
    res.status(404).json({
      error: 'unknown_operation',
      operations: ['scan'],
    });
  });

  return router;
}
