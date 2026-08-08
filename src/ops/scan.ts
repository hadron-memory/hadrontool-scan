/**
 * The one operation: POST /ops/scan — fetch already-authorized bytes from a
 * presigned GET URL and stream them into clamd.
 *
 * Contract `scan@1` (provider-neutral: nothing in the envelope names
 * ClamAV except the informational `engine` block, so a hosted engine can
 * replace this implementation without touching hadron-server):
 *
 *   request  { url: string, sizeBytes?: number, filename?: string }
 *   response { contract: 'scan@1',
 *              verdict: 'clean' | 'infected' | 'error',
 *              signature?: string,          // infected only
 *              message?: string,            // error only
 *              engine: { name, version? },
 *              durationMs: number }
 *
 * A verdict of 'error' is RETRYABLE by contract — core leaves the asset
 * PENDING and its sweep retries. This op therefore never throws for
 * engine/fetch trouble; only malformed input is a 4xx.
 */

import { Readable, Transform } from 'node:stream';
import { z } from 'zod';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { scanStream, version, type ClamdScanResult } from '../clamd.js';
import { assertFetchableUrl } from '../urlGuard.js';

export const ScanInput = z.object({
  /** Presigned GET URL minted by core. Treated as a live credential —
   * never logged. */
  url: z.string().min(1),
  /** Advisory size from the Asset row; the streaming cap is enforced
   * regardless. */
  sizeBytes: z.number().int().positive().optional(),
  /** Advisory, for log correlation only (never sent to the engine). */
  filename: z.string().max(512).optional(),
});
export type ScanInputT = z.infer<typeof ScanInput>;

const FETCH_TIMEOUT_MS = 45_000;

/** Cached engine version — refreshed lazily, absent while unreachable. */
let cachedVersion: string | null = null;
async function engineVersion(): Promise<string | null> {
  cachedVersion = cachedVersion ?? (await version(config.clamd));
  return cachedVersion;
}

export interface ScanResponse {
  contract: 'scan@1';
  verdict: 'clean' | 'infected' | 'error';
  signature?: string;
  message?: string;
  engine: { name: 'clamav'; version?: string };
  durationMs: number;
}

/** Byte-counting pass-through that destroys the pipeline past a cap. */
function byteCap(maxBytes: number): Transform {
  let seen = 0;
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      seen += chunk.length;
      if (seen > maxBytes) {
        cb(new Error(`stream exceeds SCAN_MAX_BYTES (${maxBytes})`));
        return;
      }
      cb(null, chunk);
    },
  });
}

export async function scanOperation(input: ScanInputT): Promise<ScanResponse> {
  const startedAt = Date.now();
  const respond = (result: ClamdScanResult): ScanResponse => ({
    contract: 'scan@1',
    verdict: result.verdict,
    ...(result.verdict === 'infected' ? { signature: result.signature } : {}),
    ...(result.verdict === 'error' ? { message: result.message } : {}),
    engine: { name: 'clamav', ...(cachedVersion ? { version: cachedVersion } : {}) },
    durationMs: Date.now() - startedAt,
  });

  let url: URL;
  try {
    url = await assertFetchableUrl(input.url, config.allowPrivateNetworks);
  } catch (err) {
    // Guard refusals are input problems, not engine trouble — but they are
    // still delivered as an error VERDICT so core's retry posture applies
    // uniformly (a misconfigured dev MinIO fixes itself via env + retry).
    return respond({ verdict: 'error', message: (err as Error).message });
  }

  if (input.sizeBytes && input.sizeBytes > config.maxBytes) {
    return respond({
      verdict: 'error',
      message: `declared size ${input.sizeBytes} exceeds SCAN_MAX_BYTES (${config.maxBytes})`,
    });
  }

  void (await engineVersion()); // warm the info block; harmless when down

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    // Presigned URLs never redirect; following one could bypass the guard.
    res = await fetch(url, { redirect: 'error', signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    return respond({
      verdict: 'error',
      message: controller.signal.aborted
        ? 'fetching the object timed out'
        : `object fetch failed: ${(err as Error).message}`,
    });
  }

  if (!res.ok || !res.body) {
    clearTimeout(timer);
    res.body?.cancel().catch(() => {});
    return respond({
      verdict: 'error',
      message: `object fetch answered ${res.status}`,
    });
  }

  try {
    const source = Readable.fromWeb(res.body as import('node:stream/web').ReadableStream);
    const capped = source.pipe(byteCap(config.maxBytes));
    // Attach BEFORE any await: data can start flowing the moment pipe()
    // runs, and a cap error with no listener yet is an uncaught
    // exception that kills the process. Also tears down the fetch.
    capped.once('error', () => source.destroy());
    const result = await scanStream(config.clamd, capped);
    logger.info('scan finished', {
      verdict: result.verdict,
      bytes: input.sizeBytes,
      durationMs: Date.now() - startedAt,
    });
    return respond(result);
  } finally {
    clearTimeout(timer);
  }
}
