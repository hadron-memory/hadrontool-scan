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
 * engine/fetch trouble; only malformed input (unparseable/non-http URL
 * included — PR-1 review, Copilot) is a 4xx.
 *
 * SSRF enforcement is connection-time: the fetch goes through an undici
 * dispatcher whose DNS lookup rejects non-public addresses on EVERY
 * resolution (rebinding-proof), plus a literal-IP pre-check for URLs
 * that never hit DNS. See urlGuard.ts (PR-1 review, Codex/Copilot P1).
 */

import { Readable, Transform } from 'node:stream';
import { fetch as undiciFetch, type Dispatcher } from 'undici';
import { z } from 'zod';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { scanStream, version, type ClamdScanResult } from '../clamd.js';
import {
  assertUrlAddressAllowed,
  buildDispatcher,
  parseScanUrl,
} from '../urlGuard.js';

export const ScanInput = z.object({
  /** Presigned GET URL minted by core. Treated as a live credential —
   * never logged. Shape-validated here so a malformed URL is a 400
   * validation error, not a retryable engine error. */
  url: z
    .string()
    .min(1)
    .superRefine((raw, ctx) => {
      try {
        parseScanUrl(raw);
      } catch (err) {
        ctx.addIssue({ code: 'custom', message: (err as Error).message });
      }
    }),
  /** Advisory size from the Asset row; the streaming cap is enforced
   * regardless. */
  sizeBytes: z.number().int().positive().optional(),
  /** Advisory, for log correlation only (never sent to the engine). */
  filename: z.string().max(512).optional(),
});
export type ScanInputT = z.infer<typeof ScanInput>;

const FETCH_TIMEOUT_MS = 45_000;

/** One shared dispatcher — the guard lives in its connect.lookup. */
const dispatcher: Dispatcher = buildDispatcher(config.allowPrivateNetworks);

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

  const url = parseScanUrl(input.url); // already zod-validated; cannot throw
  try {
    // Literal-IP hosts never hit DNS, so the dispatcher's lookup guard
    // cannot see them — classify them here. An address refusal is an
    // error VERDICT (not a 4xx): it is config-dependent (a self-hosted
    // deployment fixes it via SCAN_ALLOW_PRIVATE_NETWORKS + retry).
    assertUrlAddressAllowed(url, config.allowPrivateNetworks);
  } catch (err) {
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
  let res: Awaited<ReturnType<typeof undiciFetch>>;
  try {
    // Presigned URLs never redirect; following one could bypass the guard.
    res = await undiciFetch(url, {
      redirect: 'error',
      signal: controller.signal,
      dispatcher,
    });
  } catch (err) {
    clearTimeout(timer);
    return respond({
      verdict: 'error',
      message: controller.signal.aborted
        ? 'fetching the object timed out'
        : `object fetch failed: ${truncateError(err)}`,
    });
  }

  if (!res.ok || !res.body) {
    clearTimeout(timer);
    await res.body?.cancel().catch(() => {});
    return respond({
      verdict: 'error',
      message: `object fetch answered ${res.status}`,
    });
  }

  const source = Readable.fromWeb(res.body as import('node:stream/web').ReadableStream);
  const capped = source.pipe(byteCap(config.maxBytes));
  // Bidirectional teardown, attached BEFORE any await (PR-1 review):
  // pipe() does not propagate source errors to the destination, so a
  // fetch-body failure or the abort above would otherwise leave the
  // clamd pump waiting for an 'end' that never comes — and a cap error
  // must cancel the upstream response or its socket lingers.
  source.once('error', (e) => capped.destroy(e));
  capped.once('error', () => source.destroy());
  try {
    const result = await scanStream(config.clamd, capped);
    logger.info('scan finished', {
      verdict: result.verdict,
      bytes: input.sizeBytes,
      durationMs: Date.now() - startedAt,
    });
    return respond(result);
  } finally {
    clearTimeout(timer);
    // Covers every early-return path inside scanStream (e.g. clamd
    // unreachable, which destroys only the capped stream): make sure
    // the fetch body and its socket are released. Idempotent.
    source.destroy();
    capped.destroy();
  }
}

/** Compact an arbitrary fetch error for the response envelope — never
 * include the URL (its query string is a live credential). */
function truncateError(err: unknown): string {
  const msg = err instanceof Error ? `${err.message}${err.cause instanceof Error ? `: ${err.cause.message}` : ''}` : String(err);
  return msg.slice(0, 300);
}
