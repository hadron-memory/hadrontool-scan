import 'dotenv/config';
import { z } from 'zod';

/**
 * Environment configuration, validated once at boot. Importing this module
 * throws (and the process exits non-zero) if the environment is invalid, so a
 * misconfigured container fails fast instead of half-working.
 *
 * clamd connectivity is deliberately NOT probed at boot (twilio posture for
 * optional providers): the tool starts, /readyz reports clamd reachability,
 * and /ops/scan answers a typed `engine_unavailable` verdict-error until the
 * daemon is up — a staged deploy is observable rather than a crash loop.
 */
const EnvSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().int().positive().default(8080),
  SCAN_TOOL_TOKEN: z.string().min(1).optional(),
  /** Host of the clamd daemon (its own container on komodo_default). */
  CLAMD_HOST: z.string().min(1).default('127.0.0.1'),
  CLAMD_PORT: z.coerce.number().int().positive().default(3310),
  /**
   * Hard ceiling on bytes accepted per scan. Must be ≥ the platform's asset
   * size cap (25 MB) and ≤ clamd's StreamMaxLength, or clean large files
   * read as engine errors. Default leaves headroom over the platform cap.
   */
  SCAN_MAX_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(26 * 1024 * 1024),
  /**
   * SSRF hatch for self-hosted / dev deployments where the object store
   * resolves to a private address (local MinIO). The hosted platform leaves
   * this unset: presigned URLs there point at a public endpoint, and a
   * fetch-capable tool on the internal network must not be steerable at
   * internal services (hadrontool-home-assistant's supported-posture shape).
   */
  SCAN_ALLOW_PRIVATE_NETWORKS: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
});

const parsed = EnvSchema.safeParse(process.env);
if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error(
    'Invalid environment configuration:',
    z.flattenError(parsed.error).fieldErrors,
  );
  process.exit(1);
}

const env = parsed.data;
const isProduction = env.NODE_ENV === 'production';

// Refuse to run an unauthenticated scan endpoint in production — an open
// fetch-and-scan op inside the private network is a free byte-exfiltration
// primitive for anything that can reach it.
if (isProduction && !env.SCAN_TOOL_TOKEN) {
  // eslint-disable-next-line no-console
  console.error(
    'SCAN_TOOL_TOKEN must be set when NODE_ENV=production. Refusing to start.',
  );
  process.exit(1);
}

export const VERSION = '0.1.0';

export const config = {
  nodeEnv: env.NODE_ENV,
  isProduction,
  port: env.PORT,
  serviceToken: env.SCAN_TOOL_TOKEN,
  clamd: { host: env.CLAMD_HOST, port: env.CLAMD_PORT },
  maxBytes: env.SCAN_MAX_BYTES,
  allowPrivateNetworks: env.SCAN_ALLOW_PRIVATE_NETWORKS,
} as const;
