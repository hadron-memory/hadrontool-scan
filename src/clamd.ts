/**
 * Zero-dependency clamd TCP client (INSTREAM / PING / VERSION).
 *
 * Deliberately implements the wire protocol directly instead of pulling in
 * an npm wrapper: the protocol is ~50 lines and stable since ClamAV 0.9x,
 * while the wrapper ecosystem (clamscan, clamdjs, …) is thinly maintained —
 * a supply-chain surface this tool does not need.
 *
 * Protocol (z-delimited command family — NUL-terminated commands and
 * replies, immune to newline injection in signature names):
 *   zINSTREAM\0  then <4-byte BE length><chunk>… terminated by a zero
 *                length; reply "stream: OK" | "stream: <sig> FOUND" |
 *                "… ERROR".
 *   zPING\0      reply "PONG".
 *   zVERSION\0   reply e.g. "ClamAV 1.4.3/27500/…".
 *
 * https://docs.clamav.net/manual/Usage/Scanning.html#clamd
 */

import net from 'node:net';
import type { Readable } from 'node:stream';

export interface ClamdAddress {
  host: string;
  port: number;
}

export type ClamdScanResult =
  | { verdict: 'clean' }
  | { verdict: 'infected'; signature: string }
  | { verdict: 'error'; message: string };

const CONNECT_TIMEOUT_MS = 5_000;
/** Whole-scan ceiling — generous next to sub-second typical scans at the
 * 25 MB platform cap; the caller maps a timeout to a retryable error. */
const SCAN_TIMEOUT_MS = 50_000;

/** Read one NUL-terminated reply from an already-connected socket. */
function readReply(socket: net.Socket, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('clamd reply timed out'));
    }, timeoutMs);
    const finish = (err?: Error) => {
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(Buffer.concat(chunks).toString('utf8').replace(/\0.*$/s, '').trim());
    };
    socket.on('data', (d) => {
      chunks.push(d);
      if (d.includes(0)) {
        socket.end();
        finish();
      }
    });
    socket.on('error', (err) => finish(err));
    socket.on('close', () => {
      // Reply may have arrived without our having seen the NUL yet.
      if (chunks.length) finish();
      else finish(new Error('clamd closed the connection without replying'));
    });
  });
}

function connect(addr: ClamdAddress): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: addr.host, port: addr.port });
    socket.setNoDelay(true);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('clamd connect timed out'));
    }, CONNECT_TIMEOUT_MS);
    socket.once('connect', () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function command(addr: ClamdAddress, cmd: string): Promise<string> {
  const socket = await connect(addr);
  const reply = readReply(socket, CONNECT_TIMEOUT_MS);
  socket.write(`z${cmd}\0`);
  return reply;
}

/** True when clamd answers PONG (signatures loaded, ready to scan). */
export async function ping(addr: ClamdAddress): Promise<boolean> {
  try {
    return (await command(addr, 'PING')) === 'PONG';
  } catch {
    return false;
  }
}

/** Engine version string, or null when unreachable. */
export async function version(addr: ClamdAddress): Promise<string | null> {
  try {
    return await command(addr, 'VERSION');
  } catch {
    return null;
  }
}

/**
 * Stream bytes into clamd via INSTREAM and parse the verdict. The source
 * stream is consumed exactly once; backpressure from clamd propagates to
 * the source via the paused-mode pump below.
 */
export async function scanStream(
  addr: ClamdAddress,
  source: Readable,
): Promise<ClamdScanResult> {
  // Capture source failure SYNCHRONOUSLY, before the first await: a
  // piped transform (the caller's byte cap) can error while we are
  // still connecting, and an 'error' listener attached after the fact
  // never fires — the pump below would then wait forever.
  let earlyError: Error | undefined;
  source.on('error', (e: Error) => {
    earlyError = earlyError ?? e;
  });

  let socket: net.Socket;
  try {
    socket = await connect(addr);
  } catch (err) {
    source.destroy();
    return { verdict: 'error', message: `clamd unreachable: ${String(err)}` };
  }
  if (earlyError) {
    socket.destroy();
    return { verdict: 'error', message: `stream failed: ${String(earlyError)}` };
  }

  const replyPromise = readReply(socket, SCAN_TIMEOUT_MS);
  socket.write('zINSTREAM\0');

  try {
    await new Promise<void>((resolve, reject) => {
      if (earlyError) {
        reject(earlyError);
        return;
      }
      source.on('data', (chunk: Buffer | string) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (buf.length === 0) return;
        const frame = Buffer.allocUnsafe(4 + buf.length);
        frame.writeUInt32BE(buf.length, 0);
        buf.copy(frame, 4);
        if (!socket.write(frame)) {
          source.pause();
          socket.once('drain', () => source.resume());
        }
      });
      source.on('end', () => {
        socket.write(Buffer.from([0, 0, 0, 0]));
        resolve();
      });
      source.on('error', reject);
      // clamd aborts the stream (size limit, dead daemon) by closing; the
      // write side then errors — surface that as a reject, the reply
      // reader usually still yields the ERROR text below.
      socket.on('error', reject);
    });
  } catch (err) {
    // Prefer clamd's own words when it answered (e.g. "INSTREAM size
    // limit exceeded. ERROR") — but only briefly: when OUR side aborted
    // the stream (byte cap, fetch failure) clamd never got the
    // terminating frame and will never reply, so waiting the full scan
    // timeout here would hang every aborted scan.
    try {
      const reply = await Promise.race([
        replyPromise,
        new Promise<never>((_, rej) =>
          setTimeout(() => rej(new Error('no reply after abort')), 1_500),
        ),
      ]);
      socket.destroy();
      return parseScanReply(reply);
    } catch {
      replyPromise.catch(() => {}); // abandoned — silence the rejection
      socket.destroy();
      return { verdict: 'error', message: `stream failed: ${String(err)}` };
    }
  }

  try {
    return parseScanReply(await replyPromise);
  } catch (err) {
    return { verdict: 'error', message: `no verdict: ${String(err)}` };
  }
}

/** Map a raw INSTREAM reply line to a typed verdict. Exported for tests. */
export function parseScanReply(reply: string): ClamdScanResult {
  const found = /^stream: (.+) FOUND$/.exec(reply);
  if (found) return { verdict: 'infected', signature: found[1] };
  if (/^stream: OK$/.test(reply)) return { verdict: 'clean' };
  return { verdict: 'error', message: reply || 'empty clamd reply' };
}
