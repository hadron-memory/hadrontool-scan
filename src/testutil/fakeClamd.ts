/**
 * In-process fake clamd for tests: speaks just enough of the z-command
 * protocol (PING / VERSION / INSTREAM) and flags any stream whose bytes
 * contain the ASCII marker "EICAR".
 */
import net from 'node:net';
import type { AddressInfo } from 'node:net';

export interface FakeClamd {
  port: number;
  close(): Promise<void>;
}

export async function startFakeClamd(): Promise<FakeClamd> {
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    let streaming = false;
    let body = Buffer.alloc(0);

    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);

      if (!streaming) {
        const nul = buf.indexOf(0);
        if (nul === -1) return;
        const cmd = buf.subarray(0, nul).toString('utf8');
        buf = buf.subarray(nul + 1);
        if (cmd === 'zPING') {
          socket.end('PONG\0');
          return;
        }
        if (cmd === 'zVERSION') {
          socket.end('ClamAV 1.4.5-fake/27500\0');
          return;
        }
        if (cmd === 'zINSTREAM') {
          streaming = true;
        } else {
          socket.end('UNKNOWN COMMAND ERROR\0');
          return;
        }
      }

      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (len === 0) {
          socket.end(
            body.toString('utf8').includes('EICAR')
              ? 'stream: Eicar-Signature FOUND\0'
              : 'stream: OK\0',
          );
          return;
        }
        if (buf.length < 4 + len) return;
        body = Buffer.concat([body, buf.subarray(4, 4 + len)]);
        buf = buf.subarray(4 + len);
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}
