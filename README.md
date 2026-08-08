# hadrontool-scan

Stateless malware-scan capability tool for [hadron-server](https://github.com/hadron-memory/hadron-server) (#896). Receives an already-authorized scan request carrying a **presigned GET URL**, streams the bytes into **ClamAV** (`clamd` INSTREAM), and returns a verdict. Hadron-blind: no DB, no object-storage credentials, no identity — hadron-server is the front door and runs all authorization before calling here.

## Contract — `scan@1` (provider-neutral)

```
POST /ops/scan            (bearer: SCAN_TOOL_TOKEN)
{ "url": "<presigned GET>", "sizeBytes": 12345, "filename": "report.pdf" }

200 {
  "contract": "scan@1",
  "verdict": "clean" | "infected" | "error",
  "signature": "Eicar-Signature",        // infected only
  "message": "...",                      // error only (RETRYABLE by contract)
  "engine": { "name": "clamav", "version": "..." },
  "durationMs": 412
}
```

`verdict: "error"` is retryable — core leaves the asset `PENDING` and its sweep retries. Only malformed input is a 4xx. Scanning is idempotent; callers may retry freely (unlike the SMS tool).

Nothing in the envelope names ClamAV except the informational `engine` block, so a hosted multi-engine scanner can replace this implementation without touching hadron-server.

## Architecture

Two containers, both internal-only on `komodo_default`:

- **hadrontool-scan** (this repo) — thin Node service; speaks the clamd wire protocol directly (`src/clamd.ts`, zero dependencies — no npm clamd wrapper, deliberately).
- **clamav** — official [`clamav/clamav`](https://hub.docker.com/r/clamav/clamav) image (1.4 LTS), ~1.5 GB signature-loaded daemon with its own `freshclam` update cycle. Reached via `CLAMD_HOST`/`CLAMD_PORT`.

**clamd.conf requirement:** `StreamMaxLength` must be ≥ `SCAN_MAX_BYTES` (the official image accepts `CLAMD_CONF_StreamMaxLength=30M` style env overrides), or clean large files come back as engine errors.

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8080` | |
| `SCAN_TOOL_TOKEN` | — | Bearer for `/info` + `/ops`. **Required when `NODE_ENV=production`** (boot refuses otherwise). |
| `CLAMD_HOST` / `CLAMD_PORT` | `127.0.0.1` / `3310` | The clamav container (alpha: `clamav`). |
| `SCAN_MAX_BYTES` | `27262976` (26 MB) | Streaming byte cap; ≥ platform asset cap (25 MB), ≤ clamd `StreamMaxLength`. |
| `SCAN_ALLOW_PRIVATE_NETWORKS` | `false` | `true` only for self-hosted/dev where the object store is on a private address (local MinIO). The hosted platform leaves it unset — SSRF guard. |

## Endpoints

- `GET /healthz` — liveness (no auth).
- `GET /readyz` — readiness: 200 only when clamd answers PONG (a booting clamd takes ~30–60 s to load signatures).
- `GET /info` — name, version, contract, engine reachability + version (bearer).
- `POST /ops/scan` — the operation (bearer).

## Dev

```bash
npm install
docker run --rm -p 3310:3310 clamav/clamav:1.4   # wait for "socket found, clamd started"
npm run dev
# EICAR round-trip:
curl -s localhost:8080/ops/scan -H 'content-type: application/json' \
  -d '{"url":"https://secure.eicar.org/eicar.com.txt"}' | jq
```

`npm test` needs no ClamAV — the suite fakes clamd with an in-process TCP server.
