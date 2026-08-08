# hadrontool-scan — stateless malware-scan capability tool (ClamAV).
#
# Built by Komodo from this repo's `main`, pushed to GHCR, deployed on the
# `komodo_default` network as an INTERNAL-ONLY service: no Traefik router, no
# public DNS. hadron-server reaches it by container name at
# http://hadrontool-scan:8080. Secrets are injected at runtime by Doppler
# (`doppler run --`), matching the other services — Komodo sets only
# DOPPLER_TOKEN.
#
# The ClamAV DAEMON is a SEPARATE container (official `clamav/clamav` image,
# also internal-only on komodo_default); this tool reaches it via
# CLAMD_HOST/CLAMD_PORT. Keeping the ~1.5 GB signature-loaded daemon out of
# this image means tool deploys don't re-pull signatures and the daemon's
# freshclam updater runs on its own cadence. Ensure the daemon's
# StreamMaxLength ≥ SCAN_MAX_BYTES (clamd.conf; default 25M needs raising to
# match a 26M cap).

FROM node:22-slim

WORKDIR /app

# Doppler CLI for runtime secret injection (same pattern as the other services).
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
  && curl -sLf --retry 3 --tlsv1.2 --proto '=https' 'https://cli.doppler.com/install.sh' | sh \
  && apt-get purge -y curl gnupg && apt-get autoremove -y \
  && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    PORT=8080

# Reproducible install from the committed lockfile, then compile and drop dev
# deps. --include=dev is required because NODE_ENV=production (set above)
# would otherwise make `npm ci` skip devDependencies (typescript/tsx) and the
# build would fail with `tsc: not found`. COPY both tsconfigs — the build
# runs `tsc -p tsconfig.build.json` (the hadrontool-twilio TS5058 lesson).
COPY package.json package-lock.json ./
RUN npm ci --include=dev
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

RUN chown -R node:node /app
USER node

EXPOSE 8080
# Doppler injects SCAN_TOOL_TOKEN / CLAMD_HOST / CLAMD_PORT / NODE_ENV / PORT
# via DOPPLER_TOKEN.
CMD ["doppler", "run", "--", "node", "dist/index.js"]
