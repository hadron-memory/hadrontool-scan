import { createApp } from './app.js';
import { config } from './config.js';
import { logger } from './logger.js';

const app = createApp();

app.listen(config.port, () => {
  logger.info('hadrontool-scan listening', {
    port: config.port,
    nodeEnv: config.nodeEnv,
    authEnabled: Boolean(config.serviceToken),
    clamd: `${config.clamd.host}:${config.clamd.port}`,
    allowPrivateNetworks: config.allowPrivateNetworks,
  });
});
