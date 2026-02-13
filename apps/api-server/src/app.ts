import { Hono } from 'hono';
import { logger } from 'hono/logger';
import { agentAuth } from './middleware/auth.js';
import { createKeysRouter } from './routes/keys.js';
import { createSigningRouter } from './routes/signing.js';
import { createPolicyRouter } from './routes/policy.js';
import { createAttestationRouter } from './routes/attestation.js';
import { createTeeServices, type TeeServices } from './tee-bridge.js';

export type AppEnv = {
  Variables: {
    callerId: string;
  };
};

export async function createApp() {
  const tee = await createTeeServices();
  const app = new Hono<AppEnv>();

  // Middleware
  app.use('*', logger());

  // Health check (no auth required)
  app.get('/health', (c) => c.json({ status: 'ok', teeProvider: tee.runtime.provider }));

  // Protected routes
  app.use('/keys/*', agentAuth);
  app.use('/sign/*', agentAuth);
  app.use('/policy/*', agentAuth);

  // Routes
  app.route('/keys', createKeysRouter(tee));
  app.route('/sign', createSigningRouter(tee));
  app.route('/policy', createPolicyRouter(tee));
  app.route('/attestation', createAttestationRouter(tee));

  return { app, tee };
}
