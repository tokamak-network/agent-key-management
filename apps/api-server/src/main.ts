import { serve } from '@hono/node-server';
import { createApp } from './app.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);

async function main() {
  const { app, tee } = await createApp();

  console.log(`[AKM] TEE Provider: ${tee.runtime.provider}`);
  console.log(`[AKM] Root Public Key: ${await tee.rootKeyManager.getPublicKey()}`);
  console.log(`[AKM] Starting API server on port ${PORT}...`);

  serve({ fetch: app.fetch, port: PORT }, (info) => {
    console.log(`[AKM] Server running at http://localhost:${info.port}`);
  });
}

main().catch(console.error);
