import { Hono } from 'hono';
import { z } from 'zod';
import type { TeeServices } from '../tee-bridge.js';

const CreateKeySchema = z.object({
  agentId: z.string().min(1),
  purpose: z.enum(['signing', 'encryption']).default('signing'),
  algorithm: z.enum(['secp256k1']).default('secp256k1'),
});

export function createKeysRouter(tee: TeeServices) {
  const router = new Hono();

  // POST /keys - Create a new key
  router.post('/', async (c) => {
    const body = await c.req.json();
    const parsed = CreateKeySchema.safeParse(body);

    if (!parsed.success) {
      return c.json({ error: 'Invalid request', details: parsed.error.issues }, 400);
    }

    const result = await tee.keyLifecycle.createKey(parsed.data);
    return c.json(result, 201);
  });

  // GET /keys - List all keys
  router.get('/', (c) => {
    const agentId = c.req.query('agentId');
    const keys = agentId
      ? tee.keyStore.getByAgent(agentId)
      : tee.keyStore.listAll();

    return c.json({ keys });
  });

  // GET /keys/:id - Get key metadata
  router.get('/:id{.+}', (c) => {
    const keyId = c.req.param('id');
    const meta = tee.keyStore.get(keyId as any);

    if (!meta) {
      return c.json({ error: 'Key not found' }, 404);
    }

    return c.json(meta);
  });

  // POST /keys/:id/rotate - Rotate a key
  router.post('/:id{.+}/rotate', async (c) => {
    const keyId = c.req.param('id');

    try {
      const result = await tee.keyLifecycle.rotateKey(keyId);
      return c.json(result);
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400);
    }
  });

  // POST /keys/:id/revoke - Revoke a key
  router.post('/:id{.+}/revoke', async (c) => {
    const keyId = c.req.param('id');

    try {
      await tee.keyLifecycle.revokeKey(keyId);
      return c.json({ success: true });
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400);
    }
  });

  return router;
}
