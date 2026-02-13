import { Hono } from 'hono';
import { z } from 'zod';
import type { TeeServices } from '../tee-bridge.js';
import type { PolicyRuleConfig } from '@akm/types';

const PolicyConfigSchema = z.object({
  rules: z.array(
    z.discriminatedUnion('type', [
      z.object({
        type: z.literal('caller'),
        allowedCallers: z.array(z.string()),
      }),
      z.object({
        type: z.literal('spending-limit'),
        maxValuePerTx: z.string().transform((v) => BigInt(v)),
        maxValuePerDay: z.string().transform((v) => BigInt(v)),
      }),
      z.object({
        type: z.literal('rate-limit'),
        maxRequestsPerMinute: z.number(),
      }),
      z.object({
        type: z.literal('allowlist'),
        allowedAddresses: z.array(z.string()),
      }),
    ]),
  ),
});

export function createPolicyRouter(tee: TeeServices) {
  const router = new Hono();

  // GET /policy/:keyId - Get policy for a key
  router.get('/:keyId{.+}', (c) => {
    const keyId = c.req.param('keyId');
    const rules = tee.keyStore.getPolicy(keyId);
    return c.json({ keyId, rules });
  });

  // PUT /policy/:keyId - Set policy for a key
  router.put('/:keyId{.+}', async (c) => {
    const keyId = c.req.param('keyId');
    const meta = tee.keyStore.get(keyId as any);

    if (!meta) {
      return c.json({ error: 'Key not found' }, 404);
    }

    const body = await c.req.json();
    const parsed = PolicyConfigSchema.safeParse(body);

    if (!parsed.success) {
      return c.json({ error: 'Invalid policy config', details: parsed.error.issues }, 400);
    }

    tee.keyStore.setPolicy(keyId, parsed.data.rules as PolicyRuleConfig[]);
    return c.json({ success: true, keyId, rulesCount: parsed.data.rules.length });
  });

  return router;
}
