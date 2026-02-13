import type { Context, Next } from 'hono';

/**
 * Simple agent authentication middleware.
 * In production, this would verify JWT tokens or mTLS certificates.
 */
export async function agentAuth(c: Context, next: Next) {
  const callerId = c.req.header('x-agent-id');

  if (!callerId) {
    return c.json({ error: 'Missing x-agent-id header' }, 401);
  }

  c.set('callerId', callerId);
  await next();
}
