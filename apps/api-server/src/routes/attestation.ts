import { Hono } from 'hono';
import { z } from 'zod';
import type { TeeServices } from '../tee-bridge.js';

const GenerateQuoteSchema = z.object({
  nonce: z.string().min(1),
});

const VerifyQuoteSchema = z.object({
  quote: z.object({
    report: z.object({
      provider: z.string(),
      timestamp: z.number(),
      measurements: z.object({
        mrEnclave: z.string(),
        mrSigner: z.string(),
        productId: z.number(),
        svn: z.number(),
      }),
      userData: z.string(),
      signature: z.string(),
    }),
    nonce: z.string(),
    rootPublicKey: z.string(),
  }),
  expectedMeasurements: z
    .object({
      mrEnclave: z.string().optional(),
      mrSigner: z.string().optional(),
    })
    .optional(),
});

export function createAttestationRouter(tee: TeeServices) {
  const router = new Hono();

  // POST /attestation/quote - Generate attestation quote
  router.post('/quote', async (c) => {
    const body = await c.req.json();
    const parsed = GenerateQuoteSchema.safeParse(body);

    if (!parsed.success) {
      return c.json({ error: 'Invalid request', details: parsed.error.issues }, 400);
    }

    const rootPublicKey = await tee.rootKeyManager.getPublicKey();
    const quote = await tee.quoteGenerator.generate(rootPublicKey, parsed.data.nonce);

    return c.json(quote);
  });

  // POST /attestation/verify - Verify attestation quote
  router.post('/verify', async (c) => {
    const body = await c.req.json();
    const parsed = VerifyQuoteSchema.safeParse(body);

    if (!parsed.success) {
      return c.json({ error: 'Invalid request', details: parsed.error.issues }, 400);
    }

    const result = tee.verifier.verify(
      parsed.data.quote as any,
      parsed.data.expectedMeasurements,
    );

    return c.json(result);
  });

  return router;
}
