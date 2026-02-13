import { Hono } from 'hono';
import { z } from 'zod';
import { keccak256, serializeTransaction, type TransactionSerializable } from 'viem';
import type { TeeServices } from '../tee-bridge.js';

const SignTransactionSchema = z.object({
  keyId: z.string().min(1),
  transaction: z.object({
    to: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
    value: z.string().optional(),
    data: z.string().optional(),
    nonce: z.number().optional(),
    gasLimit: z.string().optional(),
    maxFeePerGas: z.string().optional(),
    maxPriorityFeePerGas: z.string().optional(),
    chainId: z.number(),
  }),
});

const SignMessageSchema = z.object({
  keyId: z.string().min(1),
  message: z.string().min(1),
});

export function createSigningRouter(tee: TeeServices) {
  const router = new Hono();

  // POST /sign/transaction - Sign an EVM transaction
  router.post('/transaction', async (c) => {
    const callerId = c.get('callerId') as string;
    const body = await c.req.json();
    const parsed = SignTransactionSchema.safeParse(body);

    if (!parsed.success) {
      return c.json({ error: 'Invalid request', details: parsed.error.issues }, 400);
    }

    try {
      const { keyId, transaction } = parsed.data;
      const account = await tee.createAccount(keyId, callerId);

      const tx: TransactionSerializable = {
        to: transaction.to as `0x${string}`,
        chainId: transaction.chainId,
        type: 'eip1559',
        ...(transaction.value ? { value: BigInt(transaction.value) } : {}),
        ...(transaction.data ? { data: transaction.data as `0x${string}` } : {}),
        ...(transaction.nonce !== undefined ? { nonce: transaction.nonce } : {}),
        ...(transaction.maxFeePerGas ? { maxFeePerGas: BigInt(transaction.maxFeePerGas) } : {}),
        ...(transaction.maxPriorityFeePerGas
          ? { maxPriorityFeePerGas: BigInt(transaction.maxPriorityFeePerGas) }
          : {}),
      };

      const signature = await account.signTransaction(tx);
      const serialized = serializeTransaction(tx, signature as any);
      const hash = keccak256(serialized);

      return c.json({
        signedTransaction: serialized,
        hash,
        from: account.address,
      });
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes('Policy denied')) {
        return c.json({ error: msg }, 403);
      }
      return c.json({ error: msg }, 400);
    }
  });

  // POST /sign/message - Sign a message
  router.post('/message', async (c) => {
    const callerId = c.get('callerId') as string;
    const body = await c.req.json();
    const parsed = SignMessageSchema.safeParse(body);

    if (!parsed.success) {
      return c.json({ error: 'Invalid request', details: parsed.error.issues }, 400);
    }

    try {
      const { keyId, message } = parsed.data;
      const account = await tee.createAccount(keyId, callerId);

      const signature = await account.signMessage({ message });

      return c.json({
        signature,
        address: account.address,
      });
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes('Policy denied')) {
        return c.json({ error: msg }, 403);
      }
      return c.json({ error: msg }, 400);
    }
  });

  return router;
}
