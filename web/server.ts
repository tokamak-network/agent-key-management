import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import type { ITeeRuntime } from '@akm/tee-core';
import { SimulatedRuntime } from '@akm/tee-simulator';
import { RootKeyManager, KeyStore, KeyLifecycleManager, createTeeAccount } from '@akm/kms';
import { PolicyEngine, CallerRule, SpendingLimitRule } from '@akm/policy-engine';
import { QuoteGenerator, AttestationVerifier } from '@akm/attestation';
import type { KeyId } from '@akm/types';
import { parseEther, formatEther, keccak256 } from 'viem';
import type { TransactionSerializable } from 'viem';

const __dirname = dirname(fileURLToPath(import.meta.url));

// --- Module-level state ---
let runtime: ITeeRuntime | null = null;
let rootKeyManager: RootKeyManager | null = null;
let keyStore: KeyStore | null = null;
let keyLifecycle: KeyLifecycleManager | null = null;
let policyEngine: PolicyEngine | null = null;
let quoteGenerator: QuoteGenerator | null = null;
let activeProvider: string = '';

// --- App ---
const app = new Hono();

// Serve index.html
const html = readFileSync(join(__dirname, 'index.html'), 'utf-8');
app.get('/', (c) => c.html(html));

// POST /api/boot - Boot the TEE runtime
app.post('/api/boot', async (c) => {
  try {
    const { provider = 'simulator' } = await c.req.json();
    activeProvider = provider;

    // Reset state
    rootKeyManager = null;
    keyStore = null;
    keyLifecycle = null;
    policyEngine = null;
    quoteGenerator = null;

    if (provider === 'dstack') {
      const { DstackRuntime } = await import('@akm/tee-dstack');
      runtime = new DstackRuntime({ endpoint: process.env.DSTACK_ENDPOINT });
    } else {
      runtime = new SimulatedRuntime({ fixedMeasurement: 'akm-poc-v1' });
    }

    await runtime.initialize();
    keyStore = new KeyStore();

    const measurement = await runtime.getMeasurement();
    return c.json({ measurement, provider: activeProvider });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/init - Initialize root key
app.post('/api/init', async (c) => {
  try {
    if (!runtime) return c.json({ error: 'Runtime not booted' }, 400);
    rootKeyManager = new RootKeyManager(runtime.sealedStorage);
    await rootKeyManager.initialize();
    keyLifecycle = new KeyLifecycleManager(rootKeyManager, keyStore!, runtime.sealedStorage);
    quoteGenerator = new QuoteGenerator(runtime.attestation);
    const rootPublicKey = await rootKeyManager.getPublicKey();
    return c.json({ rootPublicKey });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/keys - Create an agent key
app.post('/api/keys', async (c) => {
  try {
    if (!keyLifecycle) return c.json({ error: 'KMS not initialized' }, 400);
    const { agentId } = await c.req.json();
    if (!agentId) return c.json({ error: 'agentId is required' }, 400);
    const result = await keyLifecycle.createKey({ agentId, purpose: 'signing' });
    return c.json(result);
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/sign/message - Sign a message
app.post('/api/sign/message', async (c) => {
  try {
    if (!keyStore || !runtime) return c.json({ error: 'KMS not initialized' }, 400);
    const { keyId, callerId, message } = await c.req.json();
    if (!keyId || !message) return c.json({ error: 'keyId and message are required' }, 400);

    const meta = keyStore.get(keyId as KeyId);
    if (!meta) return c.json({ error: `Key not found: ${keyId}` }, 404);

    const account = createTeeAccount(
      keyId,
      meta.ethereumAddress as `0x${string}`,
      runtime.sealedStorage,
      keyStore,
      policyEngine ?? undefined,
      callerId ?? 'web-demo',
    );

    const signature = await account.signMessage({ message });
    return c.json({ signature, address: account.address });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('Policy denied')) return c.json({ error: msg }, 403);
    return c.json({ error: msg }, 500);
  }
});

// POST /api/sign/transaction - Sign a transaction
app.post('/api/sign/transaction', async (c) => {
  try {
    if (!keyStore || !runtime) return c.json({ error: 'KMS not initialized' }, 400);
    const { keyId, callerId, to, value } = await c.req.json();
    if (!keyId || !to) return c.json({ error: 'keyId and to are required' }, 400);

    const meta = keyStore.get(keyId as KeyId);
    if (!meta) return c.json({ error: `Key not found: ${keyId}` }, 404);

    const account = createTeeAccount(
      keyId,
      meta.ethereumAddress as `0x${string}`,
      runtime.sealedStorage,
      keyStore,
      policyEngine ?? undefined,
      callerId ?? 'web-demo',
    );

    const weiValue = parseEther(value ?? '0');
    const tx: TransactionSerializable = {
      to: to as `0x${string}`,
      value: weiValue,
      type: 'eip1559',
      maxFeePerGas: 20000000000n,
      maxPriorityFeePerGas: 1000000000n,
      nonce: 0,
      gas: 21000n,
      chainId: 1,
    };

    const signature = await account.signTransaction(tx);
    const hash = keccak256(signature as `0x${string}`);

    return c.json({ signature, hash, from: account.address, value: formatEther(weiValue) });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('Policy denied')) return c.json({ error: msg }, 403);
    return c.json({ error: msg }, 500);
  }
});

// POST /api/policy/setup - Setup policy rules
app.post('/api/policy/setup', async (c) => {
  try {
    const { allowedCallers, maxPerTxEth, maxPerDayEth } = await c.req.json();
    policyEngine = new PolicyEngine();
    const rules: Array<{ type: string; name: string; detail: string }> = [];

    if (allowedCallers && allowedCallers.length > 0) {
      policyEngine.addRule(new CallerRule(allowedCallers));
      rules.push({ type: 'caller', name: 'Caller Whitelist', detail: allowedCallers.join(', ') });
    }
    if (maxPerTxEth || maxPerDayEth) {
      const perTx = parseEther(maxPerTxEth ?? '1');
      const perDay = parseEther(maxPerDayEth ?? '10');
      policyEngine.addRule(new SpendingLimitRule(perTx, perDay));
      rules.push({
        type: 'spending-limit',
        name: 'Spending Limit',
        detail: `max ${maxPerTxEth ?? '1'} ETH/tx, ${maxPerDayEth ?? '10'} ETH/day`,
      });
    }

    return c.json({ rules });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/keys/rotate - Rotate a key
app.post('/api/keys/rotate', async (c) => {
  try {
    if (!keyLifecycle) return c.json({ error: 'KMS not initialized' }, 400);
    const { keyId } = await c.req.json();
    if (!keyId) return c.json({ error: 'keyId is required' }, 400);

    const oldMeta = keyStore!.get(keyId as KeyId);
    const result = await keyLifecycle.rotateKey(keyId);

    return c.json({
      oldKey: {
        keyId: result.previousKeyId,
        status: keyStore!.get(result.previousKeyId)?.status ?? 'rotated',
        address: oldMeta?.ethereumAddress,
      },
      newKey: {
        keyId: result.newKeyId,
        address: result.newEthereumAddress,
        publicKey: result.newPublicKey,
        epoch: result.epoch,
      },
    });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/attestation/quote - Generate attestation quote
app.post('/api/attestation/quote', async (c) => {
  try {
    if (!quoteGenerator || !rootKeyManager) {
      return c.json({ error: 'KMS not initialized' }, 400);
    }
    const rootPublicKey = await rootKeyManager.getPublicKey();
    const quote = await quoteGenerator.generate(rootPublicKey);
    return c.json({ quote });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// POST /api/attestation/verify - Verify attestation quote
app.post('/api/attestation/verify', async (c) => {
  try {
    const { quote } = await c.req.json();
    if (!quote) return c.json({ error: 'quote is required' }, 400);
    const verifier = new AttestationVerifier();
    const result = verifier.verify(quote);
    return c.json({ result });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 500);
  }
});

// GET /api/state - Get current TEE state
app.get('/api/state', async (c) => {
  const booted = runtime !== null;
  const initialized = rootKeyManager !== null;
  const provider = activeProvider || null;
  const keys = keyStore ? keyStore.listAll().map((k) => ({
    id: k.id,
    agentId: k.agentId,
    epoch: k.epoch,
    status: k.status,
    address: k.ethereumAddress,
  })) : [];
  const policyRules = policyEngine
    ? policyEngine.getRules().map((r) => ({ type: r.type, name: r.name }))
    : [];

  return c.json({ booted, initialized, provider, keys, policyRules });
});

// --- Start ---
const port = Number(process.env.PORT ?? 3000);
console.log(`\n  TEE Agent KMS — Interactive Demo`);
console.log(`  http://localhost:${port}\n`);
serve({ fetch: app.fetch, port });
