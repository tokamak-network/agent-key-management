import { describe, it, expect, beforeEach } from 'vitest';
import { SimulatedRuntime } from '@akm/tee-simulator';
import { RootKeyManager } from './root-key.js';
import { KeyStore } from './key-store.js';
import { KeyLifecycleManager } from './key-lifecycle.js';

describe('KeyLifecycleManager', () => {
  let runtime: SimulatedRuntime;
  let rootKeyManager: RootKeyManager;
  let keyStore: KeyStore;
  let lifecycle: KeyLifecycleManager;

  beforeEach(async () => {
    runtime = new SimulatedRuntime({ fixedMeasurement: 'test-measure' });
    rootKeyManager = new RootKeyManager(runtime.sealedStorage);
    keyStore = new KeyStore();
    lifecycle = new KeyLifecycleManager(rootKeyManager, keyStore, runtime.sealedStorage);

    await rootKeyManager.initialize();
  });

  it('should create a new key', async () => {
    const result = await lifecycle.createKey({
      agentId: 'agent-1',
      purpose: 'signing',
    });

    expect(result.keyId).toBe('agent-1/signing/epoch-0');
    expect(result.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
    expect(result.publicKey).toMatch(/^04[0-9a-f]{128}$/);

    const meta = keyStore.get(result.keyId);
    expect(meta).toBeDefined();
    expect(meta!.status).toBe('active');
    expect(meta!.agentId).toBe('agent-1');
    expect(meta!.epoch).toBe(0);
  });

  it('should create deterministic keys from same root', async () => {
    const r1 = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });

    // Re-create lifecycle with same root
    const keyStore2 = new KeyStore();
    const lifecycle2 = new KeyLifecycleManager(rootKeyManager, keyStore2, runtime.sealedStorage);
    const r2 = await lifecycle2.createKey({ agentId: 'agent-1', purpose: 'signing' });

    expect(r1.ethereumAddress).toBe(r2.ethereumAddress);
    expect(r1.publicKey).toBe(r2.publicKey);
  });

  it('should rotate a key', async () => {
    const original = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });
    const rotated = await lifecycle.rotateKey(original.keyId);

    expect(rotated.previousKeyId).toBe(original.keyId);
    expect(rotated.epoch).toBe(1);
    expect(rotated.newEthereumAddress).not.toBe(original.ethereumAddress);

    // Old key should be rotated
    const oldMeta = keyStore.get(original.keyId);
    expect(oldMeta!.status).toBe('rotated');

    // New key should be active
    const newMeta = keyStore.get(rotated.newKeyId);
    expect(newMeta!.status).toBe('active');
  });

  it('should revoke a key', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });
    await lifecycle.revokeKey(result.keyId);

    const meta = keyStore.get(result.keyId);
    expect(meta!.status).toBe('revoked');

    // Should not be able to get private key for revoked key
    await expect(lifecycle.getPrivateKey(result.keyId)).rejects.toThrow('not active');
  });

  it('should fail to rotate non-active key', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });
    await lifecycle.revokeKey(result.keyId);

    await expect(lifecycle.rotateKey(result.keyId)).rejects.toThrow('not active');
  });

  it('should manage multiple agents independently', async () => {
    const r1 = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });
    const r2 = await lifecycle.createKey({ agentId: 'agent-2', purpose: 'signing' });

    expect(r1.ethereumAddress).not.toBe(r2.ethereumAddress);
    expect(keyStore.getByAgent('agent-1')).toHaveLength(1);
    expect(keyStore.getByAgent('agent-2')).toHaveLength(1);
  });
});
