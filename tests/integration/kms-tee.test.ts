import { describe, it, expect, beforeEach } from 'vitest';
import { SimulatedRuntime } from '@akm/tee-simulator';
import { RootKeyManager, KeyStore, KeyLifecycleManager, createTeeAccount } from '@akm/kms';
import { PolicyEngine, CallerRule, SpendingLimitRule, AllowlistRule } from '@akm/policy-engine';
import { hashMessage } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';

describe('KMS + TEE Integration', () => {
  let runtime: SimulatedRuntime;
  let rootKeyManager: RootKeyManager;
  let keyStore: KeyStore;
  let lifecycle: KeyLifecycleManager;

  beforeEach(async () => {
    runtime = new SimulatedRuntime({ fixedMeasurement: 'integration-test' });
    rootKeyManager = new RootKeyManager(runtime.sealedStorage);
    keyStore = new KeyStore();
    lifecycle = new KeyLifecycleManager(rootKeyManager, keyStore, runtime.sealedStorage);
    await rootKeyManager.initialize();
  });

  it('should create key and sign message inside TEE', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });

    const account = createTeeAccount(
      result.keyId,
      result.ethereumAddress as `0x${string}`,
      runtime.sealedStorage,
      keyStore,
    );

    const signature = await account.signMessage({ message: 'hello' });
    expect(signature).toMatch(/^0x[0-9a-f]+$/);
  });

  it('should sign message and verify with public key', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });

    const account = createTeeAccount(
      result.keyId,
      result.ethereumAddress as `0x${string}`,
      runtime.sealedStorage,
      keyStore,
    );

    const message = 'verify me';
    const signature = await account.signMessage({ message });

    // Verify the signature using secp256k1
    const hash = hashMessage(message);
    const sigBytes = hexToBytes(signature.slice(2));
    const r = sigBytes.slice(0, 32);
    const s = sigBytes.slice(32, 64);
    const v = sigBytes[64]! - 27;

    const sig = new secp256k1.Signature(
      BigInt('0x' + bytesToHex(r)),
      BigInt('0x' + bytesToHex(s)),
    ).addRecoveryBit(v);

    const recoveredPubKey = sig.recoverPublicKey(hexToBytes(hash.slice(2)));
    const recoveredPubKeyHex = bytesToHex(recoveredPubKey.toRawBytes(false));

    expect(recoveredPubKeyHex).toBe(result.publicKey);
  });

  it('should deny signing when policy rejects', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });

    const engine = new PolicyEngine();
    engine.addRule(new CallerRule(['agent-1']));

    const account = createTeeAccount(
      result.keyId,
      result.ethereumAddress as `0x${string}`,
      runtime.sealedStorage,
      keyStore,
      engine,
      'malicious-caller',
    );

    await expect(
      account.signMessage({ message: 'hack attempt' }),
    ).rejects.toThrow('Policy denied');
  });

  it('should enforce spending limits across multiple transactions', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });

    const engine = new PolicyEngine();
    engine.addRule(new SpendingLimitRule(
      1000000000000000000n, // 1 ETH per tx
      1500000000000000000n, // 1.5 ETH per day
    ));
    engine.addRule(new AllowlistRule(['0x' + 'ab'.repeat(20)]));

    const account = createTeeAccount(
      result.keyId,
      result.ethereumAddress as `0x${string}`,
      runtime.sealedStorage,
      keyStore,
      engine,
      'agent-1',
    );

    // First 1 ETH tx should succeed
    await expect(
      account.signTransaction({
        to: ('0x' + 'ab'.repeat(20)) as `0x${string}`,
        value: 1000000000000000000n,
        chainId: 1,
        type: 'eip1559',
      }),
    ).resolves.toBeTruthy();

    // Second 1 ETH tx should fail (exceeds daily limit of 1.5 ETH)
    await expect(
      account.signTransaction({
        to: ('0x' + 'ab'.repeat(20)) as `0x${string}`,
        value: 1000000000000000000n,
        chainId: 1,
        type: 'eip1559',
      }),
    ).rejects.toThrow('Policy denied');
  });

  it('should not expose private keys in any API response', async () => {
    const result = await lifecycle.createKey({ agentId: 'agent-1', purpose: 'signing' });

    // Key creation result should not contain private key
    const resultStr = JSON.stringify(result);
    expect(resultStr).not.toContain('privateKey');

    // Key metadata should not contain private key
    const meta = keyStore.get(result.keyId);
    const metaStr = JSON.stringify(meta);
    expect(metaStr).not.toContain('privateKey');

    // The private key should only be in sealed storage
    const privateKey = await runtime.sealedStorage.unseal(`derived:${result.keyId}`);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
  });
});
