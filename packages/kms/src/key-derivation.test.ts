import { describe, it, expect } from 'vitest';
import { deriveChildKey, deriveEthereumAddress, getPublicKeyHex, buildKeyId } from './key-derivation.js';
import { secp256k1 } from '@noble/curves/secp256k1';

describe('key-derivation', () => {
  const rootKey = secp256k1.utils.randomPrivateKey();

  it('should derive deterministic keys for same params', () => {
    const params = { agentId: 'agent-1', purpose: 'signing', epoch: 0 };

    const key1 = deriveChildKey(rootKey, params);
    const key2 = deriveChildKey(rootKey, params);

    expect(key1).toEqual(key2);
  });

  it('should derive different keys for different agents', () => {
    const key1 = deriveChildKey(rootKey, { agentId: 'agent-1', purpose: 'signing', epoch: 0 });
    const key2 = deriveChildKey(rootKey, { agentId: 'agent-2', purpose: 'signing', epoch: 0 });

    expect(key1).not.toEqual(key2);
  });

  it('should derive different keys for different epochs', () => {
    const key1 = deriveChildKey(rootKey, { agentId: 'agent-1', purpose: 'signing', epoch: 0 });
    const key2 = deriveChildKey(rootKey, { agentId: 'agent-1', purpose: 'signing', epoch: 1 });

    expect(key1).not.toEqual(key2);
  });

  it('should derive different keys for different purposes', () => {
    const key1 = deriveChildKey(rootKey, { agentId: 'agent-1', purpose: 'signing', epoch: 0 });
    const key2 = deriveChildKey(rootKey, { agentId: 'agent-1', purpose: 'encryption', epoch: 0 });

    expect(key1).not.toEqual(key2);
  });

  it('should derive valid secp256k1 keys', () => {
    const key = deriveChildKey(rootKey, { agentId: 'test', purpose: 'signing', epoch: 0 });

    // Should not throw
    const pubkey = secp256k1.getPublicKey(key, false);
    expect(pubkey.length).toBe(65); // Uncompressed
  });

  it('should derive ethereum addresses', () => {
    const key = deriveChildKey(rootKey, { agentId: 'test', purpose: 'signing', epoch: 0 });
    const address = deriveEthereumAddress(key);

    expect(address).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('should get public key hex', () => {
    const key = deriveChildKey(rootKey, { agentId: 'test', purpose: 'signing', epoch: 0 });
    const pubkey = getPublicKeyHex(key);

    expect(pubkey).toMatch(/^04[0-9a-f]{128}$/); // Uncompressed public key
  });

  it('should build key ID', () => {
    const id = buildKeyId({ agentId: 'agent-1', purpose: 'signing', epoch: 3 });
    expect(id).toBe('agent-1/signing/epoch-3');
  });
});
