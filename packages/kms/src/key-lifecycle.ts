import type { ISealedStorage } from '@akm/tee-core';
import type {
  KeyId,
  KeyMetadata,
  KeyCreationRequest,
  KeyCreationResult,
  KeyRotationResult,
} from '@akm/types';
import { createKeyId } from '@akm/types';
import { RootKeyManager } from './root-key.js';
import { KeyStore } from './key-store.js';
import {
  deriveChildKey,
  deriveEthereumAddress,
  getPublicKeyHex,
  buildKeyId,
} from './key-derivation.js';
import { wipeMemory } from '@akm/tee-simulator';

/**
 * Manages the full lifecycle of agent keys:
 * creation, rotation, and revocation.
 */
export class KeyLifecycleManager {
  constructor(
    private readonly rootKeyManager: RootKeyManager,
    private readonly keyStore: KeyStore,
    private readonly sealedStorage: ISealedStorage,
  ) {}

  /**
   * Create a new signing key for an agent.
   * Uses HKDF derivation from the root key.
   */
  async createKey(request: KeyCreationRequest): Promise<KeyCreationResult> {
    const rootKey = await this.rootKeyManager.getPrivateKey();

    const currentEpoch = this.keyStore.getCurrentEpoch(request.agentId);
    const epoch = currentEpoch + 1;

    const params = {
      agentId: request.agentId,
      purpose: request.purpose,
      epoch,
    };

    const childKey = deriveChildKey(rootKey, params);
    const keyId = createKeyId(buildKeyId(params));
    const ethereumAddress = deriveEthereumAddress(childKey);
    const publicKey = getPublicKeyHex(childKey);

    // Seal the derived key
    await this.sealedStorage.seal(`derived:${keyId}`, childKey);

    // Register metadata
    const metadata: KeyMetadata = {
      id: keyId,
      algorithm: request.algorithm ?? 'secp256k1',
      status: 'active',
      purpose: request.purpose,
      agentId: request.agentId,
      epoch,
      ethereumAddress,
      createdAt: Date.now(),
    };
    this.keyStore.register(metadata);

    // Wipe key material from memory
    wipeMemory(rootKey);
    wipeMemory(childKey);

    return { keyId, ethereumAddress, publicKey };
  }

  /**
   * Rotate a key: create new epoch, mark old as rotated.
   */
  async rotateKey(keyId: KeyId | string): Promise<KeyRotationResult> {
    const meta = this.keyStore.get(keyId as KeyId);
    if (!meta) throw new Error(`Key not found: ${keyId}`);
    if (meta.status !== 'active') throw new Error(`Key is not active: ${keyId}`);

    // Mark old key as rotated
    this.keyStore.updateStatus(keyId as KeyId, 'rotated');

    // Create new key at next epoch
    const result = await this.createKey({
      agentId: meta.agentId,
      purpose: meta.purpose,
      algorithm: meta.algorithm,
    });

    const newMeta = this.keyStore.get(result.keyId)!;

    return {
      previousKeyId: keyId as KeyId,
      newKeyId: result.keyId,
      newEthereumAddress: result.ethereumAddress,
      newPublicKey: result.publicKey,
      epoch: newMeta.epoch,
    };
  }

  /**
   * Revoke a key permanently.
   */
  async revokeKey(keyId: KeyId | string): Promise<void> {
    const meta = this.keyStore.get(keyId as KeyId);
    if (!meta) throw new Error(`Key not found: ${keyId}`);

    this.keyStore.updateStatus(keyId as KeyId, 'revoked');
    // Delete sealed key material
    await this.sealedStorage.delete(`derived:${keyId}`);
  }

  /**
   * Get private key bytes for signing (TEE internal only).
   */
  async getPrivateKey(keyId: KeyId | string): Promise<Uint8Array> {
    const meta = this.keyStore.get(keyId as KeyId);
    if (!meta) throw new Error(`Key not found: ${keyId}`);
    if (meta.status !== 'active') throw new Error(`Key is not active: ${keyId}`);

    return this.sealedStorage.unseal(`derived:${keyId}`);
  }
}
