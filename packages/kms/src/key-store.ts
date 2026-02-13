import type { KeyId, KeyMetadata, KeyStatus } from '@akm/types';
import { createKeyId } from '@akm/types';
import type { PolicyRuleConfig } from '@akm/types';

/**
 * In-memory key metadata registry.
 * Stores public metadata about keys (NOT the keys themselves).
 * Private key material is only in sealed storage.
 */
export class KeyStore {
  private readonly keys = new Map<string, KeyMetadata>();
  private readonly policies = new Map<string, PolicyRuleConfig[]>();

  register(metadata: KeyMetadata): void {
    this.keys.set(metadata.id, metadata);
  }

  get(keyId: KeyId | string): KeyMetadata | undefined {
    return this.keys.get(keyId);
  }

  getByAgent(agentId: string): KeyMetadata[] {
    return [...this.keys.values()].filter((k) => k.agentId === agentId);
  }

  getActiveByAgent(agentId: string): KeyMetadata | undefined {
    return [...this.keys.values()].find(
      (k) => k.agentId === agentId && k.status === 'active',
    );
  }

  updateStatus(keyId: KeyId | string, status: KeyStatus): boolean {
    const meta = this.keys.get(keyId);
    if (!meta) return false;

    const updated: KeyMetadata = {
      ...meta,
      status,
      ...(status === 'rotated' ? { rotatedAt: Date.now() } : {}),
      ...(status === 'revoked' ? { revokedAt: Date.now() } : {}),
    };
    this.keys.set(keyId, updated);
    return true;
  }

  listAll(): KeyMetadata[] {
    return [...this.keys.values()];
  }

  /** Get the current epoch for an agent (max epoch among all keys) */
  getCurrentEpoch(agentId: string): number {
    const agentKeys = this.getByAgent(agentId);
    if (agentKeys.length === 0) return -1;
    return Math.max(...agentKeys.map((k) => k.epoch));
  }

  setPolicy(keyId: string, rules: PolicyRuleConfig[]): void {
    this.policies.set(keyId, rules);
  }

  getPolicy(keyId: string): PolicyRuleConfig[] {
    return this.policies.get(keyId) ?? [];
  }
}
