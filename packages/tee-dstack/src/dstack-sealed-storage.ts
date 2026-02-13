import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import type { ISealedStorage } from '@akm/tee-core';
import type { TappdClient, DeriveKeyResponse } from '@phala/dstack-sdk';

const AES_KEY_SIZE = 32; // 256 bits
const IV_SIZE = 12; // 96 bits for GCM
const TAG_SIZE = 16; // 128 bits

const SEALING_KEY_PATH = 'akm/sealed-storage/v1';

/**
 * Sealed storage backed by dstack TEE key derivation.
 * Uses DstackClient.deriveKey() to obtain a deterministic sealing key
 * bound to the TEE identity, then AES-256-GCM encrypts data in-memory.
 */
export class DstackSealedStorage implements ISealedStorage {
  private sealingKey: Uint8Array | null = null;
  private readonly store = new Map<string, Uint8Array>();
  private readonly client: TappdClient;

  constructor(client: TappdClient) {
    this.client = client;
  }

  /**
   * Initialize by deriving the sealing key from dstack.
   * Must be called before any seal/unseal operations.
   */
  async initialize(): Promise<void> {
    const response: DeriveKeyResponse = await this.client.deriveKey(SEALING_KEY_PATH);
    this.sealingKey = response.asUint8Array(AES_KEY_SIZE);
  }

  private getSealingKey(): Uint8Array {
    if (!this.sealingKey) {
      throw new Error('DstackSealedStorage not initialized — call initialize() first');
    }
    return this.sealingKey;
  }

  async seal(key: string, data: Uint8Array): Promise<void> {
    const sealingKey = this.getSealingKey();
    const iv = randomBytes(IV_SIZE);
    const cipher = createCipheriv('aes-256-gcm', sealingKey, iv);

    // Include key in AAD to bind ciphertext to key name
    cipher.setAAD(Buffer.from(key, 'utf-8'));

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Store as: IV || TAG || CIPHERTEXT
    const sealed = new Uint8Array(IV_SIZE + TAG_SIZE + encrypted.length);
    sealed.set(iv, 0);
    sealed.set(tag, IV_SIZE);
    sealed.set(encrypted, IV_SIZE + TAG_SIZE);

    this.store.set(key, sealed);
  }

  async unseal(key: string): Promise<Uint8Array> {
    const sealed = this.store.get(key);
    if (!sealed) {
      throw new Error(`No sealed data found for key: ${key}`);
    }

    const sealingKey = this.getSealingKey();
    const iv = sealed.slice(0, IV_SIZE);
    const tag = sealed.slice(IV_SIZE, IV_SIZE + TAG_SIZE);
    const ciphertext = sealed.slice(IV_SIZE + TAG_SIZE);

    const decipher = createDecipheriv('aes-256-gcm', sealingKey, iv);
    decipher.setAAD(Buffer.from(key, 'utf-8'));
    decipher.setAuthTag(tag);

    try {
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return new Uint8Array(decrypted);
    } catch {
      throw new Error(`Failed to unseal data for key: ${key} (tampering detected or wrong enclave)`);
    }
  }

  async has(key: string): Promise<boolean> {
    return this.store.has(key);
  }

  async delete(key: string): Promise<boolean> {
    return this.store.delete(key);
  }

  async list(): Promise<string[]> {
    return [...this.store.keys()];
  }
}
