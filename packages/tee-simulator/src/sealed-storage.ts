import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'node:crypto';
import type { ISealedStorage } from '@akm/tee-core';

const AES_KEY_SIZE = 32; // 256 bits
const IV_SIZE = 12; // 96 bits for GCM
const TAG_SIZE = 16; // 128 bits

/**
 * In-memory sealed storage using AES-256-GCM.
 * Simulates TEE sealed storage where data is encrypted with a key
 * derived from the enclave measurement.
 *
 * In a real TEE, the sealing key is hardware-derived and bound to
 * the enclave identity (MRENCLAVE/MRSIGNER).
 */
export class SimulatedSealedStorage implements ISealedStorage {
  private readonly sealingKey: Uint8Array;
  private readonly store = new Map<string, Uint8Array>();

  constructor(measurement: string) {
    // Derive sealing key from measurement (simulates hardware key derivation)
    const encoder = new TextEncoder();
    const seed = encoder.encode(`tee-seal-key:${measurement}`);
    // Use first 32 bytes of hash as sealing key
    this.sealingKey = new Uint8Array(createHash('sha256').update(seed).digest());
  }

  async seal(key: string, data: Uint8Array): Promise<void> {
    const iv = randomBytes(IV_SIZE);
    const cipher = createCipheriv('aes-256-gcm', this.sealingKey, iv);

    // Include key in AAD (additional authenticated data) to bind ciphertext to key name
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

    const iv = sealed.slice(0, IV_SIZE);
    const tag = sealed.slice(IV_SIZE, IV_SIZE + TAG_SIZE);
    const ciphertext = sealed.slice(IV_SIZE + TAG_SIZE);

    const decipher = createDecipheriv('aes-256-gcm', this.sealingKey, iv);
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
