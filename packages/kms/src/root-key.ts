import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import type { ISealedStorage } from '@akm/tee-core';

const ROOT_KEY_STORAGE_ID = 'root-key:secp256k1';
const ROOT_PUBLIC_KEY_ID = 'root-key:public';

/**
 * Manages the root secp256k1 key pair inside the TEE.
 * The root key is generated once and sealed; all agent keys are derived from it.
 */
export class RootKeyManager {
  constructor(private readonly sealedStorage: ISealedStorage) {}

  /**
   * Initialize root key: generate if not exists, or load from sealed storage.
   * Returns the public key (safe to expose outside TEE).
   */
  async initialize(entropy?: Uint8Array): Promise<string> {
    const exists = await this.sealedStorage.has(ROOT_KEY_STORAGE_ID);

    if (!exists) {
      return this.generateAndSeal(entropy);
    }

    return this.getPublicKey();
  }

  /** Generate a new root key pair and seal it */
  private async generateAndSeal(entropy?: Uint8Array): Promise<string> {
    const privateKeyBytes = entropy ?? secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKeyBytes, false);

    // Seal the private key
    await this.sealedStorage.seal(ROOT_KEY_STORAGE_ID, privateKeyBytes);
    // Store public key separately (can be retrieved without unsealing private key)
    await this.sealedStorage.seal(ROOT_PUBLIC_KEY_ID, publicKey);

    return bytesToHex(publicKey);
  }

  /** Get the root public key (safe to share) */
  async getPublicKey(): Promise<string> {
    const publicKeyBytes = await this.sealedStorage.unseal(ROOT_PUBLIC_KEY_ID);
    return bytesToHex(publicKeyBytes);
  }

  /** Get the sealed root private key bytes (TEE internal use only) */
  async getPrivateKey(): Promise<Uint8Array> {
    return this.sealedStorage.unseal(ROOT_KEY_STORAGE_ID);
  }

  /** Check if root key has been initialized */
  async isInitialized(): Promise<boolean> {
    return this.sealedStorage.has(ROOT_KEY_STORAGE_ID);
  }
}
