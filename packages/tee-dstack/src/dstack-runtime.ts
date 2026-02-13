import { randomBytes } from 'node:crypto';
import type { ITeeRuntime } from '@akm/tee-core';
import { TappdClient } from '@phala/dstack-sdk';
import { DstackSealedStorage } from './dstack-sealed-storage.js';
import { DstackAttestationProvider } from './dstack-attestation.js';

export interface DstackRuntimeOptions {
  /** dstack simulator endpoint override (e.g. http://localhost:8090) */
  endpoint?: string;
  /** Inject a TappdClient instance (for testing) */
  client?: TappdClient;
}

/**
 * TEE runtime backed by Phala dstack (Intel TDX).
 * Uses TappdClient for key derivation, attestation, and identity.
 */
export class DstackRuntime implements ITeeRuntime {
  readonly provider = 'dstack' as const;
  readonly sealedStorage: DstackSealedStorage;
  readonly attestation: DstackAttestationProvider;

  private readonly client: TappdClient;
  private cachedMeasurement: string | null = null;

  constructor(options?: DstackRuntimeOptions) {
    this.client = options?.client ?? new TappdClient(options?.endpoint);
    this.sealedStorage = new DstackSealedStorage(this.client);
    this.attestation = new DstackAttestationProvider(this.client);
  }

  getRandomBytes(length: number): Uint8Array {
    return new Uint8Array(randomBytes(length));
  }

  async getMeasurement(): Promise<string> {
    if (this.cachedMeasurement) return this.cachedMeasurement;

    const info = await this.client.info();
    this.cachedMeasurement = info.tcb_info.mrtd;
    return this.cachedMeasurement;
  }

  async initialize(): Promise<void> {
    // Verify dstack is reachable by fetching info
    await this.client.info();
    // Initialize sealed storage (derives sealing key)
    await this.sealedStorage.initialize();
  }

  async destroy(): Promise<void> {
    // No persistent resources to clean up
  }
}
