import type { ISealedStorage } from './sealed-storage.js';
import type { IAttestationProvider } from './attestation.js';

export type TeeProvider = 'simulator' | 'dstack' | 'nitro';

/**
 * Main TEE runtime interface.
 * Implementations provide sealed storage, attestation, and entropy.
 */
export interface ITeeRuntime {
  readonly provider: TeeProvider;

  /** Sealed storage for persisting encrypted data */
  readonly sealedStorage: ISealedStorage;

  /** Remote attestation provider */
  readonly attestation: IAttestationProvider;

  /** Generate cryptographically secure random bytes inside TEE */
  getRandomBytes(length: number): Uint8Array;

  /** Get the code measurement (hash) of the running enclave */
  getMeasurement(): Promise<string>;

  /** Initialize the runtime */
  initialize(): Promise<void>;

  /** Cleanup resources */
  destroy(): Promise<void>;
}
