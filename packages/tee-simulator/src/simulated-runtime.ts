import { randomBytes } from 'node:crypto';
import type { ITeeRuntime } from '@akm/tee-core';
import { SimulatedSealedStorage } from './sealed-storage.js';
import { SimulatedAttestationProvider } from './simulated-attestation.js';
import { computeMeasurement, computeSignerMeasurement } from './measurement.js';

const DEFAULT_SIGNER_IDENTITY = 'akm-tee-simulator-v1';

export interface SimulatedRuntimeOptions {
  /** Source paths to include in code measurement (optional) */
  sourcePaths?: string[];
  /** Fixed measurement hash (overrides source path hashing) */
  fixedMeasurement?: string;
  /** Signer identity string */
  signerIdentity?: string;
}

/**
 * Simulated TEE runtime for development and testing.
 * Provides the same interface as a real TEE but runs in normal process memory.
 */
export class SimulatedRuntime implements ITeeRuntime {
  readonly provider = 'simulator' as const;
  readonly sealedStorage: SimulatedSealedStorage;
  readonly attestation: SimulatedAttestationProvider;

  private readonly measurement: string;

  constructor(options: SimulatedRuntimeOptions = {}) {
    const signerIdentity = options.signerIdentity ?? DEFAULT_SIGNER_IDENTITY;

    if (options.fixedMeasurement) {
      this.measurement = options.fixedMeasurement;
    } else if (options.sourcePaths?.length) {
      this.measurement = computeMeasurement(options.sourcePaths);
    } else {
      // Default: deterministic measurement for testing
      this.measurement = computeMeasurement([]);
    }

    const mrSigner = computeSignerMeasurement(signerIdentity);

    this.sealedStorage = new SimulatedSealedStorage(this.measurement);
    this.attestation = new SimulatedAttestationProvider(this.measurement, mrSigner);
  }

  getRandomBytes(length: number): Uint8Array {
    return new Uint8Array(randomBytes(length));
  }

  async getMeasurement(): Promise<string> {
    return this.measurement;
  }

  async initialize(): Promise<void> {
    // No-op for simulator
  }

  async destroy(): Promise<void> {
    // No-op for simulator
  }
}
