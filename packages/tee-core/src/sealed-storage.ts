/**
 * Sealed storage interface for TEE environments.
 * Data sealed by one enclave instance can only be unsealed by the same enclave
 * (identified by its measurement/code hash).
 */
export interface ISealedStorage {
  /** Encrypt and store data, bound to the current enclave identity */
  seal(key: string, data: Uint8Array): Promise<void>;

  /** Decrypt and retrieve data; fails if enclave identity doesn't match */
  unseal(key: string): Promise<Uint8Array>;

  /** Check if a sealed entry exists */
  has(key: string): Promise<boolean>;

  /** Delete a sealed entry */
  delete(key: string): Promise<boolean>;

  /** List all sealed entry keys */
  list(): Promise<string[]>;
}
