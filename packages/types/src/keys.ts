/** Opaque branded type for key identifiers */
export type KeyId = string & { readonly __brand: 'KeyId' };

export function createKeyId(id: string): KeyId {
  return id as KeyId;
}

export type KeyAlgorithm = 'secp256k1';

export type KeyStatus = 'active' | 'rotated' | 'revoked';

export type KeyPurpose = 'signing' | 'encryption';

export interface KeyMetadata {
  readonly id: KeyId;
  readonly algorithm: KeyAlgorithm;
  readonly status: KeyStatus;
  readonly purpose: KeyPurpose;
  readonly agentId: string;
  readonly epoch: number;
  readonly ethereumAddress: string;
  readonly createdAt: number;
  readonly rotatedAt?: number;
  readonly revokedAt?: number;
}

export interface KeyCreationRequest {
  readonly agentId: string;
  readonly purpose: KeyPurpose;
  readonly algorithm?: KeyAlgorithm;
}

export interface KeyCreationResult {
  readonly keyId: KeyId;
  readonly ethereumAddress: string;
  readonly publicKey: string;
}

export interface KeyRotationResult {
  readonly previousKeyId: KeyId;
  readonly newKeyId: KeyId;
  readonly newEthereumAddress: string;
  readonly newPublicKey: string;
  readonly epoch: number;
}
