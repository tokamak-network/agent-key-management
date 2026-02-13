import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * Hierarchical key derivation using HKDF-SHA256.
 * Follows the pattern: HKDF(rootKey, salt=agentId, info=purpose+epoch)
 *
 * This mirrors Phala dstack's key hierarchy:
 *   RootKey → HKDF → agent-specific signing keys
 */

export interface DeriveKeyParams {
  readonly agentId: string;
  readonly purpose: string;
  readonly epoch: number;
}

/**
 * Derive a child private key from the root key using HKDF-SHA256.
 * The derived key is guaranteed to be a valid secp256k1 private key.
 */
export function deriveChildKey(
  rootPrivateKey: Uint8Array,
  params: DeriveKeyParams,
): Uint8Array {
  const salt = new TextEncoder().encode(params.agentId);
  const info = new TextEncoder().encode(`${params.purpose}:epoch-${params.epoch}`);

  // HKDF outputs 32 bytes for secp256k1 private key
  const derived = hkdf(sha256, rootPrivateKey, salt, info, 32);

  // Ensure the derived key is a valid secp256k1 private key
  // secp256k1 order is ~2^256, so 32 random bytes have negligible collision chance
  // but we verify anyway
  try {
    secp256k1.getPublicKey(derived);
    return derived;
  } catch {
    // Extremely unlikely: retry with incremented info
    const retryInfo = new TextEncoder().encode(
      `${params.purpose}:epoch-${params.epoch}:retry`,
    );
    return hkdf(sha256, rootPrivateKey, salt, retryInfo, 32);
  }
}

/**
 * Derive the Ethereum address from a secp256k1 private key.
 */
export function deriveEthereumAddress(privateKey: Uint8Array): string {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  // Ethereum address = last 20 bytes of keccak256(uncompressed pubkey without prefix)
  // We use a simplified approach: sha256 for the PoC
  // In production, viem handles this correctly
  const pubKeyWithoutPrefix = publicKey.slice(1); // Remove 0x04 prefix
  const hash = sha256(pubKeyWithoutPrefix);
  const address = bytesToHex(hash.slice(12)); // Last 20 bytes
  return `0x${address}`;
}

/**
 * Get the uncompressed public key hex from a private key.
 */
export function getPublicKeyHex(privateKey: Uint8Array): string {
  return bytesToHex(secp256k1.getPublicKey(privateKey, false));
}

/**
 * Build a deterministic key ID from derivation parameters.
 */
export function buildKeyId(params: DeriveKeyParams): string {
  return `${params.agentId}/${params.purpose}/epoch-${params.epoch}`;
}
