import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Simulates TEE code measurement by hashing source files.
 * In a real TEE, this would be the hardware-measured enclave hash.
 */
export function computeMeasurement(sourcePaths: string[]): string {
  const hasher = sha256.create();

  for (const srcPath of sourcePaths.sort()) {
    try {
      const stat = statSync(srcPath);
      if (stat.isDirectory()) {
        hashDirectory(hasher, srcPath);
      } else {
        hasher.update(readFileSync(srcPath));
      }
    } catch {
      // Skip missing files in simulation
    }
  }

  return bytesToHex(hasher.digest());
}

function hashDirectory(
  hasher: ReturnType<typeof sha256.create>,
  dirPath: string,
): void {
  const entries = readdirSync(dirPath).sort();
  for (const entry of entries) {
    const fullPath = join(dirPath, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      hashDirectory(hasher, fullPath);
    } else if (entry.endsWith('.ts') || entry.endsWith('.js')) {
      hasher.update(readFileSync(fullPath));
    }
  }
}

/**
 * Compute a deterministic signer measurement from a fixed identity string.
 * Used for the mrSigner field in attestation reports.
 */
export function computeSignerMeasurement(signerIdentity: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(signerIdentity)));
}
