import { randomBytes } from 'node:crypto';
import { bytesToHex } from '@noble/hashes/utils';
import type { IAttestationProvider } from '@akm/tee-core';
import type { AttestationQuote } from '@akm/types';

/**
 * Generates attestation quotes by binding a nonce and root public key
 * to the enclave's attestation report.
 */
export class QuoteGenerator {
  constructor(private readonly attestationProvider: IAttestationProvider) {}

  /**
   * Generate a fresh attestation quote.
   * The nonce prevents replay attacks.
   */
  async generate(rootPublicKey: string, nonce?: string): Promise<AttestationQuote> {
    const actualNonce = nonce ?? bytesToHex(randomBytes(32));
    return this.attestationProvider.generateQuote(actualNonce, rootPublicKey);
  }
}
