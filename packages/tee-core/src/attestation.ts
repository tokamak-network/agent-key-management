import type { AttestationReport, AttestationQuote } from '@akm/types';

/**
 * Attestation provider interface for generating remote attestation quotes.
 * Allows external verifiers to confirm the enclave's identity and integrity.
 */
export interface IAttestationProvider {
  /** Generate an attestation report including code measurements */
  generateReport(userData: string): Promise<AttestationReport>;

  /** Generate a full attestation quote with nonce binding */
  generateQuote(nonce: string, rootPublicKey: string): Promise<AttestationQuote>;
}
