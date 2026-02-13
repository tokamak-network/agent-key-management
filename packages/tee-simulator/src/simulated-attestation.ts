import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { IAttestationProvider } from '@akm/tee-core';
import type { AttestationReport, AttestationQuote, CodeMeasurements } from '@akm/types';

/**
 * Simulated attestation provider.
 * Generates mock attestation reports that mimic the structure of
 * real TEE attestation (SGX/TDX/Nitro).
 */
export class SimulatedAttestationProvider implements IAttestationProvider {
  private readonly measurements: CodeMeasurements;
  private readonly signingSecret: string;

  constructor(mrEnclave: string, mrSigner: string) {
    this.measurements = {
      mrEnclave,
      mrSigner,
      productId: 1,
      svn: 1,
    };
    // In a real TEE, the attestation key is provisioned by hardware
    this.signingSecret = `sim-attest-key:${mrEnclave}`;
  }

  async generateReport(userData: string): Promise<AttestationReport> {
    const timestamp = Date.now();

    const signaturePayload = JSON.stringify({
      measurements: this.measurements,
      userData,
      timestamp,
    });

    const signature = bytesToHex(
      sha256(new TextEncoder().encode(`${this.signingSecret}:${signaturePayload}`)),
    );

    return {
      provider: 'simulator',
      timestamp,
      measurements: this.measurements,
      userData,
      signature,
    };
  }

  async generateQuote(nonce: string, rootPublicKey: string): Promise<AttestationQuote> {
    // Bind the root public key and nonce into the attestation
    const userData = bytesToHex(
      sha256(new TextEncoder().encode(`${nonce}:${rootPublicKey}`)),
    );

    const report = await this.generateReport(userData);

    return {
      report,
      nonce,
      rootPublicKey,
    };
  }
}
