import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { IAttestationProvider } from '@akm/tee-core';
import type { AttestationReport, AttestationQuote, CodeMeasurements } from '@akm/types';
import type { TappdClient } from '@phala/dstack-sdk';

/**
 * Attestation provider backed by dstack TDX quotes.
 * Uses TappdClient.tdxQuote() for remote attestation and
 * TappdClient.info() for enclave identity measurements.
 */
export class DstackAttestationProvider implements IAttestationProvider {
  private readonly client: TappdClient;
  private cachedMeasurements: CodeMeasurements | null = null;

  constructor(client: TappdClient) {
    this.client = client;
  }

  private async getMeasurements(): Promise<CodeMeasurements> {
    if (this.cachedMeasurements) return this.cachedMeasurements;

    const info = await this.client.info();
    this.cachedMeasurements = {
      mrEnclave: info.tcb_info.mrtd,
      mrSigner: info.app_id,
      productId: 0,
      svn: 0,
    };
    return this.cachedMeasurements;
  }

  async generateReport(userData: string): Promise<AttestationReport> {
    const timestamp = Date.now();

    // Hash userData to create report data for TDX quote
    const reportData = bytesToHex(sha256(new TextEncoder().encode(userData)));

    const quoteResult = await this.client.tdxQuote(reportData, 'sha256');
    const measurements = await this.getMeasurements();

    return {
      provider: 'dstack',
      timestamp,
      measurements,
      userData,
      signature: quoteResult.quote,
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
