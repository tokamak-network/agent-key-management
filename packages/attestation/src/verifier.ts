import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type {
  AttestationQuote,
  AttestationVerifyResult,
  CodeMeasurements,
} from '@akm/types';

/**
 * Verifies attestation quotes from TEE enclaves.
 * In a real deployment, this would verify hardware-backed signatures.
 * For the simulator, it re-computes the expected signature.
 */
export class AttestationVerifier {
  /**
   * Verify an attestation quote.
   */
  verify(
    quote: AttestationQuote,
    expectedMeasurements?: Partial<CodeMeasurements>,
  ): AttestationVerifyResult {
    const { report, nonce, rootPublicKey } = quote;

    // 1. Verify the userData binds nonce + rootPublicKey
    const expectedUserData = bytesToHex(
      sha256(new TextEncoder().encode(`${nonce}:${rootPublicKey}`)),
    );

    if (report.userData !== expectedUserData) {
      return {
        valid: false,
        reason: 'Quote userData does not match nonce + rootPublicKey binding',
      };
    }

    // 2. Verify the signature (simulator: re-compute HMAC-like signature)
    const signaturePayload = JSON.stringify({
      measurements: report.measurements,
      userData: report.userData,
      timestamp: report.timestamp,
    });

    const signingSecret = `sim-attest-key:${report.measurements.mrEnclave}`;
    const expectedSignature = bytesToHex(
      sha256(new TextEncoder().encode(`${signingSecret}:${signaturePayload}`)),
    );

    if (report.signature !== expectedSignature) {
      return {
        valid: false,
        reason: 'Attestation report signature is invalid (tampered or wrong enclave)',
      };
    }

    // 3. Verify measurements match expected (if provided)
    if (expectedMeasurements) {
      if (
        expectedMeasurements.mrEnclave &&
        report.measurements.mrEnclave !== expectedMeasurements.mrEnclave
      ) {
        return {
          valid: false,
          reason: `mrEnclave mismatch: expected ${expectedMeasurements.mrEnclave}, got ${report.measurements.mrEnclave}`,
        };
      }
      if (
        expectedMeasurements.mrSigner &&
        report.measurements.mrSigner !== expectedMeasurements.mrSigner
      ) {
        return {
          valid: false,
          reason: `mrSigner mismatch: expected ${expectedMeasurements.mrSigner}, got ${report.measurements.mrSigner}`,
        };
      }
    }

    // 4. Check timestamp freshness (within 5 minutes)
    const fiveMinutesMs = 5 * 60 * 1000;
    if (Math.abs(Date.now() - report.timestamp) > fiveMinutesMs) {
      return {
        valid: false,
        reason: 'Attestation report is stale (older than 5 minutes)',
      };
    }

    return {
      valid: true,
      report,
    };
  }
}
