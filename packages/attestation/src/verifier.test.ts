import { describe, it, expect } from 'vitest';
import { SimulatedRuntime } from '@akm/tee-simulator';
import { QuoteGenerator } from './quote-generator.js';
import { AttestationVerifier } from './verifier.js';

describe('Attestation roundtrip', () => {
  const runtime = new SimulatedRuntime({ fixedMeasurement: 'test-enclave-hash' });
  const generator = new QuoteGenerator(runtime.attestation);
  const verifier = new AttestationVerifier();

  it('should generate and verify a valid quote', async () => {
    const quote = await generator.generate('04abcdef1234', 'nonce-42');
    const result = verifier.verify(quote);

    expect(result.valid).toBe(true);
    expect(result.report).toBeDefined();
    expect(result.report!.measurements.mrEnclave).toBe('test-enclave-hash');
  });

  it('should reject tampered quote (modified nonce)', async () => {
    const quote = await generator.generate('04abcdef1234', 'nonce-42');
    const tampered = { ...quote, nonce: 'tampered-nonce' };
    const result = verifier.verify(tampered);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('userData does not match');
  });

  it('should reject tampered quote (modified signature)', async () => {
    const quote = await generator.generate('04abcdef1234', 'nonce-42');
    const tampered = {
      ...quote,
      report: { ...quote.report, signature: 'deadbeef' },
    };
    const result = verifier.verify(tampered);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('signature is invalid');
  });

  it('should reject quote with wrong expected measurements', async () => {
    const quote = await generator.generate('04abcdef1234', 'nonce-42');
    const result = verifier.verify(quote, { mrEnclave: 'wrong-hash' });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('mrEnclave mismatch');
  });

  it('should accept quote with correct expected measurements', async () => {
    const quote = await generator.generate('04abcdef1234', 'nonce-42');
    const result = verifier.verify(quote, { mrEnclave: 'test-enclave-hash' });

    expect(result.valid).toBe(true);
  });

  it('should reject stale quotes', async () => {
    // We need to check staleness after signature passes, so we modify
    // the verifier's time window check. Manually construct a valid but old quote.
    const oldTimestamp = Date.now() - 10 * 60 * 1000;

    // Create a runtime that generates reports with old timestamp by
    // generating a quote and then rebuilding it with consistent signature
    const { sha256 } = await import('@noble/hashes/sha256');
    const { bytesToHex } = await import('@noble/hashes/utils');

    const nonce = 'nonce-stale';
    const rootPublicKey = '04abcdef1234';
    const userData = bytesToHex(
      sha256(new TextEncoder().encode(`${nonce}:${rootPublicKey}`)),
    );

    const measurements = {
      mrEnclave: 'test-enclave-hash',
      mrSigner: (await generator.generate(rootPublicKey, nonce)).report.measurements.mrSigner,
      productId: 1,
      svn: 1,
    };

    const signaturePayload = JSON.stringify({
      measurements,
      userData,
      timestamp: oldTimestamp,
    });
    const signingSecret = `sim-attest-key:${measurements.mrEnclave}`;
    const signature = bytesToHex(
      sha256(new TextEncoder().encode(`${signingSecret}:${signaturePayload}`)),
    );

    const staleQuote = {
      nonce,
      rootPublicKey,
      report: {
        provider: 'simulator' as const,
        timestamp: oldTimestamp,
        measurements,
        userData,
        signature,
      },
    };

    const result = verifier.verify(staleQuote);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('stale');
  });
});
