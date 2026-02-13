import { describe, it, expect } from 'vitest';
import { SimulatedRuntime } from './simulated-runtime.js';

describe('SimulatedRuntime', () => {
  it('should initialize and provide all interfaces', async () => {
    const runtime = new SimulatedRuntime();
    await runtime.initialize();

    expect(runtime.provider).toBe('simulator');
    expect(runtime.sealedStorage).toBeDefined();
    expect(runtime.attestation).toBeDefined();

    await runtime.destroy();
  });

  it('should generate random bytes of requested length', () => {
    const runtime = new SimulatedRuntime();
    const bytes = runtime.getRandomBytes(32);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);

    // Ensure not all zeros (extremely unlikely with real random)
    expect(bytes.some((b) => b !== 0)).toBe(true);
  });

  it('should return deterministic measurement for same config', async () => {
    const r1 = new SimulatedRuntime({ fixedMeasurement: 'abc123' });
    const r2 = new SimulatedRuntime({ fixedMeasurement: 'abc123' });

    expect(await r1.getMeasurement()).toBe(await r2.getMeasurement());
  });

  it('should generate attestation reports', async () => {
    const runtime = new SimulatedRuntime({ fixedMeasurement: 'test-measure' });
    const report = await runtime.attestation.generateReport('test-user-data');

    expect(report.provider).toBe('simulator');
    expect(report.measurements.mrEnclave).toBe('test-measure');
    expect(report.userData).toBe('test-user-data');
    expect(report.signature).toBeTruthy();
  });

  it('should generate attestation quotes', async () => {
    const runtime = new SimulatedRuntime({ fixedMeasurement: 'test-measure' });
    const quote = await runtime.attestation.generateQuote('nonce-123', '04abcdef...');

    expect(quote.nonce).toBe('nonce-123');
    expect(quote.rootPublicKey).toBe('04abcdef...');
    expect(quote.report.provider).toBe('simulator');
  });

  it('should seal/unseal data through runtime', async () => {
    const runtime = new SimulatedRuntime({ fixedMeasurement: 'test' });
    const data = new TextEncoder().encode('private-key-material');

    await runtime.sealedStorage.seal('root-key', data);
    const unsealed = await runtime.sealedStorage.unseal('root-key');

    expect(unsealed).toEqual(data);
  });
});
