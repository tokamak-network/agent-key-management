import { describe, it, expect } from 'vitest';
import type { TappdClient, Hex } from '@phala/dstack-sdk';
import { DstackAttestationProvider } from './dstack-attestation.js';

const MOCK_MRTD = 'mock-mrtd-measurement-hash';
const MOCK_APP_ID = 'test-app-id';
const MOCK_QUOTE: Hex = '0xdeadbeefcafebabe';

function createMockClient(): TappdClient {
  return {
    deriveKey: async () => ({
      key: '',
      certificate_chain: [],
      asUint8Array: () => new Uint8Array(32),
    }),
    tdxQuote: async () => ({
      quote: MOCK_QUOTE,
      event_log: '',
      replayRtmrs: () => [],
    }),
    info: async () => ({
      app_id: MOCK_APP_ID,
      instance_id: 'test-instance',
      app_cert: '',
      app_name: 'test-app',
      public_logs: false,
      public_sysinfo: false,
      tcb_info: {
        mrtd: MOCK_MRTD,
        rootfs_hash: 'rootfs-hash',
        rtmr0: 'rtmr0',
        rtmr1: 'rtmr1',
        rtmr2: 'rtmr2',
        rtmr3: 'rtmr3',
        event_log: [],
      },
    }),
  } as unknown as TappdClient;
}

describe('DstackAttestationProvider', () => {
  it('should generate attestation report with dstack provider', async () => {
    const attestation = new DstackAttestationProvider(createMockClient());
    const report = await attestation.generateReport('test-user-data');

    expect(report.provider).toBe('dstack');
    expect(report.measurements.mrEnclave).toBe(MOCK_MRTD);
    expect(report.measurements.mrSigner).toBe(MOCK_APP_ID);
    expect(report.userData).toBe('test-user-data');
    expect(report.signature).toBe(MOCK_QUOTE);
    expect(report.timestamp).toBeGreaterThan(0);
  });

  it('should generate attestation quote with nonce and publicKey binding', async () => {
    const attestation = new DstackAttestationProvider(createMockClient());
    const quote = await attestation.generateQuote('nonce-123', '04abcdef');

    expect(quote.nonce).toBe('nonce-123');
    expect(quote.rootPublicKey).toBe('04abcdef');
    expect(quote.report.provider).toBe('dstack');
    expect(quote.report.signature).toBe(MOCK_QUOTE);
  });

  it('should cache measurements across calls', async () => {
    let infoCallCount = 0;
    const client = createMockClient();
    const origInfo = client.info.bind(client);
    client.info = async () => {
      infoCallCount++;
      return origInfo();
    };

    const attestation = new DstackAttestationProvider(client);
    await attestation.generateReport('data-1');
    await attestation.generateReport('data-2');

    // info() should only be called once due to caching
    expect(infoCallCount).toBe(1);
  });

  it('should include different userData in different reports', async () => {
    const attestation = new DstackAttestationProvider(createMockClient());
    const report1 = await attestation.generateReport('user-data-1');
    const report2 = await attestation.generateReport('user-data-2');

    expect(report1.userData).toBe('user-data-1');
    expect(report2.userData).toBe('user-data-2');
  });
});
