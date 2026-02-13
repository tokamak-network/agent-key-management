import { describe, it, expect } from 'vitest';
import type { TappdClient, Hex } from '@phala/dstack-sdk';
import { DstackRuntime } from './dstack-runtime.js';

const MOCK_MRTD = 'mock-mrtd-measurement';
const MOCK_APP_ID = 'test-app';
const MOCK_QUOTE: Hex = '0xdeadbeef';

function createMockClient(): TappdClient {
  return {
    deriveKey: async () => ({
      key: '',
      certificate_chain: [],
      asUint8Array: (maxLength?: number) => new Uint8Array(maxLength ?? 32).fill(0x42),
    }),
    tdxQuote: async () => ({
      quote: MOCK_QUOTE,
      event_log: '',
      replayRtmrs: () => [],
    }),
    info: async () => ({
      app_id: MOCK_APP_ID,
      instance_id: 'inst-1',
      app_cert: '',
      app_name: 'test',
      public_logs: false,
      public_sysinfo: false,
      tcb_info: {
        mrtd: MOCK_MRTD,
        rootfs_hash: '',
        rtmr0: '', rtmr1: '', rtmr2: '', rtmr3: '',
        event_log: [],
      },
    }),
  } as unknown as TappdClient;
}

function createUnreachableClient(): TappdClient {
  return {
    deriveKey: async () => { throw new Error('connection refused'); },
    tdxQuote: async () => { throw new Error('connection refused'); },
    info: async () => { throw new Error('connection refused'); },
  } as unknown as TappdClient;
}

describe('DstackRuntime', () => {
  it('should initialize successfully and expose all interfaces', async () => {
    const runtime = new DstackRuntime({ client: createMockClient() });
    await runtime.initialize();

    expect(runtime.provider).toBe('dstack');
    expect(runtime.sealedStorage).toBeDefined();
    expect(runtime.attestation).toBeDefined();

    await runtime.destroy();
  });

  it('should fail initialization when dstack is unreachable', async () => {
    const runtime = new DstackRuntime({ client: createUnreachableClient() });

    await expect(runtime.initialize()).rejects.toThrow('connection refused');
  });

  it('should generate random bytes of requested length', () => {
    const runtime = new DstackRuntime({ client: createMockClient() });
    const bytes = runtime.getRandomBytes(32);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
    expect(bytes.some((b) => b !== 0)).toBe(true);
  });

  it('should return measurement from dstack info', async () => {
    const runtime = new DstackRuntime({ client: createMockClient() });
    const measurement = await runtime.getMeasurement();

    expect(measurement).toBe(MOCK_MRTD);
  });

  it('should cache measurement across calls', async () => {
    let infoCallCount = 0;
    const client = createMockClient();
    const origInfo = client.info.bind(client);
    client.info = async () => {
      infoCallCount++;
      return origInfo();
    };

    const runtime = new DstackRuntime({ client });
    await runtime.getMeasurement();
    await runtime.getMeasurement();

    expect(infoCallCount).toBe(1);
  });

  it('should seal/unseal data through runtime after initialization', async () => {
    const runtime = new DstackRuntime({ client: createMockClient() });
    await runtime.initialize();

    const data = new TextEncoder().encode('private-key-material');
    await runtime.sealedStorage.seal('root-key', data);
    const unsealed = await runtime.sealedStorage.unseal('root-key');

    expect(unsealed).toEqual(data);
  });

  it('should generate attestation reports through runtime', async () => {
    const runtime = new DstackRuntime({ client: createMockClient() });
    const report = await runtime.attestation.generateReport('test-data');

    expect(report.provider).toBe('dstack');
    expect(report.measurements.mrEnclave).toBe(MOCK_MRTD);
    expect(report.signature).toBe(MOCK_QUOTE);
  });

  it('should generate attestation quotes through runtime', async () => {
    const runtime = new DstackRuntime({ client: createMockClient() });
    const quote = await runtime.attestation.generateQuote('nonce-1', '04pubkey');

    expect(quote.nonce).toBe('nonce-1');
    expect(quote.rootPublicKey).toBe('04pubkey');
    expect(quote.report.provider).toBe('dstack');
  });
});
