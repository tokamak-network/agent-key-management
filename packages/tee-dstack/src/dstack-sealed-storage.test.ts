import { describe, it, expect } from 'vitest';
import type { TappdClient } from '@phala/dstack-sdk';
import { DstackSealedStorage } from './dstack-sealed-storage.js';

function createMockClient(keyBytes: Uint8Array = new Uint8Array(32).fill(0x42)): TappdClient {
  return {
    deriveKey: async () => ({
      key: '',
      certificate_chain: [],
      asUint8Array: (maxLength?: number) => keyBytes.slice(0, maxLength ?? keyBytes.length),
    }),
    tdxQuote: async () => ({ quote: '0x' as const, event_log: '', replayRtmrs: () => [] }),
    info: async () => ({
      app_id: '', instance_id: '', app_cert: '', app_name: '',
      public_logs: false, public_sysinfo: false,
      tcb_info: { mrtd: '', rootfs_hash: '', rtmr0: '', rtmr1: '', rtmr2: '', rtmr3: '', event_log: [] },
    }),
  } as unknown as TappdClient;
}

describe('DstackSealedStorage', () => {
  it('should seal and unseal data (roundtrip)', async () => {
    const storage = new DstackSealedStorage(createMockClient());
    await storage.initialize();

    const data = new TextEncoder().encode('secret-private-key-data');
    await storage.seal('my-key', data);
    const unsealed = await storage.unseal('my-key');

    expect(unsealed).toEqual(data);
  });

  it('should throw when not initialized', async () => {
    const storage = new DstackSealedStorage(createMockClient());

    await expect(storage.seal('key', new Uint8Array([1]))).rejects.toThrow('not initialized');
  });

  it('should throw when unsealing non-existent key', async () => {
    const storage = new DstackSealedStorage(createMockClient());
    await storage.initialize();

    await expect(storage.unseal('missing')).rejects.toThrow('No sealed data found');
  });

  it('should detect tampering (different sealing key)', async () => {
    const storage1 = new DstackSealedStorage(createMockClient(new Uint8Array(32).fill(0x01)));
    const storage2 = new DstackSealedStorage(createMockClient(new Uint8Array(32).fill(0x02)));
    await storage1.initialize();
    await storage2.initialize();

    const data = new TextEncoder().encode('secret');
    await storage1.seal('key', data);

    // Copy sealed data to storage2 (simulates data from different enclave)
    const sealedData = (storage1 as any).store.get('key');
    (storage2 as any).store.set('key', sealedData);

    await expect(storage2.unseal('key')).rejects.toThrow('tampering detected');
  });

  it('should report existence correctly', async () => {
    const storage = new DstackSealedStorage(createMockClient());
    await storage.initialize();

    expect(await storage.has('key')).toBe(false);
    await storage.seal('key', new Uint8Array([1, 2, 3]));
    expect(await storage.has('key')).toBe(true);
  });

  it('should delete sealed entries', async () => {
    const storage = new DstackSealedStorage(createMockClient());
    await storage.initialize();
    await storage.seal('key', new Uint8Array([1, 2, 3]));

    expect(await storage.delete('key')).toBe(true);
    expect(await storage.has('key')).toBe(false);
    expect(await storage.delete('key')).toBe(false);
  });

  it('should list all sealed keys', async () => {
    const storage = new DstackSealedStorage(createMockClient());
    await storage.initialize();
    await storage.seal('a', new Uint8Array([1]));
    await storage.seal('b', new Uint8Array([2]));
    await storage.seal('c', new Uint8Array([3]));

    const keys = await storage.list();
    expect(keys).toEqual(expect.arrayContaining(['a', 'b', 'c']));
    expect(keys).toHaveLength(3);
  });

  it('should handle overwriting sealed data', async () => {
    const storage = new DstackSealedStorage(createMockClient());
    await storage.initialize();
    await storage.seal('key', new TextEncoder().encode('original'));
    await storage.seal('key', new TextEncoder().encode('updated'));

    const result = new TextDecoder().decode(await storage.unseal('key'));
    expect(result).toBe('updated');
  });
});
