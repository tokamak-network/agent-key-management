import { describe, it, expect } from 'vitest';
import { SimulatedSealedStorage } from './sealed-storage.js';

describe('SimulatedSealedStorage', () => {
  const measurement = 'test-measurement-hash-abc123';

  it('should seal and unseal data (roundtrip)', async () => {
    const storage = new SimulatedSealedStorage(measurement);
    const data = new TextEncoder().encode('secret-private-key-data');

    await storage.seal('my-key', data);
    const unsealed = await storage.unseal('my-key');

    expect(unsealed).toEqual(data);
  });

  it('should throw when unsealing non-existent key', async () => {
    const storage = new SimulatedSealedStorage(measurement);

    await expect(storage.unseal('missing')).rejects.toThrow('No sealed data found');
  });

  it('should detect tampering (different measurement)', async () => {
    const storage1 = new SimulatedSealedStorage('measurement-1');
    const storage2 = new SimulatedSealedStorage('measurement-2');

    const data = new TextEncoder().encode('secret');
    await storage1.seal('key', data);

    // Manually copy the sealed data to storage2's internal store
    // This simulates data sealed by a different enclave
    const sealedData = await (storage1 as any).store.get('key');
    (storage2 as any).store.set('key', sealedData);

    await expect(storage2.unseal('key')).rejects.toThrow('tampering detected');
  });

  it('should report existence correctly', async () => {
    const storage = new SimulatedSealedStorage(measurement);

    expect(await storage.has('key')).toBe(false);
    await storage.seal('key', new Uint8Array([1, 2, 3]));
    expect(await storage.has('key')).toBe(true);
  });

  it('should delete sealed entries', async () => {
    const storage = new SimulatedSealedStorage(measurement);
    await storage.seal('key', new Uint8Array([1, 2, 3]));

    expect(await storage.delete('key')).toBe(true);
    expect(await storage.has('key')).toBe(false);
    expect(await storage.delete('key')).toBe(false);
  });

  it('should list all sealed keys', async () => {
    const storage = new SimulatedSealedStorage(measurement);
    await storage.seal('a', new Uint8Array([1]));
    await storage.seal('b', new Uint8Array([2]));
    await storage.seal('c', new Uint8Array([3]));

    const keys = await storage.list();
    expect(keys).toEqual(expect.arrayContaining(['a', 'b', 'c']));
    expect(keys).toHaveLength(3);
  });

  it('should handle overwriting sealed data', async () => {
    const storage = new SimulatedSealedStorage(measurement);
    await storage.seal('key', new TextEncoder().encode('original'));
    await storage.seal('key', new TextEncoder().encode('updated'));

    const result = new TextDecoder().decode(await storage.unseal('key'));
    expect(result).toBe('updated');
  });
});
