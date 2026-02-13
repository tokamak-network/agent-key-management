import { describe, it, expect } from 'vitest';
import { createMemoryBoundary, wipeMemory } from './memory-boundary.js';

describe('createMemoryBoundary', () => {
  it('should block toJSON serialization', () => {
    const secret = createMemoryBoundary({ key: 'private-data' }, 'test-key');

    expect(() => JSON.stringify(secret)).toThrow('Cannot serialize');
  });

  it('should allow normal property access', () => {
    const secret = createMemoryBoundary({ key: 'private-data' }, 'test-key');

    expect(secret.key).toBe('private-data');
  });

  it('should return safe string representation', () => {
    const secret = createMemoryBoundary({ key: 'private-data' }, 'test-key');

    expect(secret.toString()).toBe('[TEE Protected: test-key]');
  });
});

describe('wipeMemory', () => {
  it('should zero out the array', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    wipeMemory(data);

    expect(data.every((b) => b === 0)).toBe(true);
  });
});
