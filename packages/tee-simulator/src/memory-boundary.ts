/**
 * Creates a Proxy that prevents private key material from being serialized
 * or leaked outside the TEE boundary.
 *
 * This is a simulation — in a real TEE, memory isolation is hardware-enforced.
 */
export function createMemoryBoundary<T extends object>(
  value: T,
  label: string,
): T {
  return new Proxy(value, {
    get(target, prop, receiver) {
      // Block serialization attempts
      if (prop === 'toJSON') {
        return () => {
          throw new Error(
            `[TEE Boundary] Cannot serialize ${label}: data must not leave TEE`,
          );
        };
      }
      if (prop === Symbol.toPrimitive || prop === 'toString' || prop === 'valueOf') {
        if (prop === 'toString') {
          return () => `[TEE Protected: ${label}]`;
        }
        return () => {
          throw new Error(
            `[TEE Boundary] Cannot convert ${label} to primitive: data must not leave TEE`,
          );
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/**
 * Securely wipe a Uint8Array from memory.
 * Best-effort in JavaScript — real TEEs provide hardware guarantees.
 */
export function wipeMemory(data: Uint8Array): void {
  data.fill(0);
  // Fill with random data to make recovery harder
  for (let i = 0; i < data.length; i++) {
    data[i] = Math.random() * 256 | 0;
  }
  data.fill(0);
}
