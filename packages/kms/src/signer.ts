import { toAccount } from 'viem/accounts';
import {
  type Account,
  type LocalAccount,
  type SerializeTransactionFn,
  type SignableMessage,
  type TypedDataDefinition,
  hashMessage,
  hashTypedData,
  keccak256,
  serializeTransaction,
} from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { KeyId, SigningContext } from '@akm/types';
import type { ISealedStorage } from '@akm/tee-core';
import type { PolicyEngine } from '@akm/policy-engine';
import { KeyStore } from './key-store.js';
import { wipeMemory } from '@akm/tee-simulator';

/**
 * Creates a viem-compatible account that signs transactions inside the TEE.
 * Private keys never leave the TEE boundary.
 *
 * Follows the Phala dstack pattern of using viem's toAccount() with custom signing.
 */
export function createTeeAccount(
  keyId: KeyId | string,
  address: `0x${string}`,
  sealedStorage: ISealedStorage,
  keyStore: KeyStore,
  policyEngine?: PolicyEngine,
  callerId?: string,
): LocalAccount {
  const account = toAccount({
    address,

    async signMessage({ message }: { message: SignableMessage }) {
      await checkPolicy(keyId, callerId, policyEngine, {
        callerId: callerId ?? 'unknown',
        keyId: keyId as string,
        timestamp: Date.now(),
      });

      const hash = hashMessage(message);
      return signHash(hash, keyId as string, sealedStorage);
    },

    async signTransaction(transaction: any) {
      const value = transaction.value ? BigInt(transaction.value) : 0n;
      await checkPolicy(keyId, callerId, policyEngine, {
        callerId: callerId ?? 'unknown',
        keyId: keyId as string,
        to: transaction.to,
        value,
        data: transaction.data,
        chainId: transaction.chainId,
        timestamp: Date.now(),
      });

      const serialized = serializeTransaction(transaction);
      const hash = keccak256(serialized);
      return signHash(hash, keyId as string, sealedStorage);
    },

    async signTypedData(typedData: TypedDataDefinition) {
      await checkPolicy(keyId, callerId, policyEngine, {
        callerId: callerId ?? 'unknown',
        keyId: keyId as string,
        timestamp: Date.now(),
      });

      const hash = hashTypedData(typedData);
      return signHash(hash, keyId as string, sealedStorage);
    },
  });

  return account;
}

async function checkPolicy(
  keyId: KeyId | string,
  callerId: string | undefined,
  policyEngine: PolicyEngine | undefined,
  context: SigningContext,
): Promise<void> {
  if (!policyEngine) return;

  const result = policyEngine.evaluate(context);
  if (result.verdict === 'deny') {
    throw new Error(`Policy denied: [${result.ruleName}] ${result.reason}`);
  }
}

async function signHash(
  hash: `0x${string}`,
  keyId: string,
  sealedStorage: ISealedStorage,
): Promise<`0x${string}`> {
  const privateKey = await sealedStorage.unseal(`derived:${keyId}`);

  try {
    const hashBytes = hexToBytes(hash.slice(2));
    const sig = secp256k1.sign(hashBytes, privateKey);

    // Construct Ethereum signature: r + s + v
    const r = sig.r.toString(16).padStart(64, '0');
    const s = sig.s.toString(16).padStart(64, '0');
    const v = (sig.recovery + 27).toString(16).padStart(2, '0');

    return `0x${r}${s}${v}` as `0x${string}`;
  } finally {
    wipeMemory(privateKey);
  }
}
