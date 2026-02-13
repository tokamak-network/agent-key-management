import type { ITeeRuntime } from '@akm/tee-core';
import { SimulatedRuntime } from '@akm/tee-simulator';
import { RootKeyManager, KeyStore, KeyLifecycleManager, createTeeAccount } from '@akm/kms';
import { PolicyEngine } from '@akm/policy-engine';
import { QuoteGenerator } from '@akm/attestation';
import { AttestationVerifier } from '@akm/attestation';
import type { KeyId, PolicyRuleConfig, SigningContext } from '@akm/types';

/**
 * TEE Bridge: the boundary between untrusted API layer and trusted TEE internals.
 * This factory creates the appropriate TEE runtime and wires up all services.
 */
export interface TeeServices {
  readonly runtime: ITeeRuntime;
  readonly rootKeyManager: RootKeyManager;
  readonly keyStore: KeyStore;
  readonly keyLifecycle: KeyLifecycleManager;
  readonly quoteGenerator: QuoteGenerator;
  readonly verifier: AttestationVerifier;
  createPolicyEngine(rules: PolicyRuleConfig[]): PolicyEngine;
  createAccount(keyId: string, callerId: string): Promise<ReturnType<typeof createTeeAccount>>;
  evaluatePolicy(keyId: string, context: SigningContext): Promise<{ verdict: string; reason: string }>;
}

export async function createTeeServices(): Promise<TeeServices> {
  const provider = process.env.TEE_PROVIDER ?? 'simulator';

  let runtime: ITeeRuntime;

  switch (provider) {
    case 'simulator':
      runtime = new SimulatedRuntime({ fixedMeasurement: 'akm-poc-v1' });
      break;
    // Future:
    // case 'dstack': runtime = new DstackRuntime(); break;
    // case 'nitro':  runtime = new NitroRuntime(); break;
    default:
      throw new Error(`Unknown TEE provider: ${provider}`);
  }

  await runtime.initialize();

  const rootKeyManager = new RootKeyManager(runtime.sealedStorage);
  await rootKeyManager.initialize();

  const keyStore = new KeyStore();
  const keyLifecycle = new KeyLifecycleManager(rootKeyManager, keyStore, runtime.sealedStorage);
  const quoteGenerator = new QuoteGenerator(runtime.attestation);
  const verifier = new AttestationVerifier();

  // Per-key policy engines cache
  const policyEngines = new Map<string, PolicyEngine>();

  return {
    runtime,
    rootKeyManager,
    keyStore,
    keyLifecycle,
    quoteGenerator,
    verifier,

    createPolicyEngine(rules: PolicyRuleConfig[]): PolicyEngine {
      return PolicyEngine.fromConfig(rules);
    },

    async createAccount(keyId: string, callerId: string) {
      const meta = keyStore.get(keyId as KeyId);
      if (!meta) throw new Error(`Key not found: ${keyId}`);
      if (meta.status !== 'active') throw new Error(`Key is not active: ${keyId} (status: ${meta.status})`);

      // Get or create policy engine for this key
      let engine = policyEngines.get(keyId);
      if (!engine) {
        const rules = keyStore.getPolicy(keyId);
        if (rules.length > 0) {
          engine = PolicyEngine.fromConfig(rules);
          policyEngines.set(keyId, engine);
        }
      }

      return createTeeAccount(
        keyId,
        meta.ethereumAddress as `0x${string}`,
        runtime.sealedStorage,
        keyStore,
        engine,
        callerId,
      );
    },

    async evaluatePolicy(keyId: string, context: SigningContext) {
      let engine = policyEngines.get(keyId);
      if (!engine) {
        const rules = keyStore.getPolicy(keyId);
        if (rules.length > 0) {
          engine = PolicyEngine.fromConfig(rules);
          policyEngines.set(keyId, engine);
        }
      }

      if (!engine) {
        return { verdict: 'allow', reason: 'No policy configured' };
      }

      const result = engine.evaluate(context);
      return { verdict: result.verdict, reason: result.reason };
    },
  };
}
