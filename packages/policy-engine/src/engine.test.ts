import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine } from './engine.js';
import { CallerRule } from './rules/caller-rule.js';
import { SpendingLimitRule } from './rules/spending-limit-rule.js';
import { RateLimitRule } from './rules/rate-limit-rule.js';
import { AllowlistRule } from './rules/allowlist-rule.js';
import type { SigningContext } from '@akm/types';

function makeContext(overrides: Partial<SigningContext> = {}): SigningContext {
  return {
    callerId: 'agent-1',
    keyId: 'test-key',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('CallerRule', () => {
  it('should allow authorized callers', () => {
    const rule = new CallerRule(['agent-1', 'agent-2']);
    const result = rule.evaluate(makeContext({ callerId: 'agent-1' }));
    expect(result.verdict).toBe('allow');
  });

  it('should deny unauthorized callers', () => {
    const rule = new CallerRule(['agent-1']);
    const result = rule.evaluate(makeContext({ callerId: 'hacker' }));
    expect(result.verdict).toBe('deny');
  });
});

describe('SpendingLimitRule', () => {
  it('should allow within per-tx limit', () => {
    const rule = new SpendingLimitRule(
      1000000000000000000n, // 1 ETH
      10000000000000000000n, // 10 ETH daily
    );
    const result = rule.evaluate(makeContext({ value: 500000000000000000n })); // 0.5 ETH
    expect(result.verdict).toBe('allow');
  });

  it('should deny over per-tx limit', () => {
    const rule = new SpendingLimitRule(
      1000000000000000000n, // 1 ETH
      10000000000000000000n, // 10 ETH daily
    );
    const result = rule.evaluate(makeContext({ value: 2000000000000000000n })); // 2 ETH
    expect(result.verdict).toBe('deny');
    expect(result.reason).toContain('per-tx limit');
  });

  it('should track daily spending and deny over daily limit', () => {
    const rule = new SpendingLimitRule(
      5000000000000000000n, // 5 ETH per tx
      3000000000000000000n, // 3 ETH daily
    );
    const now = Date.now();

    const r1 = rule.evaluate(makeContext({ value: 2000000000000000000n, timestamp: now }));
    expect(r1.verdict).toBe('allow');

    const r2 = rule.evaluate(makeContext({ value: 2000000000000000000n, timestamp: now }));
    expect(r2.verdict).toBe('deny');
    expect(r2.reason).toContain('Daily spending');
  });
});

describe('RateLimitRule', () => {
  it('should allow within rate limit', () => {
    const rule = new RateLimitRule(5);
    const now = Date.now();

    for (let i = 0; i < 5; i++) {
      const result = rule.evaluate(makeContext({ timestamp: now + i }));
      expect(result.verdict).toBe('allow');
    }
  });

  it('should deny when exceeding rate limit', () => {
    const rule = new RateLimitRule(3);
    const now = Date.now();

    for (let i = 0; i < 3; i++) {
      rule.evaluate(makeContext({ timestamp: now + i }));
    }

    const result = rule.evaluate(makeContext({ timestamp: now + 100 }));
    expect(result.verdict).toBe('deny');
    expect(result.reason).toContain('Rate limit');
  });

  it('should allow after window expires', () => {
    const rule = new RateLimitRule(2);
    const now = Date.now();

    rule.evaluate(makeContext({ timestamp: now }));
    rule.evaluate(makeContext({ timestamp: now + 1 }));

    // Should be denied
    expect(rule.evaluate(makeContext({ timestamp: now + 100 })).verdict).toBe('deny');

    // After 1 minute, should be allowed
    expect(rule.evaluate(makeContext({ timestamp: now + 61_000 })).verdict).toBe('allow');
  });
});

describe('AllowlistRule', () => {
  it('should allow addresses in the allowlist', () => {
    const rule = new AllowlistRule(['0xABCD1234']);
    const result = rule.evaluate(makeContext({ to: '0xabcd1234' }));
    expect(result.verdict).toBe('allow');
  });

  it('should deny addresses not in the allowlist', () => {
    const rule = new AllowlistRule(['0xABCD1234']);
    const result = rule.evaluate(makeContext({ to: '0xDEADBEEF' }));
    expect(result.verdict).toBe('deny');
  });

  it('should allow contract deployment (no to address)', () => {
    const rule = new AllowlistRule(['0xABCD1234']);
    const result = rule.evaluate(makeContext({ to: undefined }));
    expect(result.verdict).toBe('allow');
  });
});

describe('PolicyEngine', () => {
  it('should pass when all rules pass', () => {
    const engine = new PolicyEngine();
    engine.addRule(new CallerRule(['agent-1']));
    engine.addRule(new AllowlistRule(['0x1234']));

    const result = engine.evaluate(makeContext({ callerId: 'agent-1', to: '0x1234' }));
    expect(result.verdict).toBe('allow');
  });

  it('should deny on first failing rule', () => {
    const engine = new PolicyEngine();
    engine.addRule(new CallerRule(['agent-1']));
    engine.addRule(new AllowlistRule(['0x1234']));

    const result = engine.evaluate(makeContext({ callerId: 'hacker', to: '0x1234' }));
    expect(result.verdict).toBe('deny');
    expect(result.ruleName).toBe('caller-check');
  });

  it('should build from config', () => {
    const engine = PolicyEngine.fromConfig([
      { type: 'caller', allowedCallers: ['agent-1'] },
      { type: 'rate-limit', maxRequestsPerMinute: 10 },
    ]);

    expect(engine.getRules()).toHaveLength(2);
  });
});
