import type {
  PolicyRule,
  PolicyEvaluation,
  SigningContext,
  PolicyRuleConfig,
} from '@akm/types';
import { CallerRule } from './rules/caller-rule.js';
import { SpendingLimitRule } from './rules/spending-limit-rule.js';
import { RateLimitRule } from './rules/rate-limit-rule.js';
import { AllowlistRule } from './rules/allowlist-rule.js';

/**
 * Policy evaluation engine.
 * Evaluates a signing context against a set of rules.
 * ALL rules must pass for the request to be allowed (AND logic).
 */
export class PolicyEngine {
  private readonly rules: PolicyRule[] = [];

  addRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  removeRule(name: string): boolean {
    const idx = this.rules.findIndex((r) => r.name === name);
    if (idx === -1) return false;
    this.rules.splice(idx, 1);
    return true;
  }

  getRules(): readonly PolicyRule[] {
    return this.rules;
  }

  /**
   * Evaluate all rules. Returns the first denial, or an allow verdict.
   */
  evaluate(context: SigningContext): PolicyEvaluation {
    for (const rule of this.rules) {
      const result = rule.evaluate(context);
      if (result.verdict === 'deny') {
        return result;
      }
    }

    return {
      verdict: 'allow',
      reason: 'All policy rules passed',
      ruleName: 'engine',
    };
  }

  /**
   * Create a PolicyEngine from a list of rule configurations.
   */
  static fromConfig(configs: PolicyRuleConfig[]): PolicyEngine {
    const engine = new PolicyEngine();

    for (const config of configs) {
      switch (config.type) {
        case 'caller':
          engine.addRule(new CallerRule(config.allowedCallers));
          break;
        case 'spending-limit':
          engine.addRule(new SpendingLimitRule(config.maxValuePerTx, config.maxValuePerDay));
          break;
        case 'rate-limit':
          engine.addRule(new RateLimitRule(config.maxRequestsPerMinute));
          break;
        case 'allowlist':
          engine.addRule(new AllowlistRule(config.allowedAddresses));
          break;
      }
    }

    return engine;
  }
}
