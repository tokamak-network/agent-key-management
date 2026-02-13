import type { PolicyRule, PolicyEvaluation, SigningContext } from '@akm/types';

export class AllowlistRule implements PolicyRule {
  readonly type = 'allowlist' as const;
  readonly name: string;
  private readonly allowedAddresses: Set<string>;

  constructor(allowedAddresses: string[], name?: string) {
    this.name = name ?? 'allowlist';
    // Normalize addresses to lowercase
    this.allowedAddresses = new Set(allowedAddresses.map((a) => a.toLowerCase()));
  }

  evaluate(context: SigningContext): PolicyEvaluation {
    if (!context.to) {
      // Contract deployment (no "to") — allow by default
      return {
        verdict: 'allow',
        reason: 'Contract deployment (no target address)',
        ruleName: this.name,
      };
    }

    if (this.allowedAddresses.has(context.to.toLowerCase())) {
      return {
        verdict: 'allow',
        reason: `Target address ${context.to} is in allowlist`,
        ruleName: this.name,
      };
    }

    return {
      verdict: 'deny',
      reason: `Target address ${context.to} is not in the allowlist`,
      ruleName: this.name,
    };
  }
}
