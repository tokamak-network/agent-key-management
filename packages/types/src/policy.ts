export type PolicyVerdict = 'allow' | 'deny';

export interface PolicyEvaluation {
  readonly verdict: PolicyVerdict;
  readonly reason: string;
  readonly ruleName: string;
}

export interface SigningContext {
  readonly callerId: string;
  readonly keyId: string;
  readonly to?: string;
  readonly value?: bigint;
  readonly data?: string;
  readonly chainId?: number;
  readonly timestamp: number;
}

export type RuleType = 'caller' | 'spending-limit' | 'rate-limit' | 'allowlist';

export interface PolicyRule {
  readonly type: RuleType;
  readonly name: string;
  evaluate(context: SigningContext): PolicyEvaluation;
}

export interface PolicyConfig {
  readonly rules: PolicyRuleConfig[];
}

export interface CallerRuleConfig {
  readonly type: 'caller';
  readonly allowedCallers: string[];
}

export interface SpendingLimitRuleConfig {
  readonly type: 'spending-limit';
  readonly maxValuePerTx: bigint;
  readonly maxValuePerDay: bigint;
}

export interface RateLimitRuleConfig {
  readonly type: 'rate-limit';
  readonly maxRequestsPerMinute: number;
}

export interface AllowlistRuleConfig {
  readonly type: 'allowlist';
  readonly allowedAddresses: string[];
}

export type PolicyRuleConfig =
  | CallerRuleConfig
  | SpendingLimitRuleConfig
  | RateLimitRuleConfig
  | AllowlistRuleConfig;
