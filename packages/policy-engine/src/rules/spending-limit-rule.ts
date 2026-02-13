import type { PolicyRule, PolicyEvaluation, SigningContext } from '@akm/types';

export class SpendingLimitRule implements PolicyRule {
  readonly type = 'spending-limit' as const;
  readonly name: string;
  private readonly maxValuePerTx: bigint;
  private readonly maxValuePerDay: bigint;

  /** Track daily spending: date string → total value */
  private readonly dailySpending = new Map<string, bigint>();

  constructor(maxValuePerTx: bigint, maxValuePerDay: bigint, name?: string) {
    this.name = name ?? 'spending-limit';
    this.maxValuePerTx = maxValuePerTx;
    this.maxValuePerDay = maxValuePerDay;
  }

  evaluate(context: SigningContext): PolicyEvaluation {
    const value = context.value ?? 0n;

    // Check per-transaction limit
    if (value > this.maxValuePerTx) {
      return {
        verdict: 'deny',
        reason: `Transaction value ${value} exceeds per-tx limit of ${this.maxValuePerTx}`,
        ruleName: this.name,
      };
    }

    // Check daily limit
    const dateKey = new Date(context.timestamp).toISOString().split('T')[0]!;
    const currentDailySpend = this.dailySpending.get(dateKey) ?? 0n;

    if (currentDailySpend + value > this.maxValuePerDay) {
      return {
        verdict: 'deny',
        reason: `Daily spending would exceed limit of ${this.maxValuePerDay} (current: ${currentDailySpend}, requested: ${value})`,
        ruleName: this.name,
      };
    }

    // Record spending
    this.dailySpending.set(dateKey, currentDailySpend + value);

    return { verdict: 'allow', reason: 'Within spending limits', ruleName: this.name };
  }

  /** Reset spending tracking (for testing) */
  reset(): void {
    this.dailySpending.clear();
  }
}
