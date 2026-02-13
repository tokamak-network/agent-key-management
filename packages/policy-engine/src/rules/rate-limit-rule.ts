import type { PolicyRule, PolicyEvaluation, SigningContext } from '@akm/types';

export class RateLimitRule implements PolicyRule {
  readonly type = 'rate-limit' as const;
  readonly name: string;
  private readonly maxRequestsPerMinute: number;
  private readonly requestTimestamps: number[] = [];

  constructor(maxRequestsPerMinute: number, name?: string) {
    this.name = name ?? 'rate-limit';
    this.maxRequestsPerMinute = maxRequestsPerMinute;
  }

  evaluate(context: SigningContext): PolicyEvaluation {
    const now = context.timestamp;
    const oneMinuteAgo = now - 60_000;

    // Remove old timestamps
    while (this.requestTimestamps.length > 0 && this.requestTimestamps[0]! < oneMinuteAgo) {
      this.requestTimestamps.shift();
    }

    if (this.requestTimestamps.length >= this.maxRequestsPerMinute) {
      return {
        verdict: 'deny',
        reason: `Rate limit exceeded: ${this.requestTimestamps.length}/${this.maxRequestsPerMinute} requests per minute`,
        ruleName: this.name,
      };
    }

    this.requestTimestamps.push(now);

    return {
      verdict: 'allow',
      reason: 'Within rate limit',
      ruleName: this.name,
    };
  }

  /** Reset rate limit tracking (for testing) */
  reset(): void {
    this.requestTimestamps.length = 0;
  }
}
