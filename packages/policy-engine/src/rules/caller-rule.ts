import type { PolicyRule, PolicyEvaluation, SigningContext } from '@akm/types';

export class CallerRule implements PolicyRule {
  readonly type = 'caller' as const;
  readonly name: string;
  private readonly allowedCallers: Set<string>;

  constructor(allowedCallers: string[], name?: string) {
    this.name = name ?? 'caller-check';
    this.allowedCallers = new Set(allowedCallers);
  }

  evaluate(context: SigningContext): PolicyEvaluation {
    if (this.allowedCallers.has(context.callerId)) {
      return { verdict: 'allow', reason: 'Caller is authorized', ruleName: this.name };
    }
    return {
      verdict: 'deny',
      reason: `Caller '${context.callerId}' is not in the allowed list`,
      ruleName: this.name,
    };
  }
}
