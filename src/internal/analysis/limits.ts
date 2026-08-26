import type { PolicyAnalysisLimits } from '../../index.js';

export const DEFAULT_POLICY_LIMITS: PolicyAnalysisLimits = Object.freeze({
  maxInputBytes: 64 * 1024,
  maxAstNodes: 12_000,
  maxNestingDepth: 64,
  maxStatements: 512,
  maxWorkUnits: 100_000,
});

export type PolicyAnalysisLimitOverrides = Partial<PolicyAnalysisLimits>;

export function resolvePolicyLimits(
  overrides: PolicyAnalysisLimitOverrides | undefined,
): PolicyAnalysisLimits {
  const merged = {
    ...DEFAULT_POLICY_LIMITS,
    ...overrides,
  };

  for (const [name, value] of Object.entries(merged)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new TypeError(`${name} must be a positive safe integer`);
    }
  }

  return Object.freeze(merged);
}

export function inputExceedsLimit(
  sourceText: string,
  limits: PolicyAnalysisLimits,
): boolean {
  return new TextEncoder().encode(sourceText).byteLength > limits.maxInputBytes;
}

export class WorkBudget {
  readonly #limit: number;
  #used = 0;

  constructor(limit: number) {
    this.#limit = limit;
  }

  consume(units = 1): boolean {
    this.#used += units;
    return this.#used <= this.#limit;
  }
}
