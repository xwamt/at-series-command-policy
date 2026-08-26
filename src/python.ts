import type {
  PolicyAnalysisLimits,
  PolicyAssetResolver,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from './index.js';
import { createDeterministicPythonEvaluator } from './internal/python/evaluator.js';

export type PythonPolicyInput = PolicyEvaluationInput;
export type PythonPolicyEvaluator = PolicyEvaluator<PythonPolicyInput>;

export interface PythonPolicyEvaluatorOptions {
  readonly assetResolver?: PolicyAssetResolver;
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

export function createPythonPolicyEvaluator(
  options: PythonPolicyEvaluatorOptions = {},
): PythonPolicyEvaluator {
  let sqliteEvaluator: Promise<PolicyEvaluator> | undefined;
  return createDeterministicPythonEvaluator({
    ...options,
    sqliteEvaluator() {
      sqliteEvaluator ??= import('./sqlite.js').then(
        ({ createSqlitePolicyEvaluator }) =>
          createSqlitePolicyEvaluator(
            options.limits ? { limits: options.limits } : {},
          ),
      );
      return sqliteEvaluator;
    },
  });
}
