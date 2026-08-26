import type {
  PolicyAnalysisLimits,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from './index.js';
import { createDeterministicSqliteEvaluator } from './internal/sql/sqlite-evaluator.js';

export type SqlitePolicyInput = PolicyEvaluationInput;
export type SqlitePolicyEvaluator = PolicyEvaluator<SqlitePolicyInput>;

export interface SqlitePolicyEvaluatorOptions {
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

export function createSqlitePolicyEvaluator(
  options: SqlitePolicyEvaluatorOptions = {},
): SqlitePolicyEvaluator {
  return createDeterministicSqliteEvaluator(options);
}
