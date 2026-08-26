import type {
  PolicyAnalysisLimits,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from './index.js';
import { createDeterministicMysqlEvaluator } from './internal/sql/mysql-evaluator.js';

export type MysqlPolicyInput = PolicyEvaluationInput;
export type MysqlPolicyEvaluator = PolicyEvaluator<MysqlPolicyInput>;

export interface MysqlPolicyEvaluatorOptions {
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

export function createMysqlPolicyEvaluator(
  options: MysqlPolicyEvaluatorOptions = {},
): MysqlPolicyEvaluator {
  return createDeterministicMysqlEvaluator(options);
}
