import type {
  PolicyAnalysisLimits,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from './index.js';
import { createDeterministicRedisEvaluator } from './internal/redis/evaluator.js';

export type RedisPolicyInput = PolicyEvaluationInput;
export type RedisPolicyEvaluator = PolicyEvaluator<RedisPolicyInput>;

export interface RedisPolicyEvaluatorOptions {
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

export function createRedisPolicyEvaluator(
  options: RedisPolicyEvaluatorOptions = {},
): RedisPolicyEvaluator {
  return createDeterministicRedisEvaluator(options);
}
