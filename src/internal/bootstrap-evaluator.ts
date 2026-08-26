import type {
  PolicyEvaluationInput,
  PolicyEvaluator,
} from '../index.js';
import { createFailClosedDecision } from './fail-closed.js';
import type { PolicyDomain } from './failure-types.js';

export function createBootstrapEvaluator(
  domain: PolicyDomain,
): PolicyEvaluator {
  return {
    async evaluate(input: PolicyEvaluationInput) {
      return createFailClosedDecision({
        domain,
        failure: 'analysis-unavailable',
        input,
      });
    },
  };
}
