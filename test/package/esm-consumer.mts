import {
  combinePolicyDecisions,
  type PolicyDecision,
  type PolicyEvaluationInput,
  type PolicyEvaluator,
} from '@at-series/command-policy';
import { copyPolicyAssets } from '@at-series/command-policy/build';
import { createMysqlPolicyEvaluator } from '@at-series/command-policy/mysql';
import { createPythonPolicyEvaluator } from '@at-series/command-policy/python';
import { createRedisPolicyEvaluator } from '@at-series/command-policy/redis';
import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';
import { createSqlitePolicyEvaluator } from '@at-series/command-policy/sqlite';

const input = {
  sourceText: 'exact final source',
  cwd: '/separate/cwd',
} satisfies PolicyEvaluationInput;

const evaluators: readonly PolicyEvaluator[] = [
  createShellPolicyEvaluator(),
  createPythonPolicyEvaluator(),
  createSqlitePolicyEvaluator(),
  createMysqlPolicyEvaluator(),
  createRedisPolicyEvaluator(),
];

const decisions: readonly PolicyDecision[] = await Promise.all(
  evaluators.map(async (evaluator) => evaluator.evaluate(input)),
);

combinePolicyDecisions(decisions[0]!, ...decisions.slice(1));
await copyPolicyAssets({
  destinationDirectory: '/build-time-only',
});
