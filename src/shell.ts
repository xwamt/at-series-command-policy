import type {
  PolicyAnalysisLimits,
  PolicyAssetResolver,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from './index.js';
import { createDeterministicShellEvaluator } from './internal/shell/evaluator.js';

export type ShellPolicyInput = PolicyEvaluationInput;
export type ShellPolicyEvaluator = PolicyEvaluator<ShellPolicyInput>;

export interface ShellPolicyEvaluatorOptions {
  readonly assetResolver?: PolicyAssetResolver;
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

export function createShellPolicyEvaluator(
  options: ShellPolicyEvaluatorOptions = {},
): ShellPolicyEvaluator {
  let pythonEvaluator: Promise<PolicyEvaluator> | undefined;
  let sqliteEvaluator: Promise<PolicyEvaluator> | undefined;
  let mysqlEvaluator: Promise<PolicyEvaluator> | undefined;
  let redisEvaluator: Promise<PolicyEvaluator> | undefined;

  return createDeterministicShellEvaluator({
    ...options,
    embeddedEvaluators: {
      python() {
        pythonEvaluator ??= import('./python.js').then(({ createPythonPolicyEvaluator }) =>
          createPythonPolicyEvaluator(options),
        );
        return pythonEvaluator;
      },
      sqlite() {
        sqliteEvaluator ??= import('./sqlite.js').then(
          ({ createSqlitePolicyEvaluator }) =>
            createSqlitePolicyEvaluator(
              options.limits ? { limits: options.limits } : {},
            ),
        );
        return sqliteEvaluator;
      },
      mysql() {
        mysqlEvaluator ??= import('./mysql.js').then(
          ({ createMysqlPolicyEvaluator }) =>
            createMysqlPolicyEvaluator(
              options.limits ? { limits: options.limits } : {},
            ),
        );
        return mysqlEvaluator;
      },
      redis() {
        redisEvaluator ??= import('./redis.js').then(
          ({ createRedisPolicyEvaluator }) =>
            createRedisPolicyEvaluator(
              options.limits ? { limits: options.limits } : {},
            ),
        );
        return redisEvaluator;
      },
    },
  });
}
