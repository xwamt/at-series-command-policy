import type {
  PolicyAnalysisLimits,
  PolicyAssetResolver,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from './index.js';
import { createDeterministicShellEvaluator } from './internal/shell/evaluator.js';
import { createTreeSitterParser } from './internal/tree-sitter/runtime.js';

export type ShellPolicyInput = PolicyEvaluationInput;
export type ShellPolicyEvaluator = PolicyEvaluator<ShellPolicyInput>;

export interface ShellPolicyEvaluatorOptions {
  readonly assetResolver?: PolicyAssetResolver;
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

/**
 * Optionally pre-initializes the tree-sitter runtime and bash grammar so the
 * first evaluate() call pays no cold-start cost. Failures reject here, but
 * evaluators stay independent and still fail closed to review on evaluate().
 */
export async function warmupShellPolicyEvaluator(
  options: Pick<ShellPolicyEvaluatorOptions, 'assetResolver'> = {},
): Promise<void> {
  const handle = await createTreeSitterParser(
    'tree-sitter-bash',
    options.assetResolver,
  );
  handle.dispose();
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
