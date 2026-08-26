import policy = require('@at-series/command-policy');
import build = require('@at-series/command-policy/build');
import mysql = require('@at-series/command-policy/mysql');
import python = require('@at-series/command-policy/python');
import redis = require('@at-series/command-policy/redis');
import shell = require('@at-series/command-policy/shell');
import sqlite = require('@at-series/command-policy/sqlite');

const input = {
  sourceText: 'exact final source',
  cwd: '/separate/cwd',
} satisfies policy.PolicyEvaluationInput;

const evaluators: readonly policy.PolicyEvaluator[] = [
  shell.createShellPolicyEvaluator(),
  python.createPythonPolicyEvaluator(),
  sqlite.createSqlitePolicyEvaluator(),
  mysql.createMysqlPolicyEvaluator(),
  redis.createRedisPolicyEvaluator(),
];

Promise.all(evaluators.map((evaluator) => evaluator.evaluate(input))).then(
  (decisions) => policy.combinePolicyDecisions(decisions[0]!, ...decisions.slice(1)),
);

void build.copyPolicyAssets({
  destinationDirectory: '/build-time-only',
});
