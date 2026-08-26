import assert from 'node:assert/strict';
import test from 'node:test';

import * as mysql from '../../src/mysql.ts';
import * as python from '../../src/python.ts';
import * as redis from '../../src/redis.ts';
import * as shell from '../../src/shell.ts';
import * as sqlite from '../../src/sqlite.ts';

const domainFactories = [
  ['shell', shell.createShellPolicyEvaluator],
  ['python', python.createPythonPolicyEvaluator],
  ['sqlite', sqlite.createSqlitePolicyEvaluator],
  ['mysql', mysql.createMysqlPolicyEvaluator],
  ['redis', redis.createRedisPolicyEvaluator],
] as const;

test('every language subpath exposes an asynchronous policy evaluator', async () => {
  for (const [domain, createEvaluator] of domainFactories) {
    assert.equal(
      typeof createEvaluator,
      'function',
      `${domain} evaluator factory`,
    );

    const evaluation = createEvaluator().evaluate({
      sourceText: 'final source text',
      cwd: '/separate/cwd',
    });

    assert.equal(evaluation instanceof Promise, true, domain);
    await evaluation;
  }
});

test('deterministic evaluators fail closed on unknown semantics with redacted evidence', async () => {
  const unknownSources = {
    shell: 'unknown-command super-secret',
    python: 'unknown_call("super-secret")',
    sqlite: "SELECT unknown_function('super-secret')",
    mysql: "SELECT unknown_function('super-secret')",
    redis: 'CUSTOM.READ super-secret',
  } as const;

  for (const [domain, createEvaluator] of domainFactories) {
    const sourceText = unknownSources[domain];
    const input = Object.freeze({
      sourceText,
      cwd: '/secret/workspace',
    });
    const result = await createEvaluator().evaluate(input);

    assert.equal(result.action, 'review', domain);
    assert.notEqual(result.reasonCode, 'policy.analysis_unavailable', domain);
    assert.equal(result.schemaVersion, '1.0.0', domain);
    assert.equal(result.effects.length > 0, true);
    assert.equal(result.evidence.length > 0, true);
    assert.deepEqual(result.evidence[0]?.location, {
      start: { offset: 0, line: 1, column: 1 },
      end: { offset: sourceText.length, line: 1, column: sourceText.length + 1 },
    });
    assert.notEqual(result.versions.parsers[domain], 'unavailable');
    assert.equal(JSON.stringify(result).includes('super-secret'), false);
    assert.equal(JSON.stringify(result).includes('/secret/workspace'), false);
    assert.deepEqual(input, {
      sourceText,
      cwd: '/secret/workspace',
    });
  }
});

test('source ranges preserve UTF-16 and CRLF without normalization', async () => {
  const sourceText = '😀\r\nx';
  const result = await shell.createShellPolicyEvaluator().evaluate({
    sourceText,
    cwd: '/sensitive/cwd',
  });

  assert.deepEqual(result.evidence[0]?.location, {
    start: {
      offset: 0,
      line: 1,
      column: 1,
    },
    end: {
      offset: 5,
      line: 2,
      column: 2,
    },
  });
  assert.equal(JSON.stringify(result).includes(sourceText), false);
  assert.equal(JSON.stringify(result).includes('/sensitive/cwd'), false);
});
