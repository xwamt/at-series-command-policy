import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import type { PolicyAction, PolicyEvaluator } from '../../src/index.ts';
import { createMysqlPolicyEvaluator } from '../../src/mysql.ts';
import { createPythonPolicyEvaluator } from '../../src/python.ts';
import { createRedisPolicyEvaluator } from '../../src/redis.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';
import { createSqlitePolicyEvaluator } from '../../src/sqlite.ts';

type AccuracyDomain = 'shell' | 'python' | 'sqlite' | 'mysql' | 'redis';

type AccuracyClass = 'false_allow_fix' | 'false_review_fix' | 'regression';

interface AccuracyCase {
  readonly id: string;
  readonly domain: AccuracyDomain;
  readonly family: string;
  readonly sourceText: string;
  readonly expectedAction: PolicyAction;
  readonly class: AccuracyClass;
}

const ACTIONS: readonly PolicyAction[] = ['allow', 'review', 'deny'];
const DOMAINS: readonly AccuracyDomain[] = [
  'shell',
  'python',
  'sqlite',
  'mysql',
  'redis',
];
const CLASSES: readonly AccuracyClass[] = [
  'false_allow_fix',
  'false_review_fix',
  'regression',
];

const fixtureUrl = new URL(
  '../fixtures/accuracy-regression.json',
  import.meta.url,
);

async function loadFixture(): Promise<readonly AccuracyCase[]> {
  return JSON.parse(await readFile(fixtureUrl, 'utf8')) as AccuracyCase[];
}

const evaluators: Readonly<Record<AccuracyDomain, PolicyEvaluator>> = {
  shell: createShellPolicyEvaluator(),
  python: createPythonPolicyEvaluator(),
  sqlite: createSqlitePolicyEvaluator(),
  mysql: createMysqlPolicyEvaluator(),
  redis: createRedisPolicyEvaluator(),
};

function describeCase(accuracyCase: AccuracyCase): string {
  return `${accuracyCase.id} [${accuracyCase.domain}/${accuracyCase.class}/${accuracyCase.family}] ${JSON.stringify(accuracyCase.sourceText)}`;
}

test('accuracy fixture is well-formed, sequentially numbered, and redacted', async () => {
  const cases = await loadFixture();
  assert.equal(cases.length >= 35, true, 'corpus must contain at least 35 cases');
  assert.deepEqual(
    cases.map(({ id }) => id),
    cases.map((_, index) => `acc-${String(index + 1).padStart(3, '0')}`),
  );

  for (const accuracyCase of cases) {
    assert.equal(DOMAINS.includes(accuracyCase.domain), true, describeCase(accuracyCase));
    assert.equal(CLASSES.includes(accuracyCase.class), true, describeCase(accuracyCase));
    assert.equal(
      ACTIONS.includes(accuracyCase.expectedAction),
      true,
      describeCase(accuracyCase),
    );
    assert.match(accuracyCase.family, /^[a-z0-9][a-z0-9-]*$/, describeCase(accuracyCase));
    assert.equal(accuracyCase.sourceText.length > 0, true, describeCase(accuracyCase));
    if (accuracyCase.class === 'false_allow_fix') {
      assert.notEqual(
        accuracyCase.expectedAction,
        'allow',
        `${accuracyCase.id}: false_allow_fix cases must expect review or deny`,
      );
    }
    if (accuracyCase.class === 'false_review_fix') {
      assert.equal(
        accuracyCase.expectedAction,
        'allow',
        `${accuracyCase.id}: false_review_fix cases must expect allow`,
      );
    }
  }

  for (const domain of DOMAINS) {
    assert.equal(
      cases.some((accuracyCase) => accuracyCase.domain === domain),
      true,
      `corpus must cover domain ${domain}`,
    );
  }
  for (const accuracyClass of CLASSES) {
    assert.equal(
      cases.some((accuracyCase) => accuracyCase.class === accuracyClass),
      true,
      `corpus must cover class ${accuracyClass}`,
    );
  }

  const serialized = JSON.stringify(cases);
  for (const forbidden of [
    /serverId/i,
    /response|stdout|stderr/i,
    /traceId|bridgeId/i,
    /(?:^|[^0-9])(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/,
    /\/Users\//,
    /\/home\/(?!operator(?:\/|"))/,
    /Bearer\s+(?!\[redacted\])/i,
    /(?:password|token|secret)=((?!\[redacted\])[^&"\\\s]+)/i,
    /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i,
  ]) {
    assert.doesNotMatch(serialized, forbidden);
  }
});

test('accuracy corpus predictions match expected actions', async (t) => {
  const cases = await loadFixture();
  for (const accuracyCase of cases) {
    await t.test(
      `${accuracyCase.id} (${accuracyCase.domain}/${accuracyCase.class}) expects ${accuracyCase.expectedAction}`,
      async () => {
        const decision = await evaluators[accuracyCase.domain].evaluate({
          sourceText: accuracyCase.sourceText,
        });
        assert.equal(
          decision.action,
          accuracyCase.expectedAction,
          `${describeCase(accuracyCase)} predicted ${decision.action}, expected ${accuracyCase.expectedAction}`,
        );
      },
    );
  }
});

test('confusion matrix per domain has zero false allows', async (t) => {
  const cases = await loadFixture();
  type ConfusionCell = { predicted: PolicyAction; expected: PolicyAction };
  const matrixByDomain = new Map<AccuracyDomain, Map<string, number>>(
    DOMAINS.map((domain) => [domain, new Map<string, number>()]),
  );
  const falseAllows: string[] = [];
  const mismatches: string[] = [];

  for (const accuracyCase of cases) {
    const decision = await evaluators[accuracyCase.domain].evaluate({
      sourceText: accuracyCase.sourceText,
    });
    const cell: ConfusionCell = {
      predicted: decision.action,
      expected: accuracyCase.expectedAction,
    };
    const domainMatrix = matrixByDomain.get(accuracyCase.domain);
    assert.notEqual(domainMatrix, undefined, accuracyCase.id);
    const key = `predicted=${cell.predicted} expected=${cell.expected}`;
    domainMatrix?.set(key, (domainMatrix.get(key) ?? 0) + 1);
    if (cell.predicted === 'allow' && cell.expected !== 'allow') {
      falseAllows.push(describeCase(accuracyCase));
    }
    if (cell.predicted !== cell.expected) {
      mismatches.push(
        `${describeCase(accuracyCase)} predicted=${cell.predicted} expected=${cell.expected}`,
      );
    }
  }

  for (const domain of DOMAINS) {
    const domainMatrix = matrixByDomain.get(domain);
    const cells = [...(domainMatrix?.entries() ?? [])]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, count]) => `${key} count=${count}`)
      .join('; ');
    t.diagnostic(`confusion[${domain}]: ${cells.length > 0 ? cells : 'no cases'}`);
  }
  if (mismatches.length > 0) {
    t.diagnostic(`mismatches (${mismatches.length}): ${mismatches.join(' | ')}`);
  }

  assert.deepEqual(
    falseAllows,
    [],
    `predicted allow while expected review/deny must never happen:\n${falseAllows.join('\n')}`,
  );
});
