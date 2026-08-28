import assert from 'node:assert/strict';
import test from 'node:test';

import * as policy from '../../src/index.ts';

function decision(action: 'allow' | 'review' | 'deny') {
  return {
    schemaVersion: '1.0.0',
    action,
    effects: [],
    reasonCode: `test.${action}`,
    evidence: [],
    versions: {
      policy: '0.1.1',
      rules: {},
      parsers: {},
    },
  };
}

function allowDecisionWithLocation(location: {
  start: { offset: number; line: number; column: number };
  end: { offset: number; line: number; column: number };
}) {
  return {
    ...decision('allow'),
    evidence: [
      {
        kind: 'unknown',
        location,
        redacted: true,
        summary: 'static summary',
      },
    ],
  };
}

test('combinePolicyDecisions returns the first strictest decision', () => {
  assert.equal(typeof policy.combinePolicyDecisions, 'function');

  const allow = decision('allow');
  const review = decision('review');
  const secondReview = decision('review');
  const deny = decision('deny');

  assert.equal(policy.combinePolicyDecisions(allow), allow);
  assert.equal(policy.combinePolicyDecisions(allow, review), review);
  assert.equal(
    policy.combinePolicyDecisions(allow, review, secondReview),
    review,
  );
  assert.equal(policy.combinePolicyDecisions(review, allow, deny), deny);
});

test('combinePolicyDecisions fail-closes malformed runtime decisions', () => {
  const combineAtRuntime = policy.combinePolicyDecisions as (
    ...decisions: unknown[]
  ) => unknown;
  const malformedDecisions = [
    undefined,
    null,
    {
      ...decision('allow'),
      action: 'unexpected',
    },
    {
      ...decision('allow'),
      effects: 'not-an-array',
    },
    {
      ...decision('allow'),
      evidence: [
        {
          kind: 'unknown',
          location: {
            start: { offset: 1, line: 1, column: 2 },
            end: { offset: 0, line: 1, column: 1 },
          },
          redacted: true,
          summary: 'static summary',
        },
      ],
    },
  ];

  for (const malformedDecision of malformedDecisions) {
    let result: unknown;
    assert.doesNotThrow(() => {
      result = combineAtRuntime(decision('allow'), malformedDecision);
    });
    assert.deepEqual(result, {
      schemaVersion: '1.0.0',
      action: 'review',
      effects: [
        {
          effectCode: 'policy.decision.invalid',
          action: 'review',
          evidenceIndexes: [],
        },
      ],
      reasonCode: 'policy.invalid_decision',
      evidence: [],
      versions: {
        policy: '0.1.1',
        rules: {
          core: '0.1.1',
          mysql: '0.1.2',
          python: '0.1.0',
          redis: '0.1.1',
          shell: '0.1.1',
          sqlite: '0.1.1',
        },
        parsers: {
          mysql: 'node-sql-parser@5.4.0/mysql',
          python: 'tree-sitter-python@0.25.0',
          redis: 'redis-command-table@1',
          shell: 'tree-sitter-bash@0.25.1',
          sqlite: 'sqlite3-parser@0.7.1/sqlite-3.53.0',
        },
      },
    });
  }

  assert.equal(
    (combineAtRuntime() as { action: string }).action,
    'review',
  );
});

test('combinePolicyDecisions rejects effects stricter than their decision', () => {
  const inconsistentAllow = {
    ...decision('allow'),
    effects: [
      {
        effectCode: 'test.destructive',
        action: 'deny',
        evidenceIndexes: [],
      },
    ],
  };
  const deny = decision('deny');

  const fallback = policy.combinePolicyDecisions(
    inconsistentAllow as never,
  );
  assert.equal(fallback.action, 'review');
  assert.equal(fallback.reasonCode, 'policy.invalid_decision');
  assert.equal(
    policy.combinePolicyDecisions(inconsistentAllow as never, deny),
    deny,
  );
});

test('combinePolicyDecisions rejects positionally impossible evidence ranges', () => {
  const impossibleLocations = [
    {
      start: { offset: 0, line: 3, column: 1 },
      end: { offset: 5, line: 2, column: 6 },
    },
    {
      start: { offset: 0, line: 1, column: 5 },
      end: { offset: 2, line: 1, column: 4 },
    },
    {
      start: { offset: 4, line: 1, column: 5 },
      end: { offset: 4, line: 2, column: 1 },
    },
    {
      start: { offset: 4, line: 1, column: 5 },
      end: { offset: 4, line: 1, column: 6 },
    },
    {
      start: { offset: 2, line: 1, column: 3 },
      end: { offset: 4, line: 1, column: 6 },
    },
    {
      start: { offset: 0, line: 1, column: 1 },
      end: { offset: 1, line: 3, column: 1 },
    },
    {
      start: { offset: 0, line: 2, column: 1 },
      end: { offset: 2, line: 2, column: 3 },
    },
    {
      start: { offset: 2, line: 1, column: 1 },
      end: { offset: 4, line: 1, column: 3 },
    },
  ];

  for (const location of impossibleLocations) {
    const result = policy.combinePolicyDecisions(
      allowDecisionWithLocation(location) as never,
    );

    assert.equal(result.action, 'review');
    assert.equal(result.reasonCode, 'policy.invalid_decision');
  }
});

test('combinePolicyDecisions accepts coherent zero-length and multiline ranges', () => {
  const zeroLength = allowDecisionWithLocation({
    start: { offset: 4, line: 2, column: 2 },
    end: { offset: 4, line: 2, column: 2 },
  });
  const multiline = allowDecisionWithLocation({
    start: { offset: 0, line: 1, column: 1 },
    end: { offset: 5, line: 2, column: 2 },
  });

  assert.equal(policy.combinePolicyDecisions(zeroLength as never), zeroLength);
  assert.equal(policy.combinePolicyDecisions(multiline as never), multiline);
});

test('root version metadata is stable and detached from parser internals', () => {
  assert.deepEqual(policy.POLICY_VERSION_METADATA, {
    schemaVersion: '1.0.0',
    policy: '0.1.1',
    rules: {
      core: '0.1.1',
      mysql: '0.1.2',
      python: '0.1.0',
      redis: '0.1.1',
      shell: '0.1.1',
      sqlite: '0.1.1',
    },
    parsers: {
      mysql: 'node-sql-parser@5.4.0/mysql',
      python: 'tree-sitter-python@0.25.0',
      redis: 'redis-command-table@1',
      shell: 'tree-sitter-bash@0.25.1',
      sqlite: 'sqlite3-parser@0.7.1/sqlite-3.53.0',
    },
  });
  assert.equal(Object.isFrozen(policy.POLICY_VERSION_METADATA), true);
  assert.equal(Object.isFrozen(policy.POLICY_VERSION_METADATA.rules), true);
  assert.equal(Object.isFrozen(policy.POLICY_VERSION_METADATA.parsers), true);
});

test('root exports stable fail-closed reason codes', () => {
  assert.deepEqual(policy.POLICY_REASON_CODES, {
    ANALYSIS_UNAVAILABLE: 'policy.analysis_unavailable',
    INITIALIZATION_FAILED: 'policy.initialization_failed',
    PARSE_FAILED: 'policy.parse_failed',
    RESOURCE_LIMIT_EXCEEDED: 'policy.resource_limit_exceeded',
    UNKNOWN_SEMANTICS: 'policy.unknown_semantics',
    INVALID_DECISION: 'policy.invalid_decision',
  });
  assert.equal(Object.isFrozen(policy.POLICY_REASON_CODES), true);
});
