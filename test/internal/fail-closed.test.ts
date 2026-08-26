import assert from 'node:assert/strict';
import test from 'node:test';

import * as failClosed from '../../src/internal/fail-closed.ts';

const expectedFailures = {
  'analysis-unavailable': {
    reasonCode: 'policy.analysis_unavailable',
    summary: 'shell source requires review because analysis is unavailable.',
  },
  'initialization-failed': {
    reasonCode: 'policy.initialization_failed',
    summary:
      'shell source requires review because analyzer initialization failed.',
  },
  'parse-failed': {
    reasonCode: 'policy.parse_failed',
    summary: 'shell source requires review because parsing failed.',
  },
  'resource-limit-exceeded': {
    reasonCode: 'policy.resource_limit_exceeded',
    summary:
      'shell source requires review because an analysis resource limit was exceeded.',
  },
  'unknown-semantics': {
    reasonCode: 'policy.unknown_semantics',
    summary: 'shell source requires review because semantics are unknown.',
  },
} as const;

test('all analyzer failure classes produce review decisions', () => {
  assert.equal(typeof failClosed.createFailClosedDecision, 'function');

  for (const [failure, expected] of Object.entries(expectedFailures)) {
    const result = failClosed.createFailClosedDecision({
      domain: 'shell',
      failure: failure as keyof typeof expectedFailures,
      input: {
        sourceText: 'exact final source',
        cwd: '/separate/cwd',
      },
    });

    assert.equal(result.action, 'review', failure);
    assert.equal(result.reasonCode, expected.reasonCode, failure);
    assert.equal(result.evidence[0]?.summary, expected.summary, failure);
    assert.equal(JSON.stringify(result).includes('exact final source'), false);
    assert.equal(JSON.stringify(result).includes('/separate/cwd'), false);
  }
});
