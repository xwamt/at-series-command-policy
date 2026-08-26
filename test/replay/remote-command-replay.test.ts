import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createShellPolicyEvaluator } from '../../src/shell.ts';

type ReplayCategory =
  | 'ordinary_query'
  | 'sensitive_read'
  | 'state_modification'
  | 'unknown';

interface ReplayCase {
  readonly id: string;
  readonly commandShape: string;
  readonly category: ReplayCategory;
  readonly expectedAction: 'allow' | 'review' | 'deny';
}

const fixtureUrl = new URL('../fixtures/remote-command-replay.json', import.meta.url);

async function loadFixture(): Promise<readonly ReplayCase[]> {
  return JSON.parse(await readFile(fixtureUrl, 'utf8')) as ReplayCase[];
}

test('replay fixture contains exactly 86 stable, fully redacted cases', async () => {
  const cases = await loadFixture();
  assert.equal(cases.length, 86);
  assert.deepEqual(
    cases.map(({ id }) => id),
    Array.from(
      { length: 86 },
      (_, index) => `rrc-${String(index + 1).padStart(3, '0')}`,
    ),
  );

  const serialized = JSON.stringify(cases);
  for (const forbidden of [
    /serverId/i,
    /response|stdout|stderr|output/i,
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

  for (const replayCase of cases) {
    assert.equal(replayCase.commandShape.length > 0, true, replayCase.id);
    assert.match(
      replayCase.category,
      /^(?:ordinary_query|sensitive_read|state_modification|unknown)$/,
    );
    assert.match(replayCase.expectedAction, /^(?:allow|review|deny)$/);
  }
});

test('replay acceptance has no unsafe auto-allows and at most 10% ordinary reviews', async () => {
  const cases = await loadFixture();
  const evaluator = createShellPolicyEvaluator();
  let safetyViolations = 0;
  let ordinaryQueries = 0;
  let ordinaryReviews = 0;

  for (const replayCase of cases) {
    const decision = await evaluator.evaluate({
      sourceText: replayCase.commandShape,
    });
    if (replayCase.category === 'ordinary_query') {
      ordinaryQueries += 1;
      if (decision.action !== 'allow') {
        ordinaryReviews += 1;
      }
    } else if (
      (replayCase.category === 'sensitive_read' ||
        replayCase.category === 'state_modification') &&
      decision.action === 'allow'
    ) {
      safetyViolations += 1;
    }
    if (
      replayCase.expectedAction === 'deny' ||
      replayCase.category === 'sensitive_read' ||
      replayCase.category === 'state_modification'
    ) {
      assert.notEqual(decision.action, 'allow', replayCase.id);
    }
  }

  assert.equal(safetyViolations, 0);
  assert.equal(ordinaryQueries > 0, true);
  assert.equal(ordinaryReviews / ordinaryQueries <= 0.1, true);
});
