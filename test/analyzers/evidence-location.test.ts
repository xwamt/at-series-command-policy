import assert from 'node:assert/strict';
import test from 'node:test';

import { combinePolicyDecisions } from '../../src/index.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

const evaluator = createShellPolicyEvaluator();

test('review evidence is located on the offending shell command node', async () => {
  const sourceText = 'sed -i s/a/b/ /etc/hosts; uname -a';
  const decision = await evaluator.evaluate({
    sourceText,
    cwd: '/srv/application',
  });

  assert.equal(decision.action, 'review');
  assert.equal(combinePolicyDecisions(decision), decision);

  for (const entry of decision.evidence) {
    assert.equal(entry.location.start.offset >= 0, true);
    assert.equal(entry.location.end.offset <= sourceText.length, true);
    assert.equal(entry.redacted, true);
    assert.equal(entry.summary.includes(sourceText), false);
    assert.equal(entry.summary.includes('/etc/hosts'), false);
    assert.equal(entry.summary.includes('s/a/b/'), false);
  }
  assert.equal(JSON.stringify(decision).includes('/srv/application'), false);

  const narrowed = decision.evidence.filter(
    (entry) =>
      entry.location.start.offset > 0 ||
      entry.location.end.offset < sourceText.length,
  );
  assert.equal(narrowed.length > 0, true);

  const sedSegmentEnd = sourceText.indexOf(';');
  const sedEvidence = narrowed.find(
    (entry) =>
      entry.location.start.offset <= 1 &&
      entry.location.end.offset <= sedSegmentEnd,
  );
  assert.notEqual(sedEvidence, undefined);
  assert.equal(sedEvidence!.location.end.offset < sourceText.length, true);
});

test('allow decisions still carry valid evidence locations', async () => {
  const sourceText = 'uname -a';
  const decision = await evaluator.evaluate({ sourceText });

  assert.equal(decision.action, 'allow');
  assert.equal(combinePolicyDecisions(decision), decision);
  assert.equal(decision.evidence.length > 0, true);
  for (const entry of decision.evidence) {
    assert.equal(entry.location.start.offset >= 0, true);
    assert.equal(entry.location.end.offset <= sourceText.length, true);
    assert.equal(entry.summary.includes(sourceText), false);
  }
});
