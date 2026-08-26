import assert from 'node:assert/strict';
import test from 'node:test';

import { combinePolicyDecisions } from '../../src/index.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

const evaluator = createShellPolicyEvaluator();

async function action(sourceText: string) {
  return (await evaluator.evaluate({ sourceText })).action;
}

test('whitespace, comments, quotes, and option reordering do not change read-only proofs', async () => {
  const variants = [
    'ls /var/log',
    '  ls   /var/log  ',
    '# Purpose: inspect logs\nls /var/log',
    "ls -- '/var/log'",
    'ls "/var/log"',
    "ls '/var/log'",
  ];
  for (const sourceText of variants) {
    assert.equal(await action(sourceText), 'allow', sourceText);
  }
});

test('separators, nested substitutions, and redirect placement still aggregate effects', async () => {
  assert.equal(await action('uname -a; uptime && df -h'), 'allow');
  assert.equal(await action('uname -a; rm /tmp/generated'), 'review');
  assert.equal(await action('printf "%s\\n" "$(cat /etc/hosts)"'), 'allow');
  assert.equal(await action('printf "%s\\n" "$(cat /etc/shadow)"'), 'review');
  assert.equal(await action('cat /etc/hosts > /tmp/out'), 'review');
  assert.equal(await action('cat /etc/hosts 2>/dev/null'), 'allow');
});

test('wrappers, encoded payloads, and unknown executables fail closed', async () => {
  assert.equal(await action('sudo -- cat /etc/hosts'), 'allow');
  assert.equal(await action('env FOO=1 cat /etc/hosts'), 'allow');
  assert.equal(await action('eval "$(echo uname)"'), 'review');
  assert.equal(await action('bash -c "$CODE"'), 'review');
  assert.equal(await action('/tmp/ls /var/log'), 'review');
  assert.equal(await action('$(printf rm) /tmp/generated'), 'review');
});

test('resource limits fail closed instead of allowing', async () => {
  const limited = createShellPolicyEvaluator({
    limits: { maxInputBytes: 8 },
  });
  const decision = await limited.evaluate({ sourceText: 'uname -a; uptime' });
  assert.equal(decision.action, 'review');
  assert.equal(decision.reasonCode, 'policy.resource_limit_exceeded');
});

test('custom decisions can only make an official result stricter', async () => {
  const officialAllow = await evaluator.evaluate({ sourceText: 'uname -a' });
  const officialReview = await evaluator.evaluate({ sourceText: 'rm /tmp/generated' });
  const stricterReview = {
    ...officialAllow,
    action: 'review' as const,
    reasonCode: 'consumer.stricter',
  };
  const weakerAllow = {
    ...officialReview,
    action: 'allow' as const,
    reasonCode: 'consumer.weaker',
  };

  assert.equal(officialAllow.action, 'allow');
  assert.equal(
    combinePolicyDecisions(officialAllow, stricterReview).action,
    'review',
  );
  assert.equal(
    combinePolicyDecisions(officialReview, weakerAllow).action,
    'review',
  );
});
