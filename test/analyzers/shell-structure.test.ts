import assert from 'node:assert/strict';
import test from 'node:test';

import { createShellPolicyEvaluator } from '../../src/shell.ts';

const evaluator = createShellPolicyEvaluator();

async function evaluate(sourceText: string) {
  return evaluator.evaluate({ sourceText, cwd: '/srv/application' });
}

async function action(sourceText: string) {
  return (await evaluate(sourceText)).action;
}

test('allows complete multiline read-only scripts and ignores comments as authority', async () => {
  assert.equal(
    await action(
      [
        '# Purpose: inspect the host',
        'uname -a',
        'ps aux | grep worker | head -20',
        'uptime; df -h',
      ].join('\n'),
    ),
    'allow',
  );
});

test('aggregates every list, branch, and loop body', async () => {
  const cases = [
    ['true && uname -a', 'allow'],
    ['false || uptime', 'allow'],
    ['true && rm /tmp/generated', 'review'],
    ['if true; then ps aux; else systemctl restart app; fi', 'review'],
    ['for item in one two; do printf "%s\\n" "$item"; done', 'allow'],
    ['while false; do rm /tmp/generated; done', 'review'],
  ] as const;

  for (const [sourceText, expected] of cases) {
    assert.equal(await action(sourceText), expected, sourceText);
  }
});

test('aggregates substitutions and rejects dynamic or detached execution', async () => {
  assert.equal(await action('printf "%s\\n" "$(uname -s)"'), 'allow');
  assert.equal(await action('printf "%s\\n" "$(cat /etc/shadow)"'), 'review');
  assert.equal(await action('$(printf rm) /tmp/generated'), 'review');
  assert.equal(await action('uname -a &'), 'review');
  assert.equal(await action('cat <(uname -a)'), 'review');
});

test('classifies redirects and propagates sensitive input reads', async () => {
  assert.equal(await action('cat < /etc/hosts | head -5'), 'allow');
  assert.equal(await action('cat < /etc/shadow | head -5'), 'review');
  assert.equal(await action('uname -a > /tmp/report'), 'review');
  assert.equal(await action('uname -a 2>/dev/null'), 'allow');
  assert.equal(await action('cat <<EOF\nvalue\nEOF'), 'review');
});

test('parse errors and unsupported shell semantics fail closed with redacted evidence', async () => {
  for (const sourceText of ['', 'echo "unterminated', 'if true; then uname; fi fi']) {
    const decision = await evaluate(sourceText);
    assert.equal(decision.action, 'review', sourceText);
    assert.match(
      decision.reasonCode,
      /^policy\.(?:parse_failed|unknown_semantics)$/,
    );
    assert.equal(decision.evidence.length > 0, true);
    if (sourceText.length > 0) {
      assert.equal(JSON.stringify(decision).includes(sourceText), false);
    }
    assert.equal(JSON.stringify(decision).includes('/srv/application'), false);
  }
});
