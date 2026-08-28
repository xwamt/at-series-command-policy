import assert from 'node:assert/strict';
import test from 'node:test';

import { embeddedDomainForExecutable } from '../../src/internal/shell/embedded.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

test('embedded domain gate matches exactly the four client executables', () => {
  assert.equal(embeddedDomainForExecutable('python3'), 'python');
  assert.equal(embeddedDomainForExecutable('python3.12'), 'python');
  assert.equal(embeddedDomainForExecutable('sqlite3'), 'sqlite');
  assert.equal(embeddedDomainForExecutable('mysql'), 'mysql');
  assert.equal(embeddedDomainForExecutable('redis-cli'), 'redis');
  assert.equal(embeddedDomainForExecutable('uptime'), undefined);
  assert.equal(embeddedDomainForExecutable('mysqldump'), undefined);
  assert.equal(embeddedDomainForExecutable(undefined), undefined);
});

test('gate does not change embedded and fall-through behavior', async () => {
  const evaluator = createShellPolicyEvaluator();
  const python = await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' });
  assert.equal(python.action, 'allow');
  assert.equal(
    python.effects.some((effect) => effect.effectCode === 'shell.embedded.python'),
    true,
  );
  assert.equal(
    (await evaluator.evaluate({ sourceText: 'python3 --version' })).action,
    'allow', // 仍落回 shell contracts（P2-2 行为）
  );
  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
});
