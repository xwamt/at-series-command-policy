import assert from 'node:assert/strict';
import test from 'node:test';

import { createShellPolicyEvaluator } from '../../src/shell.ts';

const evaluator = createShellPolicyEvaluator();
const seed = 20260825;

function mulberry32(value: number) {
  return () => {
    let next = (value += 0x6d2b79f5);
    next = Math.imul(next ^ (next >>> 15), next | 1);
    next ^= next + Math.imul(next ^ (next >>> 7), next | 61);
    return ((next ^ (next >>> 14)) >>> 0) / 4294967296;
  };
}

const observers = [
  'uname -a',
  'uptime',
  'df -h',
  'ps aux',
  'cat /etc/hosts',
  'ls /var/log',
];
const writers = ['rm /tmp/generated', 'chmod 600 /tmp/key', 'touch /tmp/generated'];
const separators = ['; ', ' && ', ' || ', '\n'];

test('seeded mutations never auto-allow a known write', async () => {
  const random = mulberry32(seed);
  for (let index = 0; index < 32; index += 1) {
    const observer = observers[Math.floor(random() * observers.length)]!;
    const writer = writers[Math.floor(random() * writers.length)]!;
    const separator = separators[Math.floor(random() * separators.length)]!;
    const sourceText =
      random() < 0.5
        ? `${observer}${separator}${writer}`
        : `${writer}${separator}${observer}`;
    const decision = await evaluator.evaluate({ sourceText });
    assert.notEqual(decision.action, 'allow', sourceText);
  }
});

test('seeded observer-only scripts stay ordinary reads', async () => {
  const random = mulberry32(seed + 1);
  for (let index = 0; index < 16; index += 1) {
    const left = observers[Math.floor(random() * observers.length)]!;
    const right = observers[Math.floor(random() * observers.length)]!;
    const separator = separators[Math.floor(random() * separators.length)]!;
    const sourceText = `${left}${separator}${right}`;
    const decision = await evaluator.evaluate({ sourceText });
    assert.equal(decision.action, 'allow', sourceText);
  }
});
