import assert from 'node:assert/strict';
import test from 'node:test';

import {
  inputExceedsLimit,
  resolvePolicyLimits,
} from '../../src/internal/analysis/limits.ts';

const limits8 = resolvePolicyLimits({ maxInputBytes: 8 });

test('inputExceedsLimit matches exact UTF-8 byte semantics', () => {
  assert.equal(inputExceedsLimit('', limits8), false);
  assert.equal(inputExceedsLimit('a'.repeat(8), limits8), false); // 恰好边界
  assert.equal(inputExceedsLimit('a'.repeat(9), limits8), true);
  assert.equal(inputExceedsLimit('€€', limits8), false); // 6 字节，length*3=6 走快路径
  assert.equal(inputExceedsLimit('€€€', limits8), true); // 9 字节，length*3=9>8 走精确路径
  assert.equal(inputExceedsLimit('😀😀', limits8), false); // 8 字节，length=4 走精确路径
  assert.equal(inputExceedsLimit('😀😀a', limits8), true); // 9 字节
});

test('inputExceedsLimit is equivalent to TextEncoder byte counting', () => {
  const encoder = new TextEncoder();
  const samples = [
    '',
    'a',
    'a'.repeat(7),
    'a'.repeat(8),
    'a'.repeat(9),
    '€', // 3-byte character
    '€€',
    '€€€',
    'ß€', // 2-byte + 3-byte mix
    '😀', // surrogate pair, 4 bytes
    '😀😀',
    '😀😀a',
    'a😀€ß',
    '\u0000'.repeat(8),
  ];
  for (const sample of samples) {
    assert.equal(
      inputExceedsLimit(sample, limits8),
      encoder.encode(sample).byteLength > limits8.maxInputBytes,
      `sample ${JSON.stringify(sample)}`,
    );
  }
});

test('default limit keeps large ASCII inputs on the fast path boundary', () => {
  const limits = resolvePolicyLimits(undefined);
  assert.equal(inputExceedsLimit('a'.repeat(limits.maxInputBytes), limits), false);
  assert.equal(inputExceedsLimit('a'.repeat(limits.maxInputBytes + 1), limits), true);
});
