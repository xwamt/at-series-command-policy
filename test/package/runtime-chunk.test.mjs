import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const distDirectory = new URL('../../dist/', import.meta.url);
const assetsDirectory = new URL('../../dist/assets/', import.meta.url);

test('shell and python entries share one tree-sitter runtime instance', async () => {
  const { createShellPolicyEvaluator } = await import(
    new URL('../../dist/shell.js', import.meta.url).href
  );
  const calls = new Map();
  const resolver = (asset) => {
    calls.set(asset.id, (calls.get(asset.id) ?? 0) + 1);
    return fileURLToPath(new URL(asset.fileName, assetsDirectory));
  };
  const evaluator = createShellPolicyEvaluator({ assetResolver: resolver });

  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal(calls.get('tree-sitter-python') ?? 0, 0);
  assert.equal(calls.get('tree-sitter-runtime'), 1);

  const embedded = await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' });
  assert.equal(embedded.action, 'allow');
  assert.equal(calls.get('tree-sitter-python'), 1);
  assert.equal(calls.get('tree-sitter-runtime'), 1);
});

test('dist entries import the sibling runtime chunk instead of inlining glue', async () => {
  const shellEsm = await readFile(new URL('shell.js', distDirectory), 'utf8');
  const pythonEsm = await readFile(new URL('python.js', distDirectory), 'utf8');
  const shellCjs = await readFile(new URL('shell.cjs', distDirectory), 'utf8');
  const pythonCjs = await readFile(new URL('python.cjs', distDirectory), 'utf8');

  assert.equal(shellEsm.includes('./tree-sitter-runtime.js'), true);
  assert.equal(pythonEsm.includes('./tree-sitter-runtime.js'), true);
  assert.equal(shellCjs.includes('./tree-sitter-runtime.cjs'), true);
  assert.equal(pythonCjs.includes('./tree-sitter-runtime.cjs'), true);
});
