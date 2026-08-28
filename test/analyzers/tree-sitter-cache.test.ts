import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import type { PolicyAssetReference } from '../../src/index.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

const assetUrls: Record<PolicyAssetReference['id'], URL> = {
  'tree-sitter-runtime': new URL(
    '../../node_modules/web-tree-sitter/web-tree-sitter.wasm', import.meta.url),
  'tree-sitter-bash': new URL(
    '../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm', import.meta.url),
  'tree-sitter-python': new URL(
    '../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-python.wasm', import.meta.url),
};

function countingResolver(calls: Map<string, number>) {
  return (asset: PolicyAssetReference) => {
    calls.set(asset.id, (calls.get(asset.id) ?? 0) + 1);
    return fileURLToPath(assetUrls[asset.id]);
  };
}

test('a second evaluator with the same resolver reuses the loaded bash language', async () => {
  const calls = new Map<string, number>();
  const resolver = countingResolver(calls);
  const first = createShellPolicyEvaluator({ assetResolver: resolver });
  const second = createShellPolicyEvaluator({ assetResolver: resolver });
  assert.equal((await first.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal((await second.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal(calls.get('tree-sitter-bash'), 1);
  assert.equal(calls.get('tree-sitter-runtime'), 1);
});

test('a failing resolver still fails closed after another resolver succeeded', async () => {
  const good = createShellPolicyEvaluator();
  assert.equal((await good.evaluate({ sourceText: 'uptime' })).action, 'allow');
  const bad = createShellPolicyEvaluator({
    assetResolver() { throw new Error('controlled test failure'); },
  });
  const decision = await bad.evaluate({ sourceText: 'uptime' });
  assert.equal(decision.action, 'review');
  assert.equal(decision.reasonCode, 'policy.initialization_failed');
});

test('warmup preloads runtime and bash so evaluate pays no cold cost', async () => {
  const calls = new Map<string, number>();
  const resolver = countingResolver(calls);
  const { warmupShellPolicyEvaluator } = await import('../../src/shell.ts');
  await warmupShellPolicyEvaluator({ assetResolver: resolver });
  const evaluator = createShellPolicyEvaluator({ assetResolver: resolver });
  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal(calls.get('tree-sitter-bash'), 1);
  assert.equal(calls.get('tree-sitter-python') ?? 0, 0);
});
