import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import type { PolicyAssetReference } from '../../src/index.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

const assetUrls: Record<PolicyAssetReference['id'], URL> = {
  'tree-sitter-runtime': new URL(
    '../../node_modules/web-tree-sitter/web-tree-sitter.wasm',
    import.meta.url,
  ),
  'tree-sitter-bash': new URL(
    '../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm',
    import.meta.url,
  ),
  'tree-sitter-python': new URL(
    '../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-python.wasm',
    import.meta.url,
  ),
};

// Simulates a consumer that used copyPolicyAssets({ include }) without
// 'tree-sitter-python': the resolver has no python grammar to hand out.
test('missing python grammar fails closed for python payloads only', async () => {
  const evaluator = createShellPolicyEvaluator({
    assetResolver(asset) {
      if (asset.id === 'tree-sitter-python') {
        throw new Error('excluded by copyPolicyAssets include list');
      }
      return fileURLToPath(assetUrls[asset.id]);
    },
  });

  assert.equal(
    (await evaluator.evaluate({ sourceText: 'uptime' })).action,
    'allow',
  );

  const python = await evaluator.evaluate({
    sourceText: 'python3 -c "print(1)"',
  });
  assert.equal(python.action, 'review');
  assert.equal(python.reasonCode, 'shell.embedded_python_review');
  assert.equal(
    JSON.stringify(python).includes('excluded by copyPolicyAssets'),
    false,
  );
});
