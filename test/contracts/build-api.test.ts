import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import * as build from '../../src/build.ts';
import * as root from '../../src/index.ts';

test('build subpath owns the asset-copying API', async () => {
  assert.equal(typeof build.copyPolicyAssets, 'function');
  assert.deepEqual(build.POLICY_ASSET_MANIFEST, [
    {
      id: 'tree-sitter-runtime',
      fileName: 'web-tree-sitter.wasm',
    },
    {
      id: 'tree-sitter-bash',
      fileName: 'tree-sitter-bash.wasm',
    },
    {
      id: 'tree-sitter-python',
      fileName: 'tree-sitter-python.wasm',
    },
  ]);
  assert.equal(Object.isFrozen(build.POLICY_ASSET_MANIFEST), true);
  for (const asset of build.POLICY_ASSET_MANIFEST) {
    assert.equal(Object.isFrozen(asset), true);
  }

  const destinationDirectory = await mkdtemp(
    join(tmpdir(), 'command-policy-assets-'),
  );

  try {
    const copiedAssets = build.copyPolicyAssets({
      destinationDirectory,
    });

    assert.equal(copiedAssets instanceof Promise, true);
    assert.deepEqual(
      await copiedAssets,
      build.POLICY_ASSET_MANIFEST.map((asset) => ({
        id: asset.id,
        destinationPath: join(destinationDirectory, asset.fileName),
      })),
    );
    for (const asset of build.POLICY_ASSET_MANIFEST) {
      const bytes = await readFile(join(destinationDirectory, asset.fileName));
      assert.equal(bytes.length > 4, true);
      assert.deepEqual([...bytes.subarray(0, 4)], [0, 97, 115, 109]);
    }
    assert.equal('copyPolicyAssets' in root, false);
    assert.equal('POLICY_ASSET_MANIFEST' in root, false);
  } finally {
    await rm(destinationDirectory, { recursive: true, force: true });
  }
});

test('copyPolicyAssets can copy an explicit asset subset', async () => {
  const destinationDirectory = await mkdtemp(
    join(tmpdir(), 'command-policy-subset-'),
  );
  try {
    const copied = await build.copyPolicyAssets({
      destinationDirectory,
      include: ['tree-sitter-runtime', 'tree-sitter-bash'],
    });
    assert.deepEqual(
      copied.map((asset) => asset.id),
      ['tree-sitter-runtime', 'tree-sitter-bash'],
    );
    await assert.rejects(
      readFile(join(destinationDirectory, 'tree-sitter-python.wasm')),
      { code: 'ENOENT' },
    );
    await assert.rejects(
      build.copyPolicyAssets({ destinationDirectory, include: ['no-such-asset'] }),
      TypeError,
    );
  } finally {
    await rm(destinationDirectory, { recursive: true, force: true });
  }
});
