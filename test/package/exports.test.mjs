import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);

const runtimeExports = {
  '@at-series/command-policy': [
    'POLICY_DECISION_SCHEMA_VERSION',
    'POLICY_PACKAGE_VERSION',
    'POLICY_REASON_CODES',
    'POLICY_VERSION_METADATA',
    'combinePolicyDecisions',
  ],
  '@at-series/command-policy/shell': ['createShellPolicyEvaluator'],
  '@at-series/command-policy/python': ['createPythonPolicyEvaluator'],
  '@at-series/command-policy/sqlite': ['createSqlitePolicyEvaluator'],
  '@at-series/command-policy/mysql': ['createMysqlPolicyEvaluator'],
  '@at-series/command-policy/redis': ['createRedisPolicyEvaluator'],
  '@at-series/command-policy/build': [
    'POLICY_ASSET_MANIFEST',
    'copyPolicyAssets',
  ],
};

test('all public subpaths load through ESM and CJS conditions', async () => {
  for (const [specifier, expectedExports] of Object.entries(runtimeExports)) {
    const esm = await import(specifier);
    const cjs = require(specifier);

    assert.deepEqual(Object.keys(esm).sort(), expectedExports.sort(), specifier);
    assert.deepEqual(Object.keys(cjs).sort(), expectedExports.sort(), specifier);
  }
});

test('published manifest has no runtime or vscode dependency', () => {
  const manifest = require('@at-series/command-policy/package.json');
  const root = require('@at-series/command-policy');

  assert.equal(manifest.sideEffects, false);
  assert.equal(manifest.engines.node, '>=18');
  assert.equal(manifest.engines.vscode, undefined);
  assert.equal(manifest.publishConfig.access, 'public');
  assert.equal(root.POLICY_PACKAGE_VERSION, manifest.version);
  assert.equal(manifest.dependencies, undefined);
  assert.equal(manifest.peerDependencies, undefined);
  assert.equal(manifest.optionalDependencies, undefined);
});

test('internal modules are blocked by package exports', async () => {
  const internalSpecifier =
    '@at-series/command-policy/dist/internal/fail-closed.js';

  await assert.rejects(import(internalSpecifier), {
    code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  });
  assert.throws(() => require(internalSpecifier), {
    code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  });
});
