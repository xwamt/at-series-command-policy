import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

const publicEntries = [
  'index',
  'shell',
  'python',
  'sqlite',
  'mysql',
  'redis',
  'build',
];

test('npm tarball contains only public package artifacts', () => {
  const environment = { ...process.env };
  delete environment.npm_config_devdir;
  delete environment.NPM_CONFIG_DEVDIR;

  const packed = spawnSync(
    'npm',
    ['pack', '--dry-run', '--json', '--ignore-scripts'],
    {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: environment,
    },
  );

  assert.equal(packed.status, 0, packed.stderr);

  const [manifest] = JSON.parse(packed.stdout);
  const actualFiles = manifest.files
    .map(({ path }) => path)
    .sort();
  const expectedFiles = [
    'LICENSE',
    'NOTICE',
    'README.md',
    'docs/api.md',
    'dist/assets/tree-sitter-bash.wasm',
    'dist/assets/tree-sitter-python.wasm',
    'dist/assets/web-tree-sitter.wasm',
    'dist/tree-sitter-runtime.js',
    'dist/tree-sitter-runtime.cjs',
    'package.json',
    ...publicEntries.flatMap((entry) => [
      `dist/${entry}.cjs`,
      `dist/${entry}.d.cts`,
      `dist/${entry}.d.ts`,
      `dist/${entry}.js`,
    ]),
  ].sort();

  assert.deepEqual(actualFiles, expectedFiles);
});
