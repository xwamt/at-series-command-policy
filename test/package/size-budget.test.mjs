import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const MAX_PACKED_BYTES = 2.5 * 1024 * 1024;

test('packed production assets stay within the published size budget', () => {
  const packed = spawnSync(
    'npm',
    ['pack', '--dry-run', '--json', '--ignore-scripts'],
    {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: { ...process.env, npm_config_devdir: undefined },
    },
  );
  assert.equal(packed.status, 0, packed.stderr);
  const [manifest] = JSON.parse(packed.stdout);
  assert.equal(
    manifest.size <= MAX_PACKED_BYTES,
    true,
    `packed size ${manifest.size} exceeds ${MAX_PACKED_BYTES}`,
  );
  const wasmFiles = manifest.files.filter(({ path }) => path.endsWith('.wasm'));
  assert.equal(wasmFiles.length, 3);
});
