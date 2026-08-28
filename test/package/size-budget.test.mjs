import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const distDirectory = fileURLToPath(new URL('../../dist/', import.meta.url));
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

test('dist JavaScript stays within the minified raw-size budget', async () => {
  const entries = (await readdir(distDirectory)).filter(
    (name) => name.endsWith('.js') || name.endsWith('.cjs'),
  );
  let total = 0;
  const sizes = {};
  for (const name of entries) {
    const { size } = await stat(join(distDirectory, name));
    sizes[name] = size;
    total += size;
  }
  assert.equal(sizes['mysql.js'] <= 460_000, true, `mysql.js ${sizes['mysql.js']}`);
  assert.equal(total <= 1_900_000, true, `dist JS total ${total}`);
});
