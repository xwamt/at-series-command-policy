import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const temporaryDirectory = new URL('../../.tmp/', import.meta.url);
const mismatchedManifest = new URL('mismatched-package.json', temporaryDirectory);

test('build fails when runtime policy version differs from package version', async () => {
  await mkdir(temporaryDirectory, {
    recursive: true,
  });
  await writeFile(
    mismatchedManifest,
    JSON.stringify({
      version: '9.9.9',
    }),
    'utf8',
  );

  try {
    const environment = {
      ...process.env,
      AT_POLICY_MANIFEST_PATH: fileURLToPath(mismatchedManifest),
    };
    delete environment.npm_config_devdir;
    delete environment.NPM_CONFIG_DEVDIR;

    const build = spawnSync('npm', ['run', 'build'], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: environment,
    });

    assert.notEqual(build.status, 0);
    assert.match(
      `${build.stdout}\n${build.stderr}`,
      /package version 9\.9\.9 does not match runtime policy version \d+\.\d+\.\d+/,
    );
  } finally {
    await rm(temporaryDirectory, {
      recursive: true,
      force: true,
    });
  }
});
