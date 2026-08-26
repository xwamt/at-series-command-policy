import assert from 'node:assert/strict';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const temporaryRoot = fileURLToPath(new URL('../../.tmp/', import.meta.url));
const typeScriptCompiler = fileURLToPath(
  new URL('../../node_modules/.bin/tsc', import.meta.url),
);

function cleanEnvironment() {
  const environment = { ...process.env };
  delete environment.npm_config_devdir;
  delete environment.NPM_CONFIG_DEVDIR;
  return environment;
}

function run(command, arguments_, cwd) {
  const result = spawnSync(command, arguments_, {
    cwd,
    encoding: 'utf8',
    env: cleanEnvironment(),
  });
  assert.equal(
    result.status,
    0,
    [result.stdout, result.stderr].filter(Boolean).join('\n'),
  );
}

test('packed package works from a clean installation', async () => {
  await mkdir(temporaryRoot, {
    recursive: true,
  });
  const temporaryDirectory = await mkdtemp(
    join(temporaryRoot, 'installed-consumer-'),
  );
  const consumerDirectory = join(temporaryDirectory, 'consumer');
  await mkdir(consumerDirectory);

  try {
    const packed = spawnSync(
      'npm',
      ['pack', '--json', '--ignore-scripts', '--pack-destination', temporaryDirectory],
      {
        cwd: repositoryRoot,
        encoding: 'utf8',
        env: cleanEnvironment(),
      },
    );
    assert.equal(packed.status, 0, packed.stderr);
    const [packResult] = JSON.parse(packed.stdout);
    const tarballPath = join(temporaryDirectory, packResult.filename);

    await writeFile(
      join(consumerDirectory, 'package.json'),
      JSON.stringify({
        name: 'command-policy-clean-consumer',
        private: true,
        type: 'module',
      }),
      'utf8',
    );

    run(
      'npm',
      [
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--no-package-lock',
        tarballPath,
      ],
      consumerDirectory,
    );

    await Promise.all([
      writeFile(
        join(consumerDirectory, 'consumer.mjs'),
        [
          "import { POLICY_PACKAGE_VERSION } from '@at-series/command-policy';",
          "import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';",
          "const result = await createShellPolicyEvaluator().evaluate({ sourceText: 'echo ok' });",
          "if (POLICY_PACKAGE_VERSION !== '0.1.0' || result.action !== 'allow') process.exit(1);",
          '',
        ].join('\n'),
        'utf8',
      ),
      writeFile(
        join(consumerDirectory, 'consumer.cjs'),
        [
          "const policy = require('@at-series/command-policy');",
          "const shell = require('@at-series/command-policy/shell');",
          "shell.createShellPolicyEvaluator().evaluate({ sourceText: 'echo ok' }).then((result) => {",
          "  if (policy.POLICY_PACKAGE_VERSION !== '0.1.0' || result.action !== 'allow') process.exit(1);",
          '});',
          '',
        ].join('\n'),
        'utf8',
      ),
      writeFile(
        join(consumerDirectory, 'consumer.mts'),
        [
          "import type { PolicyDecision } from '@at-series/command-policy';",
          "import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';",
          "const decision: Promise<PolicyDecision> = createShellPolicyEvaluator().evaluate({ sourceText: 'echo ok' });",
          'void decision;',
          '',
        ].join('\n'),
        'utf8',
      ),
      writeFile(
        join(consumerDirectory, 'consumer.cts'),
        [
          "import policy = require('@at-series/command-policy');",
          "import shell = require('@at-series/command-policy/shell');",
          "const decision: Promise<policy.PolicyDecision> = shell.createShellPolicyEvaluator().evaluate({ sourceText: 'echo ok' });",
          'void decision;',
          '',
        ].join('\n'),
        'utf8',
      ),
      writeFile(
        join(consumerDirectory, 'tsconfig.json'),
        JSON.stringify({
          compilerOptions: {
            module: 'NodeNext',
            moduleResolution: 'NodeNext',
            target: 'ES2022',
            strict: true,
            skipLibCheck: false,
            noEmit: true,
          },
          files: ['./consumer.mts', './consumer.cts'],
        }),
        'utf8',
      ),
    ]);

    run(process.execPath, ['consumer.mjs'], consumerDirectory);
    run(process.execPath, ['consumer.cjs'], consumerDirectory);
    run(typeScriptCompiler, ['--project', 'tsconfig.json'], consumerDirectory);

    const installedManifest = JSON.parse(
      await readFile(
        join(
          consumerDirectory,
          'node_modules',
          '@at-series',
          'command-policy',
          'package.json',
        ),
        'utf8',
      ),
    );
    assert.equal(installedManifest.version, '0.1.0');
  } finally {
    await rm(temporaryDirectory, {
      recursive: true,
      force: true,
    });
  }
});
