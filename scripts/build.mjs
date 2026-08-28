import { build } from 'esbuild';
import { rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));

const entryPoints = {
  index: 'src/index.ts',
  shell: 'src/shell.ts',
  python: 'src/python.ts',
  sqlite: 'src/sqlite.ts',
  mysql: 'src/mysql.ts',
  redis: 'src/redis.ts',
  build: 'src/build.ts',
};

const sharedOptions = {
  absWorkingDir: repositoryRoot,
  entryPoints,
  outdir: 'dist',
  entryNames: '[name]',
  bundle: true,
  platform: 'node',
  target: 'node18',
  minify: true,
  legalComments: 'eof',
  logLevel: 'info',
  external: ['./mysql.js', './python.js', './redis.js', './sqlite.js'],
};

await rm(new URL('../dist/', import.meta.url), {
  recursive: true,
  force: true,
});

await build({
  ...sharedOptions,
  format: 'esm',
  outExtension: {
    '.js': '.js',
  },
});

await build({
  ...sharedOptions,
  format: 'cjs',
  banner: {
    js: 'var __commandPolicyModuleUrl = require("node:url").pathToFileURL(__filename).href;',
  },
  define: {
    'import.meta.url': '__commandPolicyModuleUrl',
  },
  outExtension: {
    '.js': '.cjs',
  },
});

const { copyPolicyAssets } = await import('../dist/build.js');
await copyPolicyAssets({
  destinationDirectory: fileURLToPath(new URL('../dist/assets/', import.meta.url)),
});
