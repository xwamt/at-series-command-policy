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
  'tree-sitter-runtime': 'src/internal/tree-sitter/runtime.ts',
};

// Rewrites non-entry relative imports of the tree-sitter runtime module to a
// sibling external file so every entry shares one runtime module instance
// (one Emscripten glue copy, one Parser.init) instead of inlining it.
function treeSitterRuntimeChunkPlugin(importPath) {
  return {
    name: 'tree-sitter-runtime-chunk',
    setup(build) {
      build.onResolve(
        { filter: /^\.\.?\/.*tree-sitter\/runtime\.js$/ },
        (args) =>
          args.kind === 'entry-point'
            ? null
            : { path: importPath, external: true },
      );
    },
  };
}

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
  plugins: [treeSitterRuntimeChunkPlugin('./tree-sitter-runtime.js')],
  outExtension: {
    '.js': '.js',
  },
});

await build({
  ...sharedOptions,
  format: 'cjs',
  plugins: [treeSitterRuntimeChunkPlugin('./tree-sitter-runtime.cjs')],
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
