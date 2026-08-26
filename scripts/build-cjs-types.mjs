import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { rewriteCjsModuleSpecifiers } from './rewrite-cjs-module-specifiers.mjs';

const declarationDirectory = new URL('../.types/', import.meta.url);
const distDirectory = fileURLToPath(new URL('../dist/', import.meta.url));

const publicEntries = [
  'index',
  'shell',
  'python',
  'sqlite',
  'mysql',
  'redis',
  'build',
];
const cjsSpecifierMap = new Map(
  publicEntries.map((entry) => [
    `./${entry}.js`,
    `./${entry}.cjs`,
  ]),
);

await mkdir(distDirectory, {
  recursive: true,
});

for (const entry of publicEntries) {
  const esmDeclaration = (
    await readFile(new URL(`${entry}.d.ts`, declarationDirectory), 'utf8')
  )
    .trimEnd()
    .concat('\n');
  const cjsDeclaration = rewriteCjsModuleSpecifiers(
    esmDeclaration,
    cjsSpecifierMap,
  );

  await Promise.all([
    writeFile(`${distDirectory}/${entry}.d.ts`, esmDeclaration, 'utf8'),
    writeFile(`${distDirectory}/${entry}.d.cts`, cjsDeclaration, 'utf8'),
  ]);
}

await rm(declarationDirectory, {
  recursive: true,
  force: true,
});
