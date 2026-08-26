import { readFile } from 'node:fs/promises';

const manifestPath =
  process.env.AT_POLICY_MANIFEST_PATH ??
  new URL('../package.json', import.meta.url);
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const { POLICY_PACKAGE_VERSION } = await import('../dist/index.js');

if (typeof manifest.version !== 'string' || manifest.version.length === 0) {
  throw new Error('package manifest must contain a non-empty version');
}

if (manifest.version !== POLICY_PACKAGE_VERSION) {
  throw new Error(
    `package version ${manifest.version} does not match runtime policy version ${POLICY_PACKAGE_VERSION}`,
  );
}
