import { access, copyFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface PolicyAssetDescriptor {
  readonly id: string;
  readonly fileName: string;
}

export interface CopyPolicyAssetsOptions {
  readonly destinationDirectory: string;
}

export interface CopiedPolicyAsset {
  readonly id: string;
  readonly destinationPath: string;
}

function asset(id: string, fileName: string): PolicyAssetDescriptor {
  return Object.freeze({ id, fileName });
}

export const POLICY_ASSET_MANIFEST: readonly PolicyAssetDescriptor[] =
  Object.freeze([
    asset('tree-sitter-runtime', 'web-tree-sitter.wasm'),
    asset('tree-sitter-bash', 'tree-sitter-bash.wasm'),
    asset('tree-sitter-python', 'tree-sitter-python.wasm'),
  ]);

const dependencyAssetPathById: Readonly<Record<string, string>> = Object.freeze({
  'tree-sitter-runtime':
    '../node_modules/web-tree-sitter/web-tree-sitter.wasm',
  'tree-sitter-bash':
    '../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm',
  'tree-sitter-python':
    '../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-python.wasm',
});

async function resolvePackagedAssetPath(
  descriptor: PolicyAssetDescriptor,
): Promise<string> {
  const candidates = [
    fileURLToPath(new URL(`./assets/${descriptor.fileName}`, import.meta.url)),
    fileURLToPath(
      new URL(dependencyAssetPathById[descriptor.id] ?? '', import.meta.url),
    ),
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next controlled location.
    }
  }

  throw new Error(`Policy asset is unavailable: ${descriptor.id}`);
}

/**
 * Copies the explicit production asset allowlist into a consumer build.
 */
export async function copyPolicyAssets(
  options: CopyPolicyAssetsOptions,
): Promise<readonly CopiedPolicyAsset[]> {
  await mkdir(options.destinationDirectory, { recursive: true });

  return Promise.all(
    POLICY_ASSET_MANIFEST.map(async (descriptor) => {
      const sourcePath = await resolvePackagedAssetPath(descriptor);
      const destinationPath = join(
        options.destinationDirectory,
        descriptor.fileName,
      );
      await copyFile(sourcePath, destinationPath);
      return {
        id: descriptor.id,
        destinationPath,
      };
    }),
  );
}
