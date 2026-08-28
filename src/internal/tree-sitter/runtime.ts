import { access, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  Language,
  Parser,
  type Node as SyntaxNode,
  type Tree,
} from 'web-tree-sitter';

import type {
  PolicyAssetReference,
  PolicyAssetResolver,
  PolicyAssetSource,
} from '../../index.js';

export type { SyntaxNode, Tree };

const assetById = {
  'tree-sitter-runtime': Object.freeze({
    id: 'tree-sitter-runtime',
    fileName: 'web-tree-sitter.wasm',
  }),
  'tree-sitter-bash': Object.freeze({
    id: 'tree-sitter-bash',
    fileName: 'tree-sitter-bash.wasm',
  }),
  'tree-sitter-python': Object.freeze({
    id: 'tree-sitter-python',
    fileName: 'tree-sitter-python.wasm',
  }),
} as const satisfies Readonly<Record<string, PolicyAssetReference>>;

const dependencyPathById: Readonly<Record<PolicyAssetReference['id'], string>> =
  Object.freeze({
    'tree-sitter-runtime':
      '../../../node_modules/web-tree-sitter/web-tree-sitter.wasm',
    'tree-sitter-bash':
      '../../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm',
    'tree-sitter-python':
      '../../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-python.wasm',
  });

async function defaultResolveAsset(
  asset: PolicyAssetReference,
): Promise<string> {
  const candidates = [
    fileURLToPath(new URL(`./assets/${asset.fileName}`, import.meta.url)),
    fileURLToPath(new URL(dependencyPathById[asset.id], import.meta.url)),
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Continue through controlled package layouts.
    }
  }
  throw new Error(`Policy parser asset is unavailable: ${asset.id}`);
}

function sourceForLoader(source: PolicyAssetSource): string | Uint8Array {
  return source instanceof URL ? source.toString() : source;
}

let runtimeInitialization: Promise<void> | undefined;

async function initializeRuntime(
  resolver: PolicyAssetResolver | undefined,
): Promise<void> {
  if (!runtimeInitialization) {
    runtimeInitialization = (async () => {
      const source = sourceForLoader(
        await (resolver ?? defaultResolveAsset)(
          assetById['tree-sitter-runtime'],
        ),
      );
      if (source instanceof Uint8Array) {
        await Parser.init({ wasmBinary: source });
      } else {
        await Parser.init({ locateFile: () => source });
      }
    })();
    // Success stays first-wins (Parser.init is an Emscripten global), but a
    // failure must not poison every later evaluator in the process.
    runtimeInitialization.catch(() => {
      runtimeInitialization = undefined;
    });
  }
  await runtimeInitialization;
}

type LanguageId = 'tree-sitter-bash' | 'tree-sitter-python';

const defaultLanguageCache = new Map<LanguageId, Promise<Language>>();
const resolverLanguageCaches = new WeakMap<
  PolicyAssetResolver,
  Map<LanguageId, Promise<Language>>
>();

function languageCacheFor(
  resolver: PolicyAssetResolver | undefined,
): Map<LanguageId, Promise<Language>> {
  if (!resolver) {
    return defaultLanguageCache;
  }
  let cache = resolverLanguageCaches.get(resolver);
  if (!cache) {
    cache = new Map();
    resolverLanguageCaches.set(resolver, cache);
  }
  return cache;
}

async function loadLanguage(
  id: LanguageId,
  resolver: PolicyAssetResolver | undefined,
): Promise<Language> {
  const cache = languageCacheFor(resolver);
  let pending = cache.get(id);
  if (!pending) {
    pending = (async () => {
      await initializeRuntime(resolver);
      const source = sourceForLoader(
        await (resolver ?? defaultResolveAsset)(assetById[id]),
      );
      return Language.load(source);
    })();
    cache.set(id, pending);
    // Never cache failures: this avoids poisoning later calls that share the
    // resolver and keeps the fail-closed retry path alive.
    pending.catch(() => cache.delete(id));
  }
  return pending;
}

export interface TreeSitterParserHandle {
  readonly parser: Parser;
  readonly parse: (sourceText: string) => Tree | null;
  readonly dispose: () => void;
}

export async function createTreeSitterParser(
  languageId: 'tree-sitter-bash' | 'tree-sitter-python',
  resolver?: PolicyAssetResolver,
): Promise<TreeSitterParserHandle> {
  const language = await loadLanguage(languageId, resolver);
  const parser = new Parser();
  try {
    parser.setLanguage(language);
  } catch (error) {
    parser.delete();
    throw error;
  }

  return {
    parser,
    parse(sourceText: string) {
      parser.reset();
      return parser.parse(sourceText);
    },
    dispose() {
      parser.delete();
    },
  };
}

export async function readAssetBytes(
  resolver: PolicyAssetResolver | undefined,
  id: PolicyAssetReference['id'],
): Promise<Uint8Array> {
  const source = sourceForLoader(
    await (resolver ?? defaultResolveAsset)(assetById[id]),
  );
  return source instanceof Uint8Array ? source : readFile(source);
}
