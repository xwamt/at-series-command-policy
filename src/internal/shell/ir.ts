import type { PolicyAnalysisLimits } from '../../index.js';
import { WorkBudget } from '../analysis/limits.js';
import type {
  SyntaxNode,
  TreeSitterParserHandle,
} from '../tree-sitter/runtime.js';

export interface ShellCommandIr {
  readonly name: string | undefined;
  readonly arguments: readonly (string | undefined)[];
}

export interface ShellRedirectIr {
  readonly direction: 'input' | 'output' | 'read-write' | 'unknown';
  readonly target: string | undefined;
  readonly harmless: boolean;
}

export interface ShellIr {
  readonly commands: readonly ShellCommandIr[];
  readonly redirects: readonly ShellRedirectIr[];
  readonly unsupported: boolean;
  readonly background: boolean;
}

export type ShellParseResult =
  | { readonly ok: true; readonly ir: ShellIr }
  | {
      readonly ok: false;
      readonly failure:
        | 'parse-failed'
        | 'resource-limit-exceeded'
        | 'unknown-semantics';
    };

const unsupportedNodeTypes = new Set([
  'process_substitution',
  'heredoc_redirect',
  'herestring_redirect',
  'function_definition',
  'coproc',
  'select_statement',
]);

const dynamicNodeTypes = new Set([
  'arithmetic_expansion',
  'brace_expansion',
  'command_substitution',
  'expansion',
  'process_substitution',
  'simple_expansion',
  'special_variable_name',
  'variable_expansion',
]);

function containsDynamicSyntax(node: SyntaxNode): boolean {
  const pending = [node];
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (current !== node && dynamicNodeTypes.has(current.type)) {
      return true;
    }
    pending.push(...current.namedChildren);
  }
  return false;
}

function decodeStaticShellText(text: string): string | undefined {
  if (text.includes('\0')) {
    return undefined;
  }

  let value = '';
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]!;
    if (!quote && (character === "'" || character === '"')) {
      quote = character;
      continue;
    }
    if (quote === character) {
      quote = undefined;
      continue;
    }
    if (character === '\\' && quote !== "'") {
      index += 1;
      const escaped = text[index];
      if (escaped === undefined) {
        return undefined;
      }
      value += escaped;
      continue;
    }
    value += character;
  }

  if (quote || value.includes('`')) {
    return undefined;
  }
  return value;
}

function staticNodeValue(node: SyntaxNode | null): string | undefined {
  if (!node || containsDynamicSyntax(node)) {
    return undefined;
  }
  return decodeStaticShellText(node.text);
}

function commandFromNode(node: SyntaxNode): ShellCommandIr {
  return {
    name: staticNodeValue(node.childForFieldName('name')),
    arguments: node
      .childrenForFieldName('argument')
      .map((argument) => staticNodeValue(argument)),
  };
}

function redirectFromNode(node: SyntaxNode): ShellRedirectIr {
  const target = staticNodeValue(node.childForFieldName('destination'));
  const text = node.text;
  const harmless =
    target === '/dev/null' ||
    target === '/dev/stdout' ||
    target === '/dev/stderr' ||
    />\s*&(?:1|2|-)\s*$/.test(text);

  let direction: ShellRedirectIr['direction'] = 'unknown';
  if (/<>/.test(text)) {
    direction = 'read-write';
  } else if (/(?:^|[^<])>>?|&>/.test(text)) {
    direction = 'output';
  } else if (/<(?![<(])/.test(text)) {
    direction = 'input';
  }

  return { direction, target, harmless };
}

export function parseShellIr(
  parser: TreeSitterParserHandle,
  sourceText: string,
  limits: PolicyAnalysisLimits,
): ShellParseResult {
  const tree = parser.parse(sourceText);
  if (!tree) {
    return { ok: false, failure: 'resource-limit-exceeded' };
  }

  try {
    if (tree.rootNode.hasError) {
      return { ok: false, failure: 'parse-failed' };
    }

    const commands: ShellCommandIr[] = [];
    const redirects: ShellRedirectIr[] = [];
    const budget = new WorkBudget(limits.maxWorkUnits);
    const pending: { node: SyntaxNode; depth: number }[] = [
      { node: tree.rootNode, depth: 1 },
    ];
    let nodeCount = 0;
    let unsupported = false;
    let background = false;

    while (pending.length > 0) {
      const { node, depth } = pending.pop()!;
      nodeCount += 1;
      if (
        nodeCount > limits.maxAstNodes ||
        depth > limits.maxNestingDepth ||
        !budget.consume()
      ) {
        return { ok: false, failure: 'resource-limit-exceeded' };
      }
      if (node.isError || node.isMissing) {
        return { ok: false, failure: 'parse-failed' };
      }
      if (unsupportedNodeTypes.has(node.type)) {
        unsupported = true;
      }
      if (node.type === 'command') {
        commands.push(commandFromNode(node));
        if (commands.length > limits.maxStatements) {
          return { ok: false, failure: 'resource-limit-exceeded' };
        }
      } else if (node.type === 'file_redirect') {
        redirects.push(redirectFromNode(node));
      }

      for (const child of node.children) {
        if (child.type === '&') {
          background = true;
        }
        pending.push({ node: child, depth: depth + 1 });
      }
    }

    return {
      ok: true,
      ir: {
        commands,
        redirects,
        unsupported,
        background,
      },
    };
  } finally {
    tree.delete();
  }
}
