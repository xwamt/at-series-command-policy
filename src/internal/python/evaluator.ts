import type {
  PolicyAnalysisLimits,
  PolicyAssetResolver,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from '../../index.js';
import {
  createAnalyzedDecision,
  type AnalyzedEffect,
} from '../analysis/decision.js';
import {
  inputExceedsLimit,
  resolvePolicyLimits,
  WorkBudget,
} from '../analysis/limits.js';
import { isSensitivePath } from '../analysis/sensitivity.js';
import { createFailClosedDecision } from '../fail-closed.js';
import {
  createTreeSitterParser,
  type SyntaxNode,
  type TreeSitterParserHandle,
} from '../tree-sitter/runtime.js';

const PYTHON_PARSER_VERSION = 'tree-sitter-python@0.25.0';

const approvedModules = new Set([
  'collections',
  'csv',
  'datetime',
  'decimal',
  'fractions',
  'functools',
  'itertools',
  'json',
  'math',
  'pathlib',
  're',
  'sqlite3',
  'statistics',
]);

const pureBuiltins = new Set([
  'abs',
  'all',
  'any',
  'bool',
  'dict',
  'enumerate',
  'float',
  'frozenset',
  'int',
  'len',
  'list',
  'max',
  'min',
  'object',
  'print',
  'range',
  'repr',
  'reversed',
  'round',
  'set',
  'sorted',
  'str',
  'sum',
  'tuple',
  'zip',
]);

const forbiddenCalls = new Set([
  '__import__',
  'breakpoint',
  'compile',
  'delattr',
  'eval',
  'exec',
  'getattr',
  'globals',
  'help',
  'input',
  'locals',
  'memoryview',
  'setattr',
  'vars',
]);

const unsupportedNodeTypes = new Set([
  'async_function_definition',
  'await',
  'class_definition',
  'decorated_definition',
  'function_definition',
  'global_statement',
  'lambda',
  'nonlocal_statement',
  'yield',
]);

const sqliteReadMethods = new Set([
  'close',
  'cursor',
  'description',
  'fetchall',
  'fetchmany',
  'fetchone',
  'keys',
]);

const sqliteSqlMethods = new Set(['execute', 'executemany', 'executescript']);

const sqliteWriteMethods = new Set([
  'backup',
  'commit',
  'create_aggregate',
  'create_collation',
  'create_function',
  'dump',
  'enable_load_extension',
  'iterdump',
  'load_extension',
  'rollback',
  'set_authorizer',
]);

interface ImportBindings {
  readonly symbols: ReadonlyMap<string, string>;
  readonly sqliteImported: boolean;
  readonly effects: readonly AnalyzedEffect[];
}

export interface InternalPythonEvaluatorOptions {
  readonly assetResolver?: PolicyAssetResolver;
  readonly limits?: Partial<PolicyAnalysisLimits>;
  readonly sqliteEvaluator?: () => Promise<PolicyEvaluator>;
}

const allowEffect = (
  effectCode = 'python.process.pure',
  summary = 'Python syntax is within the approved pure static subset.',
): AnalyzedEffect => ({
  effectCode,
  action: 'allow',
  reasonCode: 'python.read_only',
  kind: 'statement',
  summary,
});

const reviewEffect = (
  effectCode = 'python.semantics.unknown',
  summary = 'Python semantics are outside the approved static subset.',
): AnalyzedEffect => ({
  effectCode,
  action: 'review',
  reasonCode: 'python.unknown_semantics',
  kind: 'statement',
  summary,
});

function decodePythonString(node: SyntaxNode | undefined): string | undefined {
  if (!node || node.type !== 'string') {
    return undefined;
  }
  if (node.namedChildren.some((child) => child.type === 'interpolation')) {
    return undefined;
  }
  const match = /^([rRuU]*)(['"]{1,3})([\s\S]*)(\2)$/.exec(node.text);
  if (!match) {
    return undefined;
  }
  const raw = /r/i.test(match[1] ?? '');
  const content = match[3] ?? '';
  if (raw) {
    return content;
  }
  let decoded = '';
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index]!;
    if (character !== '\\') {
      decoded += character;
      continue;
    }
    index += 1;
    const escaped = content[index];
    if (escaped === undefined) {
      return undefined;
    }
    const simpleEscapes: Readonly<Record<string, string>> = {
      '\\': '\\',
      '"': '"',
      "'": "'",
      n: '\n',
      r: '\r',
      t: '\t',
    };
    const replacement = simpleEscapes[escaped];
    if (replacement === undefined) {
      return undefined;
    }
    decoded += replacement;
  }
  return decoded;
}

function callArguments(call: SyntaxNode): readonly SyntaxNode[] {
  return call.childForFieldName('arguments')?.namedChildren ?? [];
}

function moduleRoot(moduleName: string): string {
  return moduleName.split('.')[0] ?? moduleName;
}

function collectImports(root: SyntaxNode): ImportBindings {
  const symbols = new Map<string, string>();
  const effects: AnalyzedEffect[] = [];
  const pending = [root];

  while (pending.length > 0) {
    const node = pending.pop()!;
    if (node.type === 'import_statement') {
      for (const imported of node.namedChildren) {
        const nameNode =
          imported.type === 'aliased_import'
            ? imported.childForFieldName('name')
            : imported;
        const aliasNode = imported.childForFieldName('alias');
        const moduleName = nameNode?.text;
        if (!moduleName || !approvedModules.has(moduleRoot(moduleName))) {
          effects.push(
            reviewEffect(
              'python.import.unknown',
              'A Python import is outside the approved standard-library subset.',
            ),
          );
          continue;
        }
        symbols.set(aliasNode?.text ?? moduleRoot(moduleName), moduleName);
        effects.push(
          allowEffect(
            'python.import.approved',
            'A Python import is in the approved standard-library subset.',
          ),
        );
      }
    } else if (node.type === 'import_from_statement') {
      const moduleName = node.childForFieldName('module_name')?.text;
      if (!moduleName || !approvedModules.has(moduleRoot(moduleName))) {
        effects.push(
          reviewEffect(
            'python.import.unknown',
            'A Python import is outside the approved standard-library subset.',
          ),
        );
      } else {
        for (const imported of node.childrenForFieldName('name')) {
          const importedName = imported.text;
          symbols.set(importedName, `${moduleName}.${importedName}`);
        }
        effects.push(
          allowEffect(
            'python.import.approved',
            'A Python import is in the approved standard-library subset.',
          ),
        );
      }
    }
    pending.push(...node.namedChildren);
  }

  return {
    symbols,
    sqliteImported: [...symbols.values()].some(
      (moduleName) => moduleRoot(moduleName) === 'sqlite3',
    ),
    effects,
  };
}

function pathReadEffect(path: string | undefined): AnalyzedEffect {
  if (path === undefined) {
    return reviewEffect(
      'python.filesystem.unknown_read',
      'A Python filesystem path is not statically established.',
    );
  }
  if (isSensitivePath(path)) {
    return reviewEffect(
      'python.filesystem.sensitive_read',
      'Python code may read a sensitive filesystem resource.',
    );
  }
  return allowEffect(
    'python.filesystem.read',
    'Python code reads an ordinary static filesystem resource.',
  );
}

function analyzeOpen(call: SyntaxNode): AnalyzedEffect {
  const args = callArguments(call);
  const path = decodePythonString(args[0]);
  const mode = decodePythonString(args[1]) ?? 'r';
  if (/[wax+]/.test(mode)) {
    return reviewEffect(
      'python.filesystem.write',
      'Python code may modify a filesystem resource.',
    );
  }
  return pathReadEffect(path);
}

function resolveIdentifier(
  name: string,
  bindings: ImportBindings,
): string {
  return bindings.symbols.get(name) ?? name;
}

function pathConstructorArgument(call: SyntaxNode): string | undefined {
  const functionNode = call.childForFieldName('function');
  if (functionNode?.type !== 'identifier' || functionNode.text !== 'Path') {
    return undefined;
  }
  return decodePythonString(callArguments(call)[0]);
}

function analyzeAttributeCall(
  call: SyntaxNode,
  functionNode: SyntaxNode,
  bindings: ImportBindings,
  sqlPayloads: string[],
): AnalyzedEffect {
  const object = functionNode.childForFieldName('object');
  const attribute = functionNode.childForFieldName('attribute')?.text;
  if (!object || !attribute) {
    return reviewEffect();
  }

  if (bindings.sqliteImported && sqliteWriteMethods.has(attribute)) {
    return reviewEffect(
      'python.sqlite.write',
      'Python sqlite3 code may modify database state.',
    );
  }
  if (bindings.sqliteImported && sqliteSqlMethods.has(attribute)) {
    const sql = decodePythonString(callArguments(call)[0]);
    if (!sql) {
      return reviewEffect(
        'python.sqlite.unknown_sql',
        'A sqlite3 statement is not statically established.',
      );
    }
    sqlPayloads.push(sql);
    return allowEffect(
      'python.sqlite.execute',
      'Python sqlite3 code executes a static SQL payload.',
    );
  }
  if (bindings.sqliteImported && sqliteReadMethods.has(attribute)) {
    return allowEffect(
      'python.sqlite.cursor',
      'Python sqlite3 code uses a read-only cursor API.',
    );
  }
  if (
    bindings.sqliteImported &&
    attribute === 'connect' &&
    object.type === 'identifier' &&
    moduleRoot(resolveIdentifier(object.text, bindings)) === 'sqlite3'
  ) {
    return pathReadEffect(decodePythonString(callArguments(call)[0]));
  }

  if (object.type === 'identifier') {
    const qualified = `${resolveIdentifier(object.text, bindings)}.${attribute}`;
    if (
      /^(?:json\.(?:dumps|loads)|math\.[A-Za-z_][A-Za-z0-9_]*|statistics\.[A-Za-z_][A-Za-z0-9_]*|re\.(?:compile|escape|findall|fullmatch|match|search|split))$/.test(
        qualified,
      )
    ) {
      return allowEffect();
    }
    return reviewEffect();
  }

  if (object.type === 'call') {
    const innerFunction = object.childForFieldName('function');
    if (innerFunction?.type === 'identifier' && innerFunction.text === 'open') {
      if (new Set(['read', 'readline', 'readlines']).has(attribute)) {
        return analyzeOpen(object);
      }
      return reviewEffect(
        'python.filesystem.write',
        'Python code may invoke a side-effecting file API.',
      );
    }
    const path = pathConstructorArgument(object);
    if (path !== undefined || innerFunction?.text === 'Path') {
      if (new Set(['read_bytes', 'read_text']).has(attribute)) {
        return pathReadEffect(path);
      }
      if (attribute === 'open') {
        const mode = decodePythonString(callArguments(call)[0]) ?? 'r';
        return /[wax+]/.test(mode)
          ? reviewEffect(
              'python.filesystem.write',
              'Python code may modify a filesystem resource.',
            )
          : pathReadEffect(path);
      }
      return reviewEffect(
        'python.filesystem.write',
        'Python code may invoke a side-effecting path API.',
      );
    }
  }

  if (
    new Set(['integer', 'list', 'set', 'string', 'tuple']).has(object.type) &&
    new Set([
      'capitalize',
      'casefold',
      'count',
      'endswith',
      'find',
      'index',
      'isalnum',
      'isalpha',
      'isdigit',
      'join',
      'lower',
      'replace',
      'split',
      'startswith',
      'strip',
      'upper',
    ]).has(attribute)
  ) {
    return allowEffect();
  }

  return reviewEffect();
}

function analyzeCall(
  call: SyntaxNode,
  bindings: ImportBindings,
  sqlPayloads: string[],
): AnalyzedEffect {
  const functionNode = call.childForFieldName('function');
  if (!functionNode) {
    return reviewEffect();
  }
  if (functionNode.type === 'attribute') {
    return analyzeAttributeCall(call, functionNode, bindings, sqlPayloads);
  }
  if (functionNode.type !== 'identifier') {
    return reviewEffect();
  }

  const name = resolveIdentifier(functionNode.text, bindings);
  if (forbiddenCalls.has(name)) {
    return reviewEffect(
      'python.dynamic_code',
      'Python code invokes dynamic execution or reflection.',
    );
  }
  if (name === 'open') {
    return analyzeOpen(call);
  }
  if (name === 'pathlib.Path' || name === 'Path') {
    return allowEffect();
  }
  if (
    pureBuiltins.has(name) ||
    /^(?:math|statistics)\.[A-Za-z_][A-Za-z0-9_]*$/.test(name)
  ) {
    return allowEffect();
  }
  return reviewEffect();
}

function analyzeTree(
  parser: TreeSitterParserHandle,
  sourceText: string,
  limits: PolicyAnalysisLimits,
):
  | {
      readonly ok: true;
      readonly effects: readonly AnalyzedEffect[];
      readonly sqlPayloads: readonly string[];
    }
  | {
      readonly ok: false;
      readonly failure: 'parse-failed' | 'resource-limit-exceeded';
    } {
  const tree = parser.parse(sourceText);
  if (!tree) {
    return { ok: false, failure: 'resource-limit-exceeded' };
  }
  try {
    if (tree.rootNode.hasError) {
      return { ok: false, failure: 'parse-failed' };
    }
    const bindings = collectImports(tree.rootNode);
    const effects = [...bindings.effects];
    const sqlPayloads: string[] = [];
    const budget = new WorkBudget(limits.maxWorkUnits);
    const pending: { node: SyntaxNode; depth: number }[] = [
      { node: tree.rootNode, depth: 1 },
    ];
    let nodes = 0;
    let statements = 0;

    while (pending.length > 0) {
      const { node, depth } = pending.pop()!;
      nodes += 1;
      if (
        nodes > limits.maxAstNodes ||
        depth > limits.maxNestingDepth ||
        !budget.consume()
      ) {
        return { ok: false, failure: 'resource-limit-exceeded' };
      }
      if (node.isError || node.isMissing) {
        return { ok: false, failure: 'parse-failed' };
      }
      if (unsupportedNodeTypes.has(node.type)) {
        effects.push(reviewEffect());
      }
      if (node.type.endsWith('_statement')) {
        statements += 1;
        if (statements > limits.maxStatements) {
          return { ok: false, failure: 'resource-limit-exceeded' };
        }
      }
      if (node.type === 'call') {
        effects.push(analyzeCall(node, bindings, sqlPayloads));
      }
      pending.push(
        ...node.namedChildren.map((child) => ({ node: child, depth: depth + 1 })),
      );
    }

    return {
      ok: true,
      effects: effects.length > 0 || sqlPayloads.length > 0 ? effects : [allowEffect()],
      sqlPayloads,
    };
  } finally {
    tree.delete();
  }
}

export function createDeterministicPythonEvaluator(
  options: InternalPythonEvaluatorOptions = {},
): PolicyEvaluator {
  const limits = resolvePolicyLimits(options.limits);
  let parserPromise: Promise<TreeSitterParserHandle> | undefined;
  const getParser = () => {
    parserPromise ??= createTreeSitterParser(
      'tree-sitter-python',
      options.assetResolver,
    );
    return parserPromise;
  };

  return {
    async evaluate(input: PolicyEvaluationInput) {
      const sourceText =
        typeof input.sourceText === 'string' ? input.sourceText : '';
      if (sourceText.trim().length === 0) {
        return createFailClosedDecision({
          domain: 'python',
          failure: 'parse-failed',
          input,
        });
      }
      if (inputExceedsLimit(sourceText, limits)) {
        return createFailClosedDecision({
          domain: 'python',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      let parser;
      try {
        parser = await getParser();
      } catch {
        return createFailClosedDecision({
          domain: 'python',
          failure: 'initialization-failed',
          input,
        });
      }

      let analysis;
      try {
        analysis = analyzeTree(parser, sourceText, limits);
      } catch {
        return createFailClosedDecision({
          domain: 'python',
          failure: 'parse-failed',
          input,
        });
      }
      if (!analysis.ok) {
        return createFailClosedDecision({
          domain: 'python',
          failure: analysis.failure,
          input,
        });
      }
      const sqliteEffects: AnalyzedEffect[] = [];
      if (analysis.sqlPayloads.length > 0) {
        if (!options.sqliteEvaluator) {
          sqliteEffects.push(
            reviewEffect(
              'python.sqlite.unavailable',
              'Python sqlite3 payloads cannot be analyzed without a sqlite evaluator.',
            ),
          );
        } else {
          const sqlite = await options.sqliteEvaluator();
          for (const sql of analysis.sqlPayloads) {
            const nested = await sqlite.evaluate({ sourceText: sql });
            sqliteEffects.push({
              effectCode: `python.embedded.sqlite.${nested.action}`,
              action: nested.action,
              reasonCode:
                nested.action === 'allow'
                  ? 'python.read_only'
                  : nested.reasonCode.startsWith('sqlite.')
                    ? nested.reasonCode.replace(/^sqlite\./, 'python.sqlite_')
                    : nested.reasonCode,
              kind: 'statement',
              summary:
                nested.action === 'allow'
                  ? 'Python sqlite3 code executes an ordinary read-only SQL payload.'
                  : 'Python sqlite3 code executes a SQL payload that requires review.',
            });
          }
        }
      }
      return createAnalyzedDecision(
        'python',
        input,
        PYTHON_PARSER_VERSION,
        [...analysis.effects, ...sqliteEffects],
      );
    },
  };
}
