import { parse } from 'sqlite3-parser';

import type {
  PolicyAnalysisLimits,
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
} from '../analysis/limits.js';
import { createFailClosedDecision } from '../fail-closed.js';
import {
  isRecord,
  isSensitiveSqlName,
  isSensitiveTableRef,
  pureSqlFunctions,
  readEffect,
  reviewEffect,
  walkRecords,
  type UnknownRecord,
} from './common.js';

const SQLITE_PARSER_VERSION = 'sqlite3-parser@0.7.1/sqlite-3.53.0';

const readOnlyPragmas = new Set([
  'application_id',
  'collation_list',
  'compile_options',
  'database_list',
  'encoding',
  'foreign_key_list',
  'freelist_count',
  'function_list',
  'index_info',
  'index_list',
  'index_xinfo',
  'journal_mode',
  'module_list',
  'page_count',
  'pragma_list',
  'schema_version',
  'table_info',
  'table_list',
  'table_xinfo',
  'user_version',
]);

export interface InternalSqliteEvaluatorOptions {
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

function nestedName(value: unknown): string | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (typeof value.name === 'string') {
    return value.name;
  }
  if (typeof value.text === 'string') {
    return value.text;
  }
  if ('objName' in value) {
    return nestedName(value.objName);
  }
  return undefined;
}

function functionName(node: UnknownRecord): string | undefined {
  return nestedName(node.name)?.toLowerCase();
}

// QualifiedName nodes hold the schema qualifier (e.g. `main.credentials`)
// in `dbName`; unqualified table names omit the field.
function qualifierName(value: unknown): string | undefined {
  return isRecord(value) ? nestedName(value.dbName) : undefined;
}

function analyzeSelect(
  statement: unknown,
  limits: PolicyAnalysisLimits,
): AnalyzedEffect {
  const records = walkRecords(statement, limits);
  if (!records) {
    return reviewEffect('sqlite', 'unknown');
  }
  for (const node of records) {
    if (node.type !== 'TableSelectTable') {
      continue;
    }
    const table = nestedName(node.tblName);
    if (table === undefined) {
      continue;
    }
    const schema = qualifierName(node.tblName);
    if (isSensitiveTableRef(schema, table) || isSensitiveSqlName(table)) {
      return reviewEffect('sqlite', 'sensitive_read');
    }
  }
  if (
    records.some(
      (node) =>
        node.type === 'Id' &&
        typeof node.name === 'string' &&
        isSensitiveSqlName(node.name),
    )
  ) {
    return reviewEffect('sqlite', 'sensitive_read');
  }
  for (const node of records) {
    if (typeof node.type === 'string' && node.type.startsWith('FunctionCall')) {
      const name = functionName(node);
      if (!name || !pureSqlFunctions.has(name)) {
        return reviewEffect('sqlite', 'unknown');
      }
    }
  }
  return readEffect('sqlite');
}

function analyzePragma(statement: UnknownRecord): AnalyzedEffect {
  const name = nestedName(statement.name)?.toLowerCase();
  const body = statement.body;
  if (
    !name ||
    !readOnlyPragmas.has(name) ||
    (isRecord(body) &&
      body.type !== 'CallPragmaBody' &&
      body.type !== 'MinusPragmaBody')
  ) {
    return reviewEffect('sqlite', 'write');
  }
  return readEffect('sqlite');
}

function analyzeStatement(
  statement: unknown,
  limits: PolicyAnalysisLimits,
): AnalyzedEffect {
  if (!isRecord(statement) || typeof statement.type !== 'string') {
    return reviewEffect('sqlite', 'unknown');
  }
  if (statement.type === 'SelectStmt') {
    return analyzeSelect(statement, limits);
  }
  if (statement.type === 'ExplainStmt') {
    const explained = statement.stmt;
    return isRecord(explained) && explained.type === 'SelectStmt'
      ? analyzeSelect(explained, limits)
      : reviewEffect('sqlite', 'write');
  }
  if (statement.type === 'PragmaStmt') {
    return analyzePragma(statement);
  }
  return reviewEffect('sqlite', 'write');
}

export function createDeterministicSqliteEvaluator(
  options: InternalSqliteEvaluatorOptions = {},
): PolicyEvaluator {
  const limits = resolvePolicyLimits(options.limits);

  return {
    async evaluate(input: PolicyEvaluationInput) {
      const sourceText =
        typeof input.sourceText === 'string' ? input.sourceText : '';
      if (sourceText.trim().length === 0) {
        return createFailClosedDecision({
          domain: 'sqlite',
          failure: 'parse-failed',
          input,
        });
      }
      if (inputExceedsLimit(sourceText, limits)) {
        return createFailClosedDecision({
          domain: 'sqlite',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      let parsed;
      try {
        parsed = parse(sourceText);
      } catch {
        return createFailClosedDecision({
          domain: 'sqlite',
          failure: 'parse-failed',
          input,
        });
      }
      if (parsed.status !== 'ok') {
        return createFailClosedDecision({
          domain: 'sqlite',
          failure: 'parse-failed',
          input,
        });
      }
      const statements = parsed.root.cmds;
      if (statements.length === 0) {
        return createFailClosedDecision({
          domain: 'sqlite',
          failure: 'parse-failed',
          input,
        });
      }
      if (statements.length > limits.maxStatements) {
        return createFailClosedDecision({
          domain: 'sqlite',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      return createAnalyzedDecision(
        'sqlite',
        input,
        SQLITE_PARSER_VERSION,
        statements.map((statement) => analyzeStatement(statement, limits)),
      );
    },
  };
}
