import mysqlParserModule from 'node-sql-parser/build/mysql.js';

import type {
  PolicyAnalysisLimits,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from '../../index.js';
import { createAnalyzedDecision } from '../analysis/decision.js';
import {
  inputExceedsLimit,
  resolvePolicyLimits,
} from '../analysis/limits.js';
import { createFailClosedDecision } from '../fail-closed.js';
import {
  isKnownSecretColumn,
  isRecord,
  isSensitiveSqlName,
  isSensitiveTableRef,
  pureSqlFunctions,
  readEffect,
  reviewEffect,
  walkRecords,
  type UnknownRecord,
} from './common.js';

const MYSQL_PARSER_VERSION = 'node-sql-parser@5.4.0/mysql';
const MysqlParser = (
  mysqlParserModule as unknown as {
    readonly Parser: new () => {
      astify(
        sourceText: string,
        options: { readonly database: 'MySQL' },
      ): unknown;
    };
  }
).Parser;

export interface InternalMysqlEvaluatorOptions {
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

// Identifier fields in node-sql-parser ASTs are usually plain strings but can
// appear as `{ value }` wrappers in some productions.
function mysqlIdentifierValue(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }
  return isRecord(value) && typeof value.value === 'string'
    ? value.value
    : undefined;
}

function mysqlFunctionName(node: UnknownRecord): string | undefined {
  if (typeof node.name === 'string') {
    return node.name.toLowerCase();
  }
  if (!isRecord(node.name) || !Array.isArray(node.name.name)) {
    return undefined;
  }
  const finalPart = node.name.name.at(-1);
  return isRecord(finalPart) && typeof finalPart.value === 'string'
    ? finalPart.value.toLowerCase()
    : undefined;
}

function analyzeSelect(
  statement: unknown,
  limits: PolicyAnalysisLimits,
) {
  const records = walkRecords(statement, limits);
  if (!records) {
    return reviewEffect('mysql', 'unknown');
  }

  for (const node of records) {
    if (
      node.type === 'select' &&
      (typeof node.locking_read === 'string' ||
        (isRecord(node.into) &&
          (typeof node.into.keyword === 'string' ||
            isRecord(node.into.expr))))
    ) {
      return reviewEffect('mysql', 'write');
    }
    if (
      node.type === 'column_ref' &&
      typeof node.column === 'string' &&
      isKnownSecretColumn(node.column)
    ) {
      return reviewEffect('mysql', 'sensitive_read');
    }
    if (node.type === 'assign' || node.type === 'var') {
      return reviewEffect('mysql', 'unknown');
    }
  }

  for (const node of records) {
    const table = mysqlIdentifierValue(node.table);
    if (table === undefined) {
      continue;
    }
    // Table references in FROM clauses carry the qualifying schema in `db`
    // (e.g. `SELECT * FROM mysql.user` yields { db: 'mysql', table: 'user' }).
    const schema = mysqlIdentifierValue(node.db);
    if (isSensitiveTableRef(schema, table) || isSensitiveSqlName(table)) {
      return reviewEffect('mysql', 'sensitive_read');
    }
  }

  for (const node of records) {
    if (node.type === 'function' || node.type === 'aggr_func') {
      const name = mysqlFunctionName(node);
      if (!name || !pureSqlFunctions.has(name)) {
        return reviewEffect('mysql', 'unknown');
      }
    }
  }
  return readEffect('mysql');
}

function analyzeStatement(
  statement: unknown,
  limits: PolicyAnalysisLimits,
) {
  if (!isRecord(statement) || typeof statement.type !== 'string') {
    return reviewEffect('mysql', 'unknown');
  }
  if (statement.type === 'select') {
    return analyzeSelect(statement, limits);
  }
  if (statement.type === 'show' || statement.type === 'desc') {
    return readEffect('mysql');
  }
  if (statement.type === 'explain') {
    return isRecord(statement.expr) && statement.expr.type === 'select'
      ? analyzeSelect(statement.expr, limits)
      : reviewEffect('mysql', 'unknown');
  }
  return reviewEffect('mysql', 'write');
}

export function createDeterministicMysqlEvaluator(
  options: InternalMysqlEvaluatorOptions = {},
): PolicyEvaluator {
  const limits = resolvePolicyLimits(options.limits);
  const parser = new MysqlParser();

  return {
    async evaluate(input: PolicyEvaluationInput) {
      const sourceText =
        typeof input.sourceText === 'string' ? input.sourceText : '';
      if (sourceText.trim().length === 0) {
        return createFailClosedDecision({
          domain: 'mysql',
          failure: 'parse-failed',
          input,
        });
      }
      if (inputExceedsLimit(sourceText, limits)) {
        return createFailClosedDecision({
          domain: 'mysql',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      let ast: unknown;
      try {
        ast = parser.astify(sourceText, { database: 'MySQL' });
      } catch {
        return createFailClosedDecision({
          domain: 'mysql',
          failure: 'parse-failed',
          input,
        });
      }
      const statements = Array.isArray(ast) ? ast : [ast];
      if (statements.length === 0) {
        return createFailClosedDecision({
          domain: 'mysql',
          failure: 'parse-failed',
          input,
        });
      }
      if (statements.length > limits.maxStatements) {
        return createFailClosedDecision({
          domain: 'mysql',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      return createAnalyzedDecision(
        'mysql',
        input,
        MYSQL_PARSER_VERSION,
        statements.map((statement) => analyzeStatement(statement, limits)),
      );
    },
  };
}
