import type { PolicyAnalysisLimits } from '../../index.js';
import type { AnalyzedEffect } from '../analysis/decision.js';
import { isSensitiveIdentifier } from '../analysis/sensitivity.js';

export type UnknownRecord = Record<string, unknown>;

export const pureSqlFunctions = new Set([
  'abs',
  'avg',
  'cast',
  'char',
  'coalesce',
  'concat',
  'count',
  'date',
  'datetime',
  'format',
  'glob',
  'group_concat',
  'hex',
  'if',
  'ifnull',
  'instr',
  'json',
  'json_array',
  'json_array_length',
  'json_extract',
  'json_object',
  'json_quote',
  'json_type',
  'julianday',
  'length',
  'like',
  'likely',
  'lower',
  'ltrim',
  'max',
  'min',
  'nullif',
  'printf',
  'quote',
  'random',
  'randomblob',
  'rank',
  'replace',
  'round',
  'row_number',
  'rtrim',
  'soundex',
  'strftime',
  'substr',
  'substring',
  'sum',
  'time',
  'total',
  'trim',
  'typeof',
  'unicode',
  'unixepoch',
  'unlikely',
  'upper',
  'zeroblob',
]);

export function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function readEffect(domain: 'sqlite' | 'mysql'): AnalyzedEffect {
  return {
    effectCode: `${domain}.database.read`,
    action: 'allow',
    reasonCode: `${domain}.read_only`,
    kind: 'statement',
    summary: `${domain} statements have an ordinary read-only contract.`,
  };
}

export function reviewEffect(
  domain: 'sqlite' | 'mysql',
  category: 'write' | 'sensitive_read' | 'unknown',
): AnalyzedEffect {
  const summaryByCategory = {
    write: `${domain} statements may modify database or server state.`,
    sensitive_read: `${domain} statements may read sensitive database data.`,
    unknown: `${domain} statement semantics are not statically established.`,
  };
  return {
    effectCode: `${domain}.database.${category}`,
    action: 'review',
    reasonCode: `${domain}.${category}`,
    kind: 'statement',
    summary: summaryByCategory[category],
  };
}

export function isSensitiveSqlName(name: string): boolean {
  return name !== '*' && isSensitiveIdentifier(name);
}

export function isKnownSecretTable(name: string): boolean {
  return (
    isSensitiveSqlName(name) ||
    /^(?:auth|credential|credentials|private_keys?|secrets?|tokens?|api_keys?|service_accounts?)$/i.test(
      name,
    )
  );
}

export function walkRecords(
  value: unknown,
  limits: PolicyAnalysisLimits,
): readonly UnknownRecord[] | undefined {
  const records: UnknownRecord[] = [];
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 1 }];
  let work = 0;

  while (pending.length > 0) {
    const current = pending.pop()!;
    work += 1;
    if (
      work > limits.maxWorkUnits ||
      records.length > limits.maxAstNodes ||
      current.depth > limits.maxNestingDepth
    ) {
      return undefined;
    }
    if (Array.isArray(current.value)) {
      for (const child of current.value) {
        pending.push({ value: child, depth: current.depth + 1 });
      }
    } else if (isRecord(current.value)) {
      records.push(current.value);
      for (const child of Object.values(current.value)) {
        pending.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
  return records;
}
