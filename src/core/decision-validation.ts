import type {
  PolicyAction,
  PolicyDecision,
  PolicyEvidenceKind,
  SourcePosition,
} from '../index.js';
import {
  POLICY_DECISION_SCHEMA_VERSION,
  POLICY_PACKAGE_VERSION,
} from './version.js';

const actionRank: Readonly<Record<PolicyAction, number>> = {
  allow: 0,
  review: 1,
  deny: 2,
};

const evidenceKinds: ReadonlySet<PolicyEvidenceKind> = new Set([
  'command',
  'argument',
  'path',
  'identifier',
  'literal',
  'statement',
  'unknown',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isPolicyAction(value: unknown): value is PolicyAction {
  return value === 'allow' || value === 'review' || value === 'deny';
}

function isSourcePosition(value: unknown): value is SourcePosition {
  return (
    isRecord(value) &&
    typeof value.offset === 'number' &&
    Number.isInteger(value.offset) &&
    value.offset >= 0 &&
    typeof value.line === 'number' &&
    Number.isInteger(value.line) &&
    value.line >= 1 &&
    typeof value.column === 'number' &&
    Number.isInteger(value.column) &&
    value.column >= 1 &&
    (value.line === 1
      ? value.offset === value.column - 1
      : value.offset >= value.line + value.column - 2)
  );
}

function isSourceLocation(value: unknown): boolean {
  if (
    !isRecord(value) ||
    !isSourcePosition(value.start) ||
    !isSourcePosition(value.end)
  ) {
    return false;
  }

  const offsetDelta = value.end.offset - value.start.offset;
  const lineDelta = value.end.line - value.start.line;

  if (offsetDelta < 0 || lineDelta < 0) {
    return false;
  }

  if (offsetDelta === 0) {
    return lineDelta === 0 && value.end.column === value.start.column;
  }

  if (lineDelta === 0) {
    return value.end.column - value.start.column === offsetDelta;
  }

  const minimumMultilineOffset = lineDelta + value.end.column - 1;
  return offsetDelta >= minimumMultilineOffset;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    isRecord(value) &&
    Object.values(value).every(
      (entry) => typeof entry === 'string' && entry.length > 0,
    )
  );
}

export function isPolicyDecision(value: unknown): value is PolicyDecision {
  if (
    !isRecord(value) ||
    value.schemaVersion !== POLICY_DECISION_SCHEMA_VERSION ||
    !isPolicyAction(value.action) ||
    !Array.isArray(value.effects) ||
    typeof value.reasonCode !== 'string' ||
    value.reasonCode.length === 0 ||
    !Array.isArray(value.evidence) ||
    !isRecord(value.versions) ||
    value.versions.policy !== POLICY_PACKAGE_VERSION ||
    !isStringRecord(value.versions.rules) ||
    !isStringRecord(value.versions.parsers)
  ) {
    return false;
  }

  const evidenceIsValid = value.evidence.every((entry) => {
    if (
      !isRecord(entry) ||
      !evidenceKinds.has(entry.kind as PolicyEvidenceKind) ||
      entry.redacted !== true ||
      typeof entry.summary !== 'string' ||
      entry.summary.length === 0 ||
      !isSourceLocation(entry.location)
    ) {
      return false;
    }

    return true;
  });

  if (!evidenceIsValid) {
    return false;
  }

  const decisionAction = value.action;
  const evidenceCount = value.evidence.length;

  return value.effects.every((effect) => {
    if (
      !isRecord(effect) ||
      typeof effect.effectCode !== 'string' ||
      effect.effectCode.length === 0 ||
      !isPolicyAction(effect.action) ||
      !Array.isArray(effect.evidenceIndexes) ||
      actionRank[effect.action] > actionRank[decisionAction]
    ) {
      return false;
    }

    return effect.evidenceIndexes.every(
      (index) =>
        typeof index === 'number' &&
        Number.isInteger(index) &&
        index >= 0 &&
        index < evidenceCount,
    );
  });
}
