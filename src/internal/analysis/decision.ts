import type {
  PolicyAction,
  PolicyDecision,
  PolicyEffect,
  PolicyEvidence,
  PolicyEvidenceKind,
  PolicyEvaluationInput,
  SourceLocation,
} from '../../index.js';
import {
  POLICY_DECISION_SCHEMA_VERSION,
  POLICY_PACKAGE_VERSION,
  POLICY_RULE_VERSIONS,
} from '../../core/version.js';
import type { PolicyDomain } from '../failure-types.js';

const actionRank: Readonly<Record<PolicyAction, number>> = Object.freeze({
  allow: 0,
  review: 1,
  deny: 2,
});

export interface AnalyzedEffect {
  readonly effectCode: string;
  readonly action: PolicyAction;
  readonly reasonCode: string;
  readonly kind: PolicyEvidenceKind;
  /** Must be controlled static text, never source-derived text. */
  readonly summary: string;
}

function wholeSourceLocation(sourceText: string): SourceLocation {
  let line = 1;
  let finalLineStart = 0;
  for (let index = 0; index < sourceText.length; index += 1) {
    if (sourceText.charCodeAt(index) === 0x0a) {
      line += 1;
      finalLineStart = index + 1;
    }
  }
  return {
    start: { offset: 0, line: 1, column: 1 },
    end: {
      offset: sourceText.length,
      line,
      column: sourceText.length - finalLineStart + 1,
    },
  };
}

export function createAnalyzedDecision(
  domain: PolicyDomain,
  input: PolicyEvaluationInput,
  parserVersion: string,
  analyzedEffects: readonly AnalyzedEffect[],
): PolicyDecision {
  const sourceText =
    typeof input.sourceText === 'string' ? input.sourceText : '';
  const effectsToUse =
    analyzedEffects.length > 0
      ? analyzedEffects
      : [
          {
            effectCode: `${domain}.process.noop`,
            action: 'allow' as const,
            reasonCode: `${domain}.read_only`,
            kind: 'statement' as const,
            summary: `${domain} source has no external effect.`,
          },
        ];

  let strictest = effectsToUse[0]!;
  for (const effect of effectsToUse.slice(1)) {
    if (actionRank[effect.action] > actionRank[strictest.action]) {
      strictest = effect;
    }
  }

  const location = wholeSourceLocation(sourceText);
  const evidence: PolicyEvidence[] = effectsToUse.map((effect) =>
    Object.freeze({
      kind: effect.kind,
      location,
      redacted: true as const,
      summary: effect.summary,
    }),
  );
  const effects: PolicyEffect[] = effectsToUse.map((effect, index) =>
    Object.freeze({
      effectCode: effect.effectCode,
      action: effect.action,
      evidenceIndexes: Object.freeze([index]),
    }),
  );

  return Object.freeze({
    schemaVersion: POLICY_DECISION_SCHEMA_VERSION,
    action: strictest.action,
    effects: Object.freeze(effects),
    reasonCode: strictest.reasonCode,
    evidence: Object.freeze(evidence),
    versions: Object.freeze({
      policy: POLICY_PACKAGE_VERSION,
      rules: Object.freeze({
        core: POLICY_RULE_VERSIONS.core,
        [domain]: POLICY_RULE_VERSIONS[domain],
      }),
      parsers: Object.freeze({
        [domain]: parserVersion,
      }),
    }),
  });
}
