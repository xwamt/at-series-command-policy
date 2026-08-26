import { isPolicyDecision } from './decision-validation.js';
import { POLICY_REASON_CODES } from './reason-codes.js';
import type { PolicyAction, PolicyDecision } from '../index.js';
import {
  POLICY_DECISION_SCHEMA_VERSION,
  POLICY_PACKAGE_VERSION,
  POLICY_VERSION_METADATA,
} from './version.js';

const actionRank: Readonly<Record<PolicyAction, number>> = {
  allow: 0,
  review: 1,
  deny: 2,
};

const invalidDecisionEffect = Object.freeze({
  effectCode: 'policy.decision.invalid',
  action: 'review' as const,
  evidenceIndexes: Object.freeze([]),
});

const invalidDecisionVersions = Object.freeze({
  policy: POLICY_PACKAGE_VERSION,
  rules: POLICY_VERSION_METADATA.rules,
  parsers: POLICY_VERSION_METADATA.parsers,
});

const INVALID_POLICY_DECISION: PolicyDecision = Object.freeze({
  schemaVersion: POLICY_DECISION_SCHEMA_VERSION,
  action: 'review',
  effects: Object.freeze([invalidDecisionEffect]),
  reasonCode: POLICY_REASON_CODES.INVALID_DECISION,
  evidence: Object.freeze([]),
  versions: invalidDecisionVersions,
});

/**
 * Returns an existing decision, preserving its evidence and version metadata.
 * Ties keep the first decision so an additional rule cannot replace an
 * equally strict official decision. Malformed decisions are replaced with a
 * stable review decision before aggregation.
 */
export function combinePolicyDecisions(
  firstDecision: PolicyDecision,
  ...additionalDecisions: readonly PolicyDecision[]
): PolicyDecision {
  const candidates = [firstDecision, ...additionalDecisions] as unknown[];
  const firstCandidate = candidates[0];
  let strictestDecision = isPolicyDecision(firstCandidate)
    ? firstCandidate
    : INVALID_POLICY_DECISION;

  for (const candidate of candidates.slice(1)) {
    const decision = isPolicyDecision(candidate)
      ? candidate
      : INVALID_POLICY_DECISION;

    if (actionRank[decision.action] > actionRank[strictestDecision.action]) {
      strictestDecision = decision;
    }
  }

  return strictestDecision;
}
