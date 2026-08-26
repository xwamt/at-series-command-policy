import { POLICY_REASON_CODES } from '../core/reason-codes.js';
import type {
  PolicyDecision,
  PolicyEvaluationInput,
} from '../index.js';
import {
  POLICY_DECISION_SCHEMA_VERSION,
  POLICY_PACKAGE_VERSION,
} from '../core/version.js';
import type { PolicyDomain, PolicyFailure } from './failure-types.js';
import { createFailureEvidence } from './redacted-evidence.js';

interface FailClosedDecisionOptions {
  readonly domain: PolicyDomain;
  readonly failure: PolicyFailure;
  readonly input: PolicyEvaluationInput;
}

const reasonCodeByFailure = {
  'analysis-unavailable': POLICY_REASON_CODES.ANALYSIS_UNAVAILABLE,
  'initialization-failed': POLICY_REASON_CODES.INITIALIZATION_FAILED,
  'parse-failed': POLICY_REASON_CODES.PARSE_FAILED,
  'resource-limit-exceeded': POLICY_REASON_CODES.RESOURCE_LIMIT_EXCEEDED,
  'unknown-semantics': POLICY_REASON_CODES.UNKNOWN_SEMANTICS,
} as const satisfies Readonly<Record<PolicyFailure, string>>;

export function createFailClosedDecision({
  domain,
  failure,
  input,
}: FailClosedDecisionOptions): PolicyDecision {
  const sourceText =
    typeof input.sourceText === 'string' ? input.sourceText : '';

  return {
    schemaVersion: POLICY_DECISION_SCHEMA_VERSION,
    action: 'review',
    effects: [
      {
        effectCode: `${domain}.analysis.unknown`,
        action: 'review',
        evidenceIndexes: [0],
      },
    ],
    reasonCode: reasonCodeByFailure[failure],
    evidence: [createFailureEvidence(domain, failure, sourceText)],
    versions: {
      policy: POLICY_PACKAGE_VERSION,
      rules: {
        core: POLICY_PACKAGE_VERSION,
        [domain]: POLICY_PACKAGE_VERSION,
      },
      parsers: {
        [domain]: 'unavailable',
      },
    },
  };
}
