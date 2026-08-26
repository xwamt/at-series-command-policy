export const POLICY_REASON_CODES = Object.freeze({
  ANALYSIS_UNAVAILABLE: 'policy.analysis_unavailable',
  INITIALIZATION_FAILED: 'policy.initialization_failed',
  PARSE_FAILED: 'policy.parse_failed',
  RESOURCE_LIMIT_EXCEEDED: 'policy.resource_limit_exceeded',
  UNKNOWN_SEMANTICS: 'policy.unknown_semantics',
  INVALID_DECISION: 'policy.invalid_decision',
} as const);

export type PolicyFailureReasonCode =
  (typeof POLICY_REASON_CODES)[keyof typeof POLICY_REASON_CODES];
