import type {
  PolicyEvidence,
  SourceLocation,
} from '../index.js';
import type {
  PolicyDomain,
  PolicyFailure,
} from './failure-types.js';

const evidenceSummaryByFailure = {
  'analysis-unavailable': 'analysis is unavailable',
  'initialization-failed': 'analyzer initialization failed',
  'parse-failed': 'parsing failed',
  'resource-limit-exceeded': 'an analysis resource limit was exceeded',
  'unknown-semantics': 'semantics are unknown',
} as const satisfies Readonly<Record<PolicyFailure, string>>;

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
    start: {
      offset: 0,
      line: 1,
      column: 1,
    },
    end: {
      offset: sourceText.length,
      line,
      column: sourceText.length - finalLineStart + 1,
    },
  };
}

/**
 * Constructs evidence from controlled labels only. sourceText is used solely
 * to calculate a location and must never be copied into summary.
 */
export function createFailureEvidence(
  domain: PolicyDomain,
  failure: PolicyFailure,
  sourceText: string,
): PolicyEvidence {
  return {
    kind: 'unknown',
    location: wholeSourceLocation(sourceText),
    redacted: true,
    summary: `${domain} source requires review because ${evidenceSummaryByFailure[failure]}.`,
  };
}
