import { combinePolicyDecisions as combineDecisions } from './core/combine.js';
import { POLICY_REASON_CODES as reasonCodes } from './core/reason-codes.js';
import {
  POLICY_DECISION_SCHEMA_VERSION as schemaVersion,
  POLICY_PACKAGE_VERSION as packageVersion,
  POLICY_VERSION_METADATA as versionMetadata,
} from './core/version.js';

export type PolicyAction = 'allow' | 'review' | 'deny';

export interface SourcePosition {
  /** Zero-based UTF-16 code-unit offset into the exact input source text. */
  readonly offset: number;
  /** One-based line number. */
  readonly line: number;
  /** One-based UTF-16 column number. */
  readonly column: number;
}

/**
 * A half-open `[start, end)` range over exact sourceText. No newline or Unicode
 * normalization is applied; CRLF occupies two UTF-16 code units.
 */
export interface SourceLocation {
  readonly start: SourcePosition;
  readonly end: SourcePosition;
}

export type PolicyEvidenceKind =
  | 'command'
  | 'argument'
  | 'path'
  | 'identifier'
  | 'literal'
  | 'statement'
  | 'unknown';

export interface PolicyEvidence {
  readonly kind: PolicyEvidenceKind;
  readonly location: SourceLocation;
  /**
   * Always true. summary must be selected from static, controlled text and
   * must never contain sourceText, cwd, parser errors, or other raw input.
   */
  readonly redacted: true;
  readonly summary: string;
}

export interface PolicyEffect {
  /** Stable, namespaced identifier such as `shell.filesystem.read`. */
  readonly effectCode: string;
  readonly action: PolicyAction;
  /** Indexes into the containing decision's evidence array. */
  readonly evidenceIndexes: readonly number[];
}

export interface PolicyVersionMetadata {
  readonly policy: string;
  readonly rules: Readonly<Record<string, string>>;
  readonly parsers: Readonly<Record<string, string>>;
}

export interface PolicyDecision {
  readonly schemaVersion: string;
  readonly action: PolicyAction;
  readonly effects: readonly PolicyEffect[];
  readonly reasonCode: string;
  readonly evidence: readonly PolicyEvidence[];
  readonly versions: PolicyVersionMetadata;
}

export interface PolicyEvaluationInput {
  /**
   * Potentially sensitive. The exact final text that would be executed.
   * Evaluators must not rewrite, log, or include it in evidence summaries.
   */
  readonly sourceText: string;
  /**
   * Potentially sensitive execution context supplied separately from
   * sourceText. Evaluators must not log or include it in evidence summaries.
   */
  readonly cwd?: string;
}

export interface PolicyAssetReference {
  readonly id:
    | 'tree-sitter-runtime'
    | 'tree-sitter-bash'
    | 'tree-sitter-python';
  readonly fileName: string;
}

export type PolicyAssetSource = string | URL | Uint8Array;

export type PolicyAssetResolver = (
  asset: PolicyAssetReference,
) => PolicyAssetSource | Promise<PolicyAssetSource>;

export interface PolicyAnalysisLimits {
  readonly maxInputBytes: number;
  readonly maxAstNodes: number;
  readonly maxNestingDepth: number;
  readonly maxStatements: number;
  readonly maxWorkUnits: number;
}

export interface PolicyEvaluator<
  TInput extends PolicyEvaluationInput = PolicyEvaluationInput,
> {
  evaluate(input: TInput): Promise<PolicyDecision>;
}

export interface PolicyPackageVersionMetadata extends PolicyVersionMetadata {
  readonly schemaVersion: string;
}

export interface PolicyReasonCodes {
  readonly ANALYSIS_UNAVAILABLE: 'policy.analysis_unavailable';
  readonly INITIALIZATION_FAILED: 'policy.initialization_failed';
  readonly PARSE_FAILED: 'policy.parse_failed';
  readonly RESOURCE_LIMIT_EXCEEDED: 'policy.resource_limit_exceeded';
  readonly UNKNOWN_SEMANTICS: 'policy.unknown_semantics';
  readonly INVALID_DECISION: 'policy.invalid_decision';
}

export type PolicyFailureReasonCode =
  PolicyReasonCodes[keyof PolicyReasonCodes];

export const POLICY_DECISION_SCHEMA_VERSION: '1.0.0' = schemaVersion;
export const POLICY_PACKAGE_VERSION: string = packageVersion;
export const POLICY_VERSION_METADATA: PolicyPackageVersionMetadata =
  versionMetadata;
export const POLICY_REASON_CODES: PolicyReasonCodes = reasonCodes;

export function combinePolicyDecisions(
  firstDecision: PolicyDecision,
  ...additionalDecisions: readonly PolicyDecision[]
): PolicyDecision {
  return combineDecisions(firstDecision, ...additionalDecisions);
}
