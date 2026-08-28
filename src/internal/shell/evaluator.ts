import type {
  PolicyAnalysisLimits,
  PolicyAssetResolver,
  PolicyEvaluationInput,
  PolicyEvaluator,
  SourceLocation,
} from '../../index.js';
import {
  createAnalyzedDecision,
  type AnalyzedEffect,
} from '../analysis/decision.js';
import {
  inputExceedsLimit,
  resolvePolicyLimits,
} from '../analysis/limits.js';
import { isSensitivePath } from '../analysis/sensitivity.js';
import { createFailClosedDecision } from '../fail-closed.js';
import {
  createTreeSitterParser,
  type TreeSitterParserHandle,
} from '../tree-sitter/runtime.js';
import { analyzeShellCommand, normalizeExecutable } from './contracts.js';
import {
  analyzeEmbeddedCommand,
  embeddedDomainForExecutable,
  type EmbeddedEvaluatorLoaders,
} from './embedded.js';
import {
  parseShellIr,
  type ShellIr,
  type ShellRedirectIr,
} from './ir.js';

const SHELL_PARSER_VERSION = 'tree-sitter-bash@0.25.1';

export interface InternalShellEvaluatorOptions {
  readonly assetResolver?: PolicyAssetResolver;
  readonly embeddedEvaluators: EmbeddedEvaluatorLoaders;
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

function redirectEffect(redirect: ShellRedirectIr): AnalyzedEffect {
  if (redirect.harmless) {
    return {
      effectCode: 'shell.process.redirect',
      action: 'allow',
      reasonCode: 'shell.read_only',
      kind: 'path',
      summary: 'A file descriptor redirect has only process-local effects.',
    };
  }
  if (redirect.direction === 'input') {
    if (!redirect.target) {
      return {
        effectCode: 'shell.filesystem.unknown_read',
        action: 'review',
        reasonCode: 'shell.unknown_semantics',
        kind: 'path',
        summary: 'An input redirect target is not statically established.',
      };
    }
    if (isSensitivePath(redirect.target)) {
      return {
        effectCode: 'shell.filesystem.sensitive_read',
        action: 'review',
        reasonCode: 'shell.sensitive_read',
        kind: 'path',
        summary: 'An input redirect may read a sensitive filesystem resource.',
      };
    }
    return {
      effectCode: 'shell.filesystem.read',
      action: 'allow',
      reasonCode: 'shell.read_only',
      kind: 'path',
      summary: 'An input redirect reads an ordinary filesystem resource.',
    };
  }
  if (
    redirect.direction === 'output' ||
    redirect.direction === 'read-write'
  ) {
    return {
      effectCode: 'shell.filesystem.write',
      action: 'review',
      reasonCode: 'shell.write',
      kind: 'path',
      summary: 'An output redirect may modify a filesystem resource.',
    };
  }
  return {
    effectCode: 'shell.redirect.unknown',
    action: 'review',
    reasonCode: 'shell.unknown_semantics',
    kind: 'path',
    summary: 'Redirect semantics are not statically established.',
  };
}

function unsupportedEffect(): AnalyzedEffect {
  return {
    effectCode: 'shell.syntax.unsupported',
    action: 'review',
    reasonCode: 'shell.unknown_semantics',
    kind: 'statement',
    summary: 'The script contains unsupported shell syntax.',
  };
}

function nestedFailureEffect(): AnalyzedEffect {
  return {
    effectCode: 'shell.nested.unknown',
    action: 'review',
    reasonCode: 'shell.unknown_semantics',
    kind: 'statement',
    summary: 'A nested shell payload could not be completely analyzed.',
  };
}

/**
 * Rebases effects onto an IR node's location. Effects produced for nested
 * payloads carry payload-relative locations, so the enclosing node's location
 * always wins; effects stay untouched when the node location is unknown.
 */
function withLocation(
  effects: readonly AnalyzedEffect[],
  location: SourceLocation | undefined,
): readonly AnalyzedEffect[] {
  return location
    ? effects.map((effect) => ({ ...effect, location }))
    : effects;
}

export function createDeterministicShellEvaluator(
  options: InternalShellEvaluatorOptions,
): PolicyEvaluator {
  const limits = resolvePolicyLimits(options.limits);
  let parserPromise: Promise<TreeSitterParserHandle> | undefined;

  const getParser = () => {
    parserPromise ??= createTreeSitterParser(
      'tree-sitter-bash',
      options.assetResolver,
    );
    return parserPromise;
  };

  return {
    async evaluate(input: PolicyEvaluationInput) {
      const sourceText =
        typeof input.sourceText === 'string' ? input.sourceText : '';
      if (sourceText.trim().length === 0) {
        return createFailClosedDecision({
          domain: 'shell',
          failure: 'parse-failed',
          input,
        });
      }
      if (inputExceedsLimit(sourceText, limits)) {
        return createFailClosedDecision({
          domain: 'shell',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      let parser: TreeSitterParserHandle;
      try {
        parser = await getParser();
      } catch {
        return createFailClosedDecision({
          domain: 'shell',
          failure: 'initialization-failed',
          input,
        });
      }

      let parsed;
      try {
        parsed = parseShellIr(parser, sourceText, limits);
      } catch {
        return createFailClosedDecision({
          domain: 'shell',
          failure: 'parse-failed',
          input,
        });
      }
      if (!parsed.ok) {
        return createFailClosedDecision({
          domain: 'shell',
          failure: parsed.failure,
          input,
        });
      }

      const effectsForIr = async (
        ir: ShellIr,
        nestingDepth: number,
      ): Promise<readonly AnalyzedEffect[]> => {
        const effects: AnalyzedEffect[] = [];
        const analyzeNestedShell = async (
          nestedSourceText: string,
        ): Promise<readonly AnalyzedEffect[]> => {
          if (
            nestingDepth >= limits.maxNestingDepth ||
            inputExceedsLimit(nestedSourceText, limits)
          ) {
            return [nestedFailureEffect()];
          }
          const nested = parseShellIr(parser, nestedSourceText, limits);
          return nested.ok
            ? await effectsForIr(nested.ir, nestingDepth + 1)
            : [nestedFailureEffect()];
        };

        for (const command of ir.commands) {
          const name = normalizeExecutable(command.name);
          const embedded = embeddedDomainForExecutable(name)
            ? await analyzeEmbeddedCommand(
                command,
                options.embeddedEvaluators,
                name,
              )
            : undefined;
          const commandEffects =
            embedded ??
            (await analyzeShellCommand(
              command,
              {
                analyzeNestedShell,
                analyzeEmbedded: (nestedCommand) =>
                  analyzeEmbeddedCommand(
                    nestedCommand,
                    options.embeddedEvaluators,
                  ),
              },
              0,
              name,
            ));
          effects.push(...withLocation(commandEffects, command.location));
        }
        for (const redirect of ir.redirects) {
          effects.push(
            ...withLocation([redirectEffect(redirect)], redirect.location),
          );
        }
        if (ir.unsupported) {
          effects.push(unsupportedEffect());
        }
        if (ir.background) {
          effects.push({
            effectCode: 'shell.process.detached',
            action: 'review',
            reasonCode: 'shell.background_execution',
            kind: 'statement',
            summary: 'The script may start detached background execution.',
          });
        }
        return effects;
      };

      const effects = await effectsForIr(parsed.ir, 0);

      return createAnalyzedDecision(
        'shell',
        input,
        SHELL_PARSER_VERSION,
        effects,
      );
    },
  };
}
