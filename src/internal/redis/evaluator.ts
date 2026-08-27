import type {
  PolicyAnalysisLimits,
  PolicyEvaluationInput,
  PolicyEvaluator,
} from '../../index.js';
import {
  createAnalyzedDecision,
  type AnalyzedEffect,
} from '../analysis/decision.js';
import {
  inputExceedsLimit,
  resolvePolicyLimits,
} from '../analysis/limits.js';
import { createFailClosedDecision } from '../fail-closed.js';

const REDIS_RULE_VERSION = 'redis-command-table@1';

const readCommands = new Set([
  'BITCOUNT',
  'BITFIELD_RO',
  'BITPOS',
  'DBSIZE',
  'DUMP',
  'ECHO',
  'EXISTS',
  'GEODIST',
  'GEOHASH',
  'GEOPOS',
  'GEORADIUS_RO',
  'GEORADIUSBYMEMBER_RO',
  'GEOSEARCH',
  'GET',
  'GETBIT',
  'GETRANGE',
  'HELLO',
  'HEXISTS',
  'HGET',
  'HGETALL',
  'HKEYS',
  'HLEN',
  'HMGET',
  'HRANDFIELD',
  'HSCAN',
  'HSTRLEN',
  'HVALS',
  'INFO',
  'LASTSAVE',
  'LINDEX',
  'LLEN',
  'LOLWUT',
  'LPOS',
  'LRANGE',
  'MEMORY',
  'MGET',
  'OBJECT',
  'PFCOUNT',
  'PING',
  'PTTL',
  'RANDOMKEY',
  'SCAN',
  'SCARD',
  'SDIFF',
  'SINTER',
  'SINTERCARD',
  'SISMEMBER',
  'SMEMBERS',
  'SMISMEMBER',
  'SORT_RO',
  'SRANDMEMBER',
  'SSCAN',
  'STRLEN',
  'SUNION',
  'TIME',
  'TTL',
  'TYPE',
  'XINFO',
  'XLEN',
  'XPENDING',
  'XRANGE',
  'XREVRANGE',
  'ZCARD',
  'ZCOUNT',
  'ZDIFF',
  'ZINTER',
  'ZINTERCARD',
  'ZLEXCOUNT',
  'ZMSCORE',
  'ZRANDMEMBER',
  'ZRANGE',
  'ZRANGEBYLEX',
  'ZRANGEBYSCORE',
  'ZRANK',
  'ZREVRANGE',
  'ZREVRANGEBYLEX',
  'ZREVRANGEBYSCORE',
  'ZREVRANK',
  'ZSCAN',
  'ZSCORE',
  'ZUNION',
]);

const blockingCommands = new Set([
  'BLMOVE',
  'BLMPOP',
  'BLPOP',
  'BRPOP',
  'BRPOPLPUSH',
  'BZMPOP',
  'BZPOPMAX',
  'BZPOPMIN',
  'KEYS',
  'MONITOR',
  'PSUBSCRIBE',
  'SSUBSCRIBE',
  'SUBSCRIBE',
  'WAIT',
  'WAITAOF',
]);

const writeOrControlCommands = new Set([
  'ACL',
  'APPEND',
  'AUTH',
  'BGREWRITEAOF',
  'BGSAVE',
  'BITFIELD',
  'BITOP',
  'CLIENT',
  'CLUSTER',
  'CONFIG',
  'COPY',
  'DECR',
  'DECRBY',
  'DEL',
  'DISCARD',
  'EVAL',
  'EVALSHA',
  'EXEC',
  'EXPIRE',
  'EXPIREAT',
  'FLUSHALL',
  'FLUSHDB',
  'FUNCTION',
  'GETDEL',
  'GETEX',
  'GETSET',
  'HDEL',
  'HINCRBY',
  'HINCRBYFLOAT',
  'HMSET',
  'HSET',
  'HSETNX',
  'INCR',
  'INCRBY',
  'INCRBYFLOAT',
  'LINSERT',
  'LMOVE',
  'LPOP',
  'LPUSH',
  'LPUSHX',
  'LREM',
  'LSET',
  'LTRIM',
  'MIGRATE',
  'MODULE',
  'MOVE',
  'MSET',
  'MSETNX',
  'MULTI',
  'PERSIST',
  'PEXPIRE',
  'PEXPIREAT',
  'PFADD',
  'PFMERGE',
  'PUBLISH',
  'RENAME',
  'RENAMENX',
  'RESTORE',
  'RPOP',
  'RPOPLPUSH',
  'RPUSH',
  'RPUSHX',
  'SADD',
  'SAVE',
  'SCRIPT',
  'SDIFFSTORE',
  'SET',
  'SETBIT',
  'SETEX',
  'SETNX',
  'SETRANGE',
  'SHUTDOWN',
  'SINTERSTORE',
  'SLAVEOF',
  'SLOWLOG',
  'SMOVE',
  'SPOP',
  'SREM',
  'SUNIONSTORE',
  'SWAPDB',
  'TOUCH',
  'UNLINK',
  'WATCH',
  'XACK',
  'XADD',
  'XAUTOCLAIM',
  'XCLAIM',
  'XDEL',
  'XGROUP',
  'XSETID',
  'XTRIM',
  'ZADD',
  'ZDIFFSTORE',
  'ZINCRBY',
  'ZINTERSTORE',
  'ZPOPMAX',
  'ZPOPMIN',
  'ZREM',
  'ZREMRANGEBYLEX',
  'ZREMRANGEBYRANK',
  'ZREMRANGEBYSCORE',
  'ZUNIONSTORE',
]);

export interface InternalRedisEvaluatorOptions {
  readonly limits?: Partial<PolicyAnalysisLimits>;
}

type ParseResult =
  | { readonly ok: true; readonly arguments: readonly string[] }
  | { readonly ok: false; readonly risky: boolean };

function parseInline(sourceText: string): ParseResult {
  if (/[\0\r\n]/.test(sourceText)) {
    return { ok: false, risky: true };
  }
  const arguments_: string[] = [];
  let current = '';
  let quote: "'" | '"' | undefined;
  let tokenStarted = false;

  for (let index = 0; index < sourceText.length; index += 1) {
    const character = sourceText[index]!;
    if (!quote && /\s/.test(character)) {
      if (tokenStarted) {
        arguments_.push(current);
        current = '';
        tokenStarted = false;
      }
      continue;
    }
    if (character === quote) {
      quote = undefined;
      tokenStarted = true;
      continue;
    }
    if (!quote && (character === "'" || character === '"')) {
      quote = character;
      tokenStarted = true;
      continue;
    }
    if (character === '\\' && quote !== "'") {
      index += 1;
      const escaped = sourceText[index];
      if (escaped === undefined) {
        return { ok: false, risky: true };
      }
      current += escaped;
      tokenStarted = true;
      continue;
    }
    current += character;
    tokenStarted = true;
  }

  if (quote) {
    return { ok: false, risky: true };
  }
  if (tokenStarted) {
    arguments_.push(current);
  }
  return arguments_.length > 0
    ? { ok: true, arguments: arguments_ }
    : { ok: false, risky: false };
}

function readRespLine(
  bytes: Uint8Array,
  offset: number,
): { readonly line: string; readonly next: number } | undefined {
  for (let index = offset; index + 1 < bytes.length; index += 1) {
    if (bytes[index] === 13 && bytes[index + 1] === 10) {
      const line = new TextDecoder('utf-8', { fatal: true }).decode(
        bytes.subarray(offset, index),
      );
      return { line, next: index + 2 };
    }
  }
  return undefined;
}

function parseResp(sourceText: string, limits: PolicyAnalysisLimits): ParseResult {
  try {
    const bytes = new TextEncoder().encode(sourceText);
    const first = readRespLine(bytes, 0);
    if (!first || !first.line.startsWith('*')) {
      return { ok: false, risky: true };
    }
    const countText = first.line.slice(1);
    if (!/^[1-9]\d*$/.test(countText)) {
      return { ok: false, risky: true };
    }
    const count = Number(countText);
    if (count > limits.maxAstNodes) {
      return { ok: false, risky: false };
    }

    const values: string[] = [];
    let offset = first.next;
    const decoder = new TextDecoder('utf-8', { fatal: true });
    for (let index = 0; index < count; index += 1) {
      const header = readRespLine(bytes, offset);
      if (!header || !/^\$\d+$/.test(header.line)) {
        return { ok: false, risky: true };
      }
      const length = Number(header.line.slice(1));
      const end = header.next + length;
      if (
        !Number.isSafeInteger(length) ||
        length < 0 ||
        end + 2 > bytes.length ||
        bytes[end] !== 13 ||
        bytes[end + 1] !== 10
      ) {
        return { ok: false, risky: true };
      }
      values.push(decoder.decode(bytes.subarray(header.next, end)));
      offset = end + 2;
    }
    return offset === bytes.length
      ? { ok: true, arguments: values }
      : { ok: false, risky: true };
  } catch {
    return { ok: false, risky: true };
  }
}

function parseCommand(
  sourceText: string,
  limits: PolicyAnalysisLimits,
): ParseResult {
  return sourceText.startsWith('*')
    ? parseResp(sourceText, limits)
    : parseInline(sourceText);
}

function effect(
  action: 'allow' | 'review' | 'deny',
  category: string,
  summary: string,
): AnalyzedEffect {
  return {
    effectCode: `redis.command.${category}`,
    action,
    reasonCode: `redis.${category}`,
    kind: 'command',
    summary,
  };
}

function hasSensitiveKey(args: readonly string[]): boolean {
  return args.some((argument) =>
    /(?:^|[:._-])(?:auth|credential|password|private[_-]?key|secret|session[:._-]token|token)(?:$|[:._-])/i.test(
      argument,
    ),
  );
}

function classify(arguments_: readonly string[]): AnalyzedEffect {
  const command = arguments_[0]?.toUpperCase();
  const args = arguments_.slice(1);
  if (!command) {
    return effect('deny', 'unsupported_protocol', 'Redis protocol shape is unsupported.');
  }
  if (
    blockingCommands.has(command) ||
    ((command === 'XREAD' || command === 'XREADGROUP') &&
      args.some((argument) => argument.toUpperCase() === 'BLOCK'))
  ) {
    return effect(
      'deny',
      'blocking',
      'A Redis command may block the bounded execution channel.',
    );
  }
  if (writeOrControlCommands.has(command)) {
    return effect(
      'review',
      'write',
      'A Redis command may modify data or control the server.',
    );
  }
  if (!readCommands.has(command)) {
    return effect(
      'review',
      'unknown',
      'Redis command semantics are not in the reviewed command table.',
    );
  }
  if (hasSensitiveKey(args)) {
    return effect(
      'review',
      'sensitive_read',
      'A Redis command may read a sensitive key.',
    );
  }
  return effect(
    'allow',
    'read',
    'A recognized Redis command has a non-blocking read-only contract.',
  );
}

export function createDeterministicRedisEvaluator(
  options: InternalRedisEvaluatorOptions = {},
): PolicyEvaluator {
  const limits = resolvePolicyLimits(options.limits);

  return {
    async evaluate(input: PolicyEvaluationInput) {
      const sourceText =
        typeof input.sourceText === 'string' ? input.sourceText : '';
      if (sourceText.trim().length === 0) {
        return createFailClosedDecision({
          domain: 'redis',
          failure: 'parse-failed',
          input,
        });
      }
      if (inputExceedsLimit(sourceText, limits)) {
        return createFailClosedDecision({
          domain: 'redis',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      const parsed = parseCommand(sourceText, limits);
      if (!parsed.ok) {
        if (parsed.risky) {
          return createAnalyzedDecision(
            'redis',
            input,
            REDIS_RULE_VERSION,
            [
              effect(
                'deny',
                'unsupported_protocol',
                'Redis protocol shape is malformed or unsupported.',
              ),
            ],
          );
        }
        return createFailClosedDecision({
          domain: 'redis',
          failure: 'resource-limit-exceeded',
          input,
        });
      }

      return createAnalyzedDecision(
        'redis',
        input,
        REDIS_RULE_VERSION,
        [classify(parsed.arguments)],
      );
    },
  };
}
