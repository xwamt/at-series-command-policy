import assert from 'node:assert/strict';
import test from 'node:test';

import { createRedisPolicyEvaluator } from '../../src/redis.ts';

const evaluator = createRedisPolicyEvaluator();

async function action(sourceText: string) {
  return (await evaluator.evaluate({ sourceText })).action;
}

test('allows recognized non-blocking read-only Redis commands', async () => {
  const commands = [
    'GET cache:item',
    'MGET cache:one cache:two',
    'EXISTS cache:item',
    'TTL cache:item',
    'TYPE cache:item',
    'HGET profile:1 name',
    'HGETALL profile:1',
    'LRANGE queue:recent 0 9',
    'SMEMBERS tags:1',
    'ZRANGE scores 0 9 WITHSCORES',
    'SCAN 0 MATCH cache:* COUNT 10',
    'INFO server',
    'DBSIZE',
    'PING',
  ];
  for (const command of commands) {
    assert.equal(await action(command), 'allow', command);
  }
});

test('reviews Redis writes, controls, unknown commands, and sensitive key reads', async () => {
  const commands = [
    'SET cache:item value',
    'DEL cache:item',
    'HSET profile:1 name value',
    'LPUSH queue value',
    'EXPIRE cache:item 30',
    'PUBLISH channel value',
    'CONFIG SET maxmemory 1gb',
    'FLUSHALL',
    'SCRIPT LOAD "return 1"',
    'EVAL "return 1" 0',
    'CUSTOM.READ cache:item',
    'GET session:token',
  ];
  for (const command of commands) {
    assert.equal(await action(command), 'review', command);
  }
});

test('denies known blocking commands and risky protocol shapes', async () => {
  const commands = [
    'BLPOP queue 0',
    'BRPOP queue 5',
    'XREAD BLOCK 0 STREAMS events $',
    'SUBSCRIBE channel',
    'PSUBSCRIBE pattern:*',
    'MONITOR',
    'KEYS *',
    '*2\r\n$3\r\nGET\r\n$5\r\nshort',
    '*1\r\n*-1\r\n',
  ];
  for (const command of commands) {
    assert.equal(await action(command), 'deny', command);
  }
});

test('accepts an exact RESP array of bulk strings', async () => {
  assert.equal(
    await action('*2\r\n$3\r\nGET\r\n$10\r\ncache:item\r\n'),
    'allow',
  );
  assert.equal(
    await action('*3\r\n$3\r\nSET\r\n$10\r\ncache:item\r\n$5\r\nvalue\r\n'),
    'review',
  );
});

test('Redis parse failures and deterministic limits fail closed', async () => {
  const empty = await evaluator.evaluate({ sourceText: '' });
  assert.equal(empty.action, 'review');
  assert.equal(empty.reasonCode, 'policy.parse_failed');

  const limited = createRedisPolicyEvaluator({
    limits: { maxInputBytes: 8 },
  });
  const exhausted = await limited.evaluate({ sourceText: 'GET cache:item' });
  assert.equal(exhausted.action, 'review');
  assert.equal(exhausted.reasonCode, 'policy.resource_limit_exceeded');
});
