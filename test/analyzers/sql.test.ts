import assert from 'node:assert/strict';
import test from 'node:test';

import { createMysqlPolicyEvaluator } from '../../src/mysql.ts';
import { createSqlitePolicyEvaluator } from '../../src/sqlite.ts';

const sqlite = createSqlitePolicyEvaluator();
const mysql = createMysqlPolicyEvaluator();

async function sqliteAction(sourceText: string) {
  return (await sqlite.evaluate({ sourceText })).action;
}

async function mysqlAction(sourceText: string) {
  return (await mysql.evaluate({ sourceText })).action;
}

test('SQLite allows complete ordinary read-only statement sets', async () => {
  const sources = [
    'SELECT id, name FROM users',
    'SELECT count(*), max(created_at) FROM events',
    'WITH recent AS (SELECT id FROM events) SELECT id FROM recent',
    'EXPLAIN QUERY PLAN SELECT id FROM users',
    'PRAGMA table_info(users)',
    'SELECT id FROM users; SELECT name FROM groups;',
  ];
  for (const source of sources) {
    assert.equal(await sqliteAction(source), 'allow', source);
  }
});

test('SQLite reviews writes, controls, sensitive reads, and unknown functions', async () => {
  const sources = [
    'UPDATE users SET name = "changed" WHERE id = 1',
    'INSERT INTO users(id) VALUES (1)',
    'DELETE FROM users',
    'CREATE TABLE generated(id INTEGER)',
    'DROP TABLE users',
    "ATTACH DATABASE '/tmp/other.db' AS other",
    'PRAGMA journal_mode = WAL',
    'PRAGMA foreign_keys = ON',
    'SELECT password_hash FROM users',
    'SELECT id, name FROM api_key',
    'SELECT * FROM credentials',
    'SELECT dangerous_udf(id) FROM users',
    "SELECT load_extension('/tmp/extension')",
  ];
  for (const source of sources) {
    assert.equal(await sqliteAction(source), 'review', source);
  }
});

test('MySQL allows ordinary read and metadata statements', async () => {
  const sources = [
    'SELECT id, name FROM users',
    'WITH recent AS (SELECT id FROM events) SELECT id FROM recent',
    'SHOW STATUS',
    'SHOW TABLES',
    'DESCRIBE users',
    'EXPLAIN SELECT id FROM users',
  ];
  for (const source of sources) {
    assert.equal(await mysqlAction(source), 'allow', source);
  }
});

test('MySQL reviews writes, controls, locks, sensitive reads, and unknown functions', async () => {
  const sources = [
    'UPDATE users SET name = "changed" WHERE id = 1',
    'INSERT INTO users(id) VALUES (1)',
    'DELETE FROM users',
    'CREATE TABLE generated(id INT)',
    'DROP TABLE users',
    'SET GLOBAL max_connections = 100',
    'USE application',
    'START TRANSACTION',
    'SELECT id FROM users FOR UPDATE',
    "SELECT id INTO OUTFILE '/tmp/export' FROM users",
    'SELECT api_token FROM users',
    'SELECT * FROM credentials',
    'SELECT unknown_function(id) FROM users',
    'LOAD DATA INFILE "/tmp/data" INTO TABLE users',
  ];
  for (const source of sources) {
    assert.equal(await mysqlAction(source), 'review', source);
  }
});

test('MySQL reviews reads against restricted system schemas and secret columns', async () => {
  const sources = [
    'SELECT * FROM mysql.user',
    'SELECT Host, User, authentication_string FROM mysql.user',
    'SELECT * FROM users UNION SELECT * FROM mysql.user',
    'SELECT grantee FROM information_schema.user_privileges',
    'SELECT * FROM performance_schema.threads',
  ];
  for (const source of sources) {
    assert.equal(await mysqlAction(source), 'review', source);
  }
});

test('MySQL still allows ordinary reads and metadata with schema checks in place', async () => {
  const sources = ['SELECT id, name FROM users', 'SHOW STATUS', 'DESCRIBE users'];
  for (const source of sources) {
    assert.equal(await mysqlAction(source), 'allow', source);
  }
});

test('SQLite table sensitivity behavior is unchanged by schema qualification', async () => {
  assert.equal(await sqliteAction('SELECT id, name FROM users'), 'allow');
  assert.equal(await sqliteAction('SELECT * FROM credentials'), 'review');
});

test('SQL parse failures and statement limits fail closed', async () => {
  for (const evaluator of [sqlite, mysql]) {
    const malformed = await evaluator.evaluate({ sourceText: 'SELECT FROM' });
    assert.equal(malformed.action, 'review');
    assert.equal(malformed.reasonCode, 'policy.parse_failed');
  }

  const limited = createSqlitePolicyEvaluator({
    limits: { maxStatements: 1 },
  });
  const exhausted = await limited.evaluate({
    sourceText: 'SELECT 1; SELECT 2;',
  });
  assert.equal(exhausted.action, 'review');
  assert.equal(exhausted.reasonCode, 'policy.resource_limit_exceeded');
});
