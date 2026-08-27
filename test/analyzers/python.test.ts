import assert from 'node:assert/strict';
import test from 'node:test';

import { createPythonPolicyEvaluator } from '../../src/python.ts';

const evaluator = createPythonPolicyEvaluator();

async function action(sourceText: string) {
  return (await evaluator.evaluate({ sourceText })).action;
}

test('allows a strict pure Python expression and control-flow subset', async () => {
  const sources = [
    'print(1 + 2)',
    'values = [1, 2, 3]\nprint(sum(values))',
    'for value in range(3):\n    print(value)',
    'if len("value") > 2:\n    print("long")\nelse:\n    print("short")',
    'import json\nprint(json.loads(\'{"value": 1}\')["value"])',
    'from math import sqrt\nprint(sqrt(9))',
  ];
  for (const source of sources) {
    assert.equal(await action(source), 'allow', source);
  }
});

test('allows explicit ordinary file reads and reviews sensitive reads or writes', async () => {
  const cases = [
    ['print(open("/etc/hosts", "r").read())', 'allow'],
    ['print(open("/var/log/app.log").readline())', 'allow'],
    ['from pathlib import Path\nprint(Path("/etc/hosts").read_text())', 'allow'],
    ['print(open("/etc/shadow").read())', 'review'],
    ['print(open(path).read())', 'review'],
    ['open("/tmp/generated", "w").write("value")', 'review'],
    ['from pathlib import Path\nPath("/tmp/generated").write_text("value")', 'review'],
  ] as const;
  for (const [source, expected] of cases) {
    assert.equal(await action(source), expected, source);
  }
});

test('reviews reads of sensitive /proc entries', async () => {
  const sources = [
    'print(open("/proc/self/environ").read())',
    'print(open("/proc/1/environ").read())',
  ];
  for (const source of sources) {
    assert.equal(await action(source), 'review', source);
  }
});

test('analyzes static sqlite3 read scripts instead of rejecting the import', async () => {
  const sources = [
    [
      'import sqlite3',
      "conn = sqlite3.connect('/tmp/application.db')",
      'c = conn.cursor()',
      "print(c.execute('SELECT id, name FROM users').fetchall())",
    ].join('\n'),
    [
      'import sqlite3',
      "conn = sqlite3.connect('/tmp/application.db')",
      'c = conn.cursor()',
      "tables = [row[0] for row in c.execute(\"SELECT name FROM sqlite_master WHERE type='table';\").fetchall()]",
      "print('Tables:', [t for t in tables if any(k in t for k in ['key', 'token'])])",
    ].join('\n'),
  ];
  for (const source of sources) {
    assert.equal(await action(source), 'allow', source);
  }
});

test('reviews sqlite3 writes, sensitive data, and dynamic SQL', async () => {
  const sources = [
    [
      'import sqlite3',
      "conn = sqlite3.connect('/tmp/application.db')",
      "conn.execute(\"UPDATE users SET name = 'changed'\").fetchall()",
      'conn.commit()',
    ].join('\n'),
    [
      'import sqlite3',
      "conn = sqlite3.connect('/etc/shadow')",
      "print(conn.execute('SELECT 1').fetchall())",
    ].join('\n'),
    [
      'import sqlite3',
      "conn = sqlite3.connect('/tmp/application.db')",
      "print(conn.execute('SELECT password_hash FROM users').fetchall())",
    ].join('\n'),
    [
      'import sqlite3',
      "conn = sqlite3.connect('/tmp/application.db')",
      'table = "users"',
      'print(conn.execute(f"SELECT * FROM {table}").fetchall())',
    ].join('\n'),
  ];
  for (const source of sources) {
    assert.equal(await action(source), 'review', source);
  }
});

test('reviews unknown imports, calls, reflection, and dynamic code', async () => {
  const sources = [
    'import requests\nrequests.get("https://example.invalid")',
    'import os\nos.remove("/tmp/generated")',
    'unknown_call()',
    'eval("1 + 1")',
    'exec("print(1)")',
    '__import__("json")',
    'getattr(object(), "value")',
    'compile("1 + 1", "<string>", "eval")',
  ];
  for (const source of sources) {
    assert.equal(await action(source), 'review', source);
  }
});

test('Python parse failures and deterministic limits fail closed', async () => {
  const malformed = await evaluator.evaluate({ sourceText: 'if True print(1)' });
  assert.equal(malformed.action, 'review');
  assert.equal(malformed.reasonCode, 'policy.parse_failed');

  const limited = createPythonPolicyEvaluator({
    limits: { maxInputBytes: 8 },
  });
  const exhausted = await limited.evaluate({ sourceText: 'print("long")' });
  assert.equal(exhausted.action, 'review');
  assert.equal(exhausted.reasonCode, 'policy.resource_limit_exceeded');
});

test('a failing parser asset resolver reviews instead of allowing', async () => {
  const unavailable = createPythonPolicyEvaluator({
    assetResolver() {
      throw new Error('controlled test failure');
    },
  });
  const decision = await unavailable.evaluate({ sourceText: 'print(1)' });
  assert.equal(decision.action, 'review');
  assert.equal(decision.reasonCode, 'policy.initialization_failed');
  assert.equal(JSON.stringify(decision).includes('controlled test failure'), false);
});
