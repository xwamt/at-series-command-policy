# Deterministic Policy Analyzers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fail-closed evaluator scaffolds with bounded deterministic Shell, Python, SQLite, MySQL, and Redis analyzers while preserving the Task 1 public package boundaries.

**Architecture:** Private parser adapters convert complete source into bounded internal syntax/effect representations. Domain-specific contracts classify every reachable effect and shared decision builders aggregate `deny > review > allow` with controlled redacted evidence. Tree-sitter runtime and grammar WASM files are copied from an explicit manifest and can be supplied through a public resolver.

**Tech Stack:** TypeScript, Node 18, `web-tree-sitter` 0.26.13, VS Code Tree-sitter WASM 0.3.1, `node-sql-parser` 5.4.0, Node test runner, esbuild.

---

### Task 1: Shared analyzer runtime

**Files:**
- Create: `src/internal/analysis/decision.ts`
- Create: `src/internal/analysis/limits.ts`
- Create: `src/internal/analysis/sensitivity.ts`
- Test: `test/analyzers/shared.test.ts`

- [ ] **Step 1: Write failing decision and limit tests**

```ts
assert.equal(makeDecision('shell', effects).action, 'deny');
assert.equal(checkInputLimit('x'.repeat(9), { maxInputBytes: 8 }).ok, false);
```

- [ ] **Step 2: Run the focused test and record RED**

Run: `node --import tsx --test test/analyzers/shared.test.ts`
Expected: FAIL because the analysis runtime does not exist.

- [ ] **Step 3: Implement immutable decision construction, UTF-16 locations, sensitivity checks, and deterministic work limits**

- [ ] **Step 4: Run the focused test and record GREEN**

Run: `node --import tsx --test test/analyzers/shared.test.ts`
Expected: PASS.

### Task 2: Published parser assets

**Files:**
- Modify: `src/build.ts`
- Modify: `scripts/build.mjs`
- Modify: `test/contracts/build-api.test.ts`
- Modify: `test/package/tarball-manifest.test.mjs`
- Create: `test/build/assets.test.mjs`

- [ ] **Step 1: Write failing manifest, resolver, and copy tests**

```ts
assert.deepEqual(POLICY_ASSET_MANIFEST.map((asset) => asset.id), [
  'tree-sitter-runtime',
  'tree-sitter-bash',
  'tree-sitter-python',
]);
```

- [ ] **Step 2: Run the build contract tests and record RED**

Run: `node --import tsx --test test/contracts/build-api.test.ts`
Expected: FAIL because the manifest is empty.

- [ ] **Step 3: Add the explicit manifest and copy only the three production WASM files**

- [ ] **Step 4: Build and run the asset tests for GREEN**

Run: `npm run build && node --test test/build/assets.test.mjs`
Expected: PASS.

### Task 3: Tree-sitter Shell parser and policy IR

**Files:**
- Create: `src/internal/tree-sitter/runtime.ts`
- Create: `src/internal/shell/ir.ts`
- Create: `src/internal/shell/parser.ts`
- Create: `src/internal/shell/evaluator.ts`
- Modify: `src/shell.ts`
- Test: `test/analyzers/shell-structure.test.ts`

- [ ] **Step 1: Write focused multiline, list, pipeline, branch, loop, substitution, redirect, and parse-failure tests**

```ts
assert.equal(await action('# Purpose: inspect\nps aux | head'), 'allow');
assert.equal(await action('true && rm /tmp/x'), 'review');
assert.equal(await action('cat /etc/hosts > /tmp/out'), 'review');
```

- [ ] **Step 2: Run the focused test and record RED**

Run: `node --import tsx --test test/analyzers/shell-structure.test.ts`
Expected: FAIL because the bootstrap evaluator reviews ordinary reads.

- [ ] **Step 3: Parse the complete script, reject error/missing/unsupported nodes, produce private IR, and aggregate all reachable effects**

- [ ] **Step 4: Run the focused test and record GREEN**

Run: `node --import tsx --test test/analyzers/shell-structure.test.ts`
Expected: PASS.

### Task 4: Shell command contracts

**Files:**
- Create: `src/internal/shell/contracts.ts`
- Create: `src/internal/shell/wrappers.ts`
- Modify: `src/internal/shell/evaluator.ts`
- Test: `test/analyzers/shell-contracts.test.ts`

- [ ] **Step 1: Write paired read/mutation tests for observers, transforms, wrappers, services, containers, network tools, curl, Python, SQLite, MySQL, and Redis clients**

```ts
assert.equal(await action('systemctl status app'), 'allow');
assert.equal(await action('systemctl restart app'), 'review');
assert.equal(await action('curl -I https://example.invalid/health'), 'allow');
assert.equal(await action('curl -d x https://example.invalid/'), 'review');
```

- [ ] **Step 2: Run the focused test and record RED**

Run: `node --import tsx --test test/analyzers/shell-contracts.test.ts`
Expected: FAIL on the read contracts.

- [ ] **Step 3: Implement strict command-specific option parsing and recursively analyze static wrapper payloads**

- [ ] **Step 4: Run the focused test and record GREEN**

Run: `node --import tsx --test test/analyzers/shell-contracts.test.ts`
Expected: PASS.

### Task 5: Strict static Python analyzer

**Files:**
- Create: `src/internal/python/evaluator.ts`
- Modify: `src/python.ts`
- Test: `test/analyzers/python.test.ts`

- [ ] **Step 1: Write failing tests for pure expressions, approved imports/read APIs, writes, dynamic code, unknown imports/calls, and resource limits**

```ts
assert.equal(await action('import json; print(json.loads("{\\"x\\":1}"))'), 'allow');
assert.equal(await action('open("/tmp/x", "w").write("x")'), 'review');
assert.equal(await action('eval("1 + 1")'), 'review');
```

- [ ] **Step 2: Run and record RED**

Run: `node --import tsx --test test/analyzers/python.test.ts`
Expected: FAIL because all Python source reviews.

- [ ] **Step 3: Traverse the Tree-sitter Python AST and permit only an explicit pure/read subset**

- [ ] **Step 4: Run and record GREEN**

Run: `node --import tsx --test test/analyzers/python.test.ts`
Expected: PASS.

### Task 6: SQLite and MySQL analyzers

**Files:**
- Create: `src/internal/sql/evaluator.ts`
- Modify: `src/sqlite.ts`
- Modify: `src/mysql.ts`
- Test: `test/analyzers/sql.test.ts`

- [ ] **Step 1: Write failing tests for all-statement parsing, SELECT/CTE/SHOW/EXPLAIN, writes/control, sensitive columns/resources, unknown functions, and malformed SQL**

```ts
assert.equal(await sqliteAction('SELECT id, name FROM users'), 'allow');
assert.equal(await sqliteAction('SELECT password_hash FROM users'), 'review');
assert.equal(await mysqlAction('SHOW STATUS'), 'allow');
assert.equal(await mysqlAction('SELECT * FROM t FOR UPDATE'), 'review');
```

- [ ] **Step 2: Run and record RED**

Run: `node --import tsx --test test/analyzers/sql.test.ts`
Expected: FAIL because all SQL source reviews.

- [ ] **Step 3: Use dialect-specific AST parsers and recursively validate statement/expression/function effects**

- [ ] **Step 4: Run and record GREEN**

Run: `node --import tsx --test test/analyzers/sql.test.ts`
Expected: PASS.

### Task 7: Redis analyzer

**Files:**
- Create: `src/internal/redis/evaluator.ts`
- Modify: `src/redis.ts`
- Test: `test/analyzers/redis.test.ts`

- [ ] **Step 1: Write failing tests for inline and RESP shapes, reads, writes/control, blocking operations, malformed frames, and limits**

```ts
assert.equal(await action('GET cache:key'), 'allow');
assert.equal(await action('SET cache:key value'), 'review');
assert.equal(await action('BLPOP queue 0'), 'deny');
```

- [ ] **Step 2: Run and record RED**

Run: `node --import tsx --test test/analyzers/redis.test.ts`
Expected: FAIL because all Redis source reviews.

- [ ] **Step 3: Implement strict protocol parsing and versioned read/write/control/blocking command tables**

- [ ] **Step 4: Run and record GREEN**

Run: `node --import tsx --test test/analyzers/redis.test.ts`
Expected: PASS.

### Task 8: Redacted replay, adversarial, and fuzz suites

**Files:**
- Create: `test/fixtures/remote-command-replay.json`
- Create: `test/replay/remote-command-replay.test.ts`
- Create: `test/adversarial/policy-adversarial.test.ts`
- Create: `test/fuzz/deterministic-policy-fuzz.test.ts`

- [ ] **Step 1: Generate and manually audit 86 stable sanitized command-shape cases with no private identifiers, paths, addresses, outputs, or raw values**

- [ ] **Step 2: Write acceptance assertions for zero unsafe auto-allows and at most 10% ordinary-query reviews**

- [ ] **Step 3: Run and record RED for uncovered command shapes**

Run: `node --import tsx --test test/replay/*.test.ts test/adversarial/*.test.ts test/fuzz/*.test.ts`
Expected: FAIL with specific missing contracts.

- [ ] **Step 4: Add only the contracts needed for the reviewed fixture and adversarial cases**

- [ ] **Step 5: Run and record GREEN**

Run: `node --import tsx --test test/replay/*.test.ts test/adversarial/*.test.ts test/fuzz/*.test.ts`
Expected: PASS with no safety violations.

### Task 9: Packaging, notices, and final verification

**Files:**
- Modify: `NOTICE`
- Modify: `README.md`
- Modify: `package.json`
- Modify: `package-lock.json`

- [ ] **Step 1: Add accurate MIT/Apache-2.0 notices and document resolver/assets/limits**

- [ ] **Step 2: Run fresh complete verification**

Run: `npm run verify`
Expected: PASS.

- [ ] **Step 3: Run focused suites, audit, pack inspection, and size measurement**

Run: `npm run test:replay && npm run test:adversarial && npm run test:fuzz && npm audit && npm pack --dry-run --json`
Expected: PASS, zero safety violations, zero audit vulnerabilities, and only allowlisted production artifacts.

- [ ] **Step 4: Self-review every requirement and report any unimplemented scope directly**
