# Plugin Size and Matching Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 **不改变任何策略决策效果** 的前提下，把 `@at-series/command-policy` 在插件（AT Terminal MCP limited-trust）内的体积与匹配延迟压下来，并顺手修掉体积分析过程中发现的一个 MySQL 可执行注释 false-allow 漏洞。

**Architecture:** 决策管线保持不变：`sourceText → parser → 私有 IR/AST → contracts → createAnalyzedDecision（deny > review > allow，redacted evidence）`。本计划只动四层外围：esbuild 产物形态（minify、共享 runtime chunk）、进程级缓存（`Language.load`）、热路径微优化（limits 快路径、embedded 同步门闩、懒算 fallback location、常量提升）、以及构建期资产过滤（可选 wasm 子集）。唯一的语义改动是 Task 4 的 MySQL 可执行注释 fail-closed 预扫描，方向只会更严，不会更松。

**Tech Stack:** TypeScript, Node 18（`target: 'node18'`）, esbuild 0.28, `web-tree-sitter` 0.26.13, `@vscode/tree-sitter-wasm` 0.3.1, `node-sql-parser` 5.4.0, `sqlite3-parser` 0.7.1, Node test runner (`node --import tsx --test`)。

---

## 0. 给 agent 的工作方式

- [ ] 在当前分支 `cursor/policy-accuracy-p0-p2-2c34` 之上按 Task 顺序工作（或按第 7 节的 PR 切分另开 `cursor/*` 分支）。**不要切到 main。**
- 每个 Task 一个独立 commit（英文祈使句 message），先写失败测试（Step 1/2），再实现（Step 3），再 GREEN（Step 4），最后跑该 Task 的不变量回归命令。commit 后立即 push。
- 每个 Task 至少要跑：`node --import tsx --test test/analyzers/accuracy-matrix.test.ts`（false-allow 必须为 0）+ 该 Task 声明的 analyzer 回归。收尾整体跑 `npm run verify`。
- 性能类 Task（3/7/8/9/10）里的微秒数字 **不是契约**。实现前先在当前机器复测基线（见第 2 节的复测方法），比较相对变化，不要把本文档里的绝对数写进断言。
- 任何时候不允许为体积或速度增加 false-allow：拿不准的改动一律回退到 review（fail-closed）。禁止合并 Task 4（准确率 P0）和高风险项（Task 9）到同一个 commit/PR。
- 本文档引用的行号以 commit `24816da` 为准，实现时以符号名（函数/常量名）为定位依据，不要盲信行号。

## 1. Goal / 非目标 / 不变量

### Goal

1. 发布产物 JS 体积显著下降（预期 raw JS 约 −47%，unpacked 约 −1.1MB）。
2. 单 CJS 再打包（插件场景）后仍然：`python3 -c` 可被嵌入分析（不静默 review）、执行级懒加载可用、wasm 可由 `assetResolver` 提供。
3. 第二个及以后的 evaluator 不再重复付 `Language.load`（~6ms）；`python -c` 冷路径不再第二次 `Parser.init`。
4. 修复 `SELECT 1 /*! , authentication_string FROM mysql.user */` 被 allow 的准确率漏洞（已现场复现：当前返回 `allow` / `mysql.read_only`）。

### 非目标

- 不替换 tree-sitter-bash / tree-sitter-python（正则方案禁止）。
- 不替换 `node-sql-parser`（见第 5 节 Epic-later）。
- 不默认移除嵌入语言分析，不默认减少打包的 wasm 数量。
- 不做 wasm-opt / 重编译官方 `@vscode/tree-sitter-wasm`（ABI 风险）。
- 不删除 CJS 子路径（Node 18 不能 `require` ESM；最多文档标注 deprecated，下个 major 处理）。

### 效果不变量（每个 Task 的验收底线）

以下断言在本计划全部 Task 完成前后必须完全一致：

1. 聚合规则 `deny > review > allow` 不变；`combinePolicyDecisions` 只会更严。
2. 所有 evidence `redacted: true`，`summary` 是受控静态文案，`sourceText` / `cwd` 永不进入决策 JSON（`test/contracts/domain-api.test.ts` 已断言）。
3. fail-closed 路径与 reasonCode 不变：缺 wasm → `policy.initialization_failed`；解析失败 → `policy.parse_failed`；超限 → `policy.resource_limit_exceeded`（且仍发生在 parse 之前）；未知语义 → `policy.unknown_semantics`。
4. 决策向量抽查（minify、chunk、缓存改动后用 dist 复查）：
   - `uptime` → allow；且不触发 `tree-sitter-python` / mysql JS 的加载。
   - `rm -rf /tmp/x` → review。
   - `python3 -c "print(1)"` → allow；`python3 --version` → allow（落到 shell contracts）。
   - `mysql -e "SELECT id FROM users"` → allow；`SELECT * FROM mysql.user` → review。
5. `test/analyzers/accuracy-matrix.test.ts` 的 confusion matrix false-allow == 0。
6. `test/package/size-budget.test.mjs`：packed ≤ 2.5MB 且恰好 3 个 wasm（Task 11 不改默认值）。

## 2. 现状实测基线（2026-08-27 本机实测，实现时必须复测）

> 下列数字是 2026-08-27 在本仓库开发机上的实测，**只用于排优先级和估收益**。实现时请在当前机器复测（体积用 `npm run build && npm pack --dry-run && du -b dist/*.js dist/*.cjs dist/assets/*`；延迟用临时 benchmark 脚本跑 dist 产物，勿提交）。微秒级数字不要写成测试契约。

### 体积

| 项 | 实测值 | 备注 |
| --- | --- | --- |
| `npm pack` | 765,459 B packed / unpacked ~4.44MB | size-budget 上限 2.5MB packed、恰好 3 个 wasm |
| `tree-sitter-bash.wasm` | 1,380,769 B | 不可压（非目标） |
| `tree-sitter-python.wasm` | 457,883 B | Task 11 可选不拷贝 |
| `web-tree-sitter.wasm` | 201,535 B | runtime |
| `dist/mysql.js` | ~512KB | `node-sql-parser` ~449KB + `big-integer` ~48KB；上游已 minify，被 esbuild pretty-print 膨胀 ~170KB |
| `dist/sqlite.js` | ~245KB | `sqlite3-parser` |
| `dist/shell.js` | ~214KB | 内含 web-tree-sitter Emscripten glue ~153KB |
| `dist/python.js` | ~179KB | **又一份** 同样的 glue（Task 5 目标） |
| `dist/redis.js` | ~15KB | |
| ESM+CJS 双发 | JS 体积 ×2 | 构建 **未 minify**（Task 1 目标） |
| 消费者单 CJS 再打包 shell | ~1.29MB | 懒加载的字节边界塌陷，但仍是执行级懒加载；若不 `define` `import.meta.url`，`python3 -c` **静默全 review**（Task 6 目标） |

### 性能（tsx 跑源码，Node 22）

| 项 | 实测值 | 备注 |
| --- | --- | --- |
| `createShellPolicyEvaluator()` | 0.012ms | 纯闭包构造 |
| 首次 `evaluate('uptime')` | ~18–20ms | `Parser.init` ~5.5–8.5ms + `Language.load`(bash) ~3.8–4.5ms |
| 热路径 `uptime` | p50 ~17µs | |
| 中等脚本 | ~168µs | IR 遍历线性放大 |
| 第二个 evaluator | 再付 ~6ms | `Language.load` **无进程级缓存**（Task 2 目标） |
| `python3 -c` 冷路径 | 6–34ms | 动态 `import('./python.js')` + **第二次 `Parser.init`**（glue 在 dist 里有两份单例，Task 5 目标） |
| sqlite 生产 dist 导入 | ~15ms | tsx 下会虚高到 ~280ms，测量必须用 dist |
| 70KiB 超限输入 | ~311µs | 主因 `TextEncoder` 全量编码（Task 3）+ `wholeSourceLocation` 全源扫描（超限路径的 location 语义上必须覆盖全源，保留） |
| 每命令 `await analyzeEmbeddedCommand` | 每条命令一次 promise 往返 | Task 7 目标 |
| 同一 evaluator 并发 | 0 竞态 | `reset+parse+遍历+delete` 是同步原子块，Task 9 必须保持 |

## 3. 已落地的准确率工作（只读上下文，不要重复实现）

以下 P0–P2 已在本分支落地并有测试覆盖。列出来只是让你不要重做、不要在本计划中回退它们。

- **P0-1 cut/jq/tr/uniq/wc 走 classifyPaths**：文件读取型 transform 命令的操作数按路径分类（普通读 allow / 敏感读 review / 不可静态确定 review）。关键文件 `src/internal/shell/contracts.ts`（`classifyPaths`、`command-table.ts` 的 `operandsAreFiles`）；测试 `test/analyzers/shell-contracts.test.ts`。
- **P0-2 敏感路径 segment 级 + /proc**：`src/internal/analysis/sensitivity.ts` 的 `isSensitivePath` 按 path segment 匹配 `.ssh`/`.aws`/`credentials` 等，并覆盖 `/proc/self|<pid>/environ|cmdline|maps|mem`；测试 `test/analyzers/sensitivity.test.ts`。
- **P0-3 awk/sed 硬化**：`contracts.ts` 的 `analyzeSed`（`safeSedShortFlags`、脚本体检查）与 `analyzeAwk`（program 里出现写/系统调用即 review）；测试 `test/analyzers/shell-contracts.test.ts`。
- **P0-4 MySQL/SQLite schema 限定读**：`src/internal/sql/common.ts` 的 `isRestrictedSchema`/`isSensitiveTableRef`，`SELECT * FROM mysql.user` 这类跨 schema 读 review；测试 `test/analyzers/sql.test.ts`。
- **P1-1 command-table.ts**：`src/internal/shell/command-table.ts` 表驱动 contracts（`processLocal`/`hostObserver`/`fileReader` 家族），`contracts.ts` 消费 `commandContracts`。
- **P1-2 accuracy-regression 语料 + 混淆矩阵**：`test/fixtures/accuracy-regression.json`（当前 43 条，id 连续 `acc-001`…`acc-043`）+ `test/analyzers/accuracy-matrix.test.ts`（**false-allow==0 硬断言**、语料 redaction 检查）。
- **P1-3 POLICY_RULE_VERSIONS 按域**：`src/core/version.ts` 的 `POLICY_RULE_VERSIONS` 按 domain 独立版本（当前 core/shell/sqlite/mysql/redis 均 `0.1.1`，python `0.1.0`）。注意 `test/contracts/root-api.test.ts` 钉死了这些值。
- **P2-1 证据 location**：`src/internal/shell/ir.ts` 的 `nodeLocation` + `evaluator.ts` 的 `withLocation`，review 证据落在肇事命令节点上；测试 `test/analyzers/evidence-location.test.ts`。
- **P2-2 wrappers/fileReader/apt、redis SORT_RO/HELLO/LOLWUT、python --version fall-through**：`embedded.ts` 的 `versionOrHelpOnly` 让 `python3 --version` 落回 shell contracts；redis 只读表补齐；测试 `test/analyzers/shell-contracts.test.ts`、`test/analyzers/redis.test.ts`。

关键路径速查：`src/internal/shell/contracts.ts`、`src/internal/shell/command-table.ts`、`src/internal/shell/embedded.ts`、`src/internal/analysis/sensitivity.ts`、`src/internal/sql/*`、`src/core/version.ts`、`test/analyzers/accuracy-matrix.test.ts`。

---

## 4. Tasks

### Task 1: esbuild minify（零语义风险，最大体积收益）

**前置依赖:** 无。建议第一个做，后续所有体积对比都以 minify 后为基线。

**现状:** `scripts/build.mjs` 的 `sharedOptions` 没有 `minify`，esbuild 把上游已 minify 的 `node-sql-parser` pretty-print 回来反而膨胀 ~170KB。CJS 构建靠 `banner.js` 注入 `var __commandPolicyModuleUrl = require("node:url").pathToFileURL(__filename).href;` 并 `define` `'import.meta.url': '__commandPolicyModuleUrl'`——minify 不会重命名 define 引入的自由标识符，banner 原样输出，两者兼容。

**为什么改:** JS raw 预期 −47%、unpacked −1.1MB，无任何语义风险（esbuild minify 是语义保持变换；本包不依赖 `Function.prototype.name`）。

**Files:**
- Modify: `scripts/build.mjs`
- Test: `test/package/size-budget.test.mjs`（扩展；它跑在 `npm run test:package:runtime`，位于 `verify` 的 build 之后，dist 一定是新鲜的——不要把 dist 体积断言放进 `test/build/`，那个目录在 `verify` 里跑在 build **之前**）

- [ ] **Step 1: 在 size-budget 测试里加 raw dist 体积断言（先失败）**

打开 `test/package/size-budget.test.mjs`，新增一个 test，读 `dist/*.js` + `dist/*.cjs` 的字节数：

```js
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

const distDirectory = fileURLToPath(new URL('../../dist/', import.meta.url));

test('dist JavaScript stays within the minified raw-size budget', async () => {
  const entries = (await readdir(distDirectory)).filter(
    (name) => name.endsWith('.js') || name.endsWith('.cjs'),
  );
  let total = 0;
  const sizes = {};
  for (const name of entries) {
    const { size } = await stat(join(distDirectory, name));
    sizes[name] = size;
    total += size;
  }
  // 阈值 = minify 后实测 + ~20% 余量。下面两个数按 2026-08-27 基线预估，
  // 实现时用当场实测值替换（minify 前 mysql.js ~512KB、总量 ~2.3MB 应 RED）。
  assert.equal(sizes['mysql.js'] <= 460_000, true, `mysql.js ${sizes['mysql.js']}`);
  assert.equal(total <= 1_900_000, true, `dist JS total ${total}`);
});
```

- [ ] **Step 2: RED**

Run: `npm run build && node --test test/package/size-budget.test.mjs`
Expected: FAIL——未 minify 的 `dist/mysql.js` ~512KB 超过阈值，总量 ~2.3MB 超过阈值。

- [ ] **Step 3: 打开 `scripts/build.mjs`，在 `sharedOptions` 加 minify**

```js
const sharedOptions = {
  // ...现有字段不动...
  minify: true,
  legalComments: 'eof', // 已有，保留：第三方 license 注释必须留在文件尾
};
```

保守替代（若全量 minify 出现任何决策差异，先退到这一档再排查）：`minifyWhitespace: true, minifySyntax: true`（不开 `minifyIdentifiers`），或加 `keepNames: true`。CJS 构建的 `banner`/`define` 保持原样，不要动。

- [ ] **Step 4: GREEN**

Run: `npm run build && node --test test/package/size-budget.test.mjs`
Expected: PASS（packed ≤ 2.5MB 的既有断言也应继续 PASS，不需要放宽预算）。

- [ ] **Step 5: 决策等价抽查（dist 级，必须做）**

```sh
node --input-type=module -e '
const { createShellPolicyEvaluator } = await import("./dist/shell.js");
const e = createShellPolicyEvaluator();
const cases = [
  ["uptime", "allow"],
  ["rm -rf /tmp/x", "review"],
  ["python3 -c \"print(1)\"", "allow"],
  ["mysql -e \"SELECT id FROM users\"", "allow"],
  ["mysql -e \"SELECT * FROM mysql.user\"", "review"],
];
for (const [src, expected] of cases) {
  const d = await e.evaluate({ sourceText: src });
  if (d.action !== expected) { console.error("MISMATCH", src, d.action, "!=", expected); process.exit(1); }
}
console.log("dist spot-check ok");
'
```

- [ ] **Step 6: 不变量回归**

Run: `node --import tsx --test test/analyzers/accuracy-matrix.test.ts && npm run test:package:runtime`
Expected: PASS（`installed-tarball.test.mjs` 会从干净安装再跑一遍 ESM/CJS 消费者）。

**风险:** 极低。唯一已知坑：`define` 的 `__commandPolicyModuleUrl` 若被误开 `banner` 之外的 scope hoisting 影响——esbuild 不会，但 Step 5 的 `python3 -c` 抽查（走 CJS 时）就是为这个兜底。
**DoD:** 阈值测试 GREEN；`npm run verify` GREEN；packed/unpacked 体积记录进 commit message。

---

### Task 2: `Language.load` 进程级缓存 + 可选 `warmup()`

**前置依赖:** 无（与 Task 1 无冲突，但建议在其后做，保持构建改动集中）。

**现状:** `src/internal/tree-sitter/runtime.ts` 里 `runtimeInitialization`（`Parser.init`）已是模块级单例，但 `loadLanguage()` 每次调用都执行 `Language.load(source)`——第二个 evaluator 再付 ~4–6ms 且重复读 wasm。另外 `runtimeInitialization` 失败后是 sticky 的：进程内首个 evaluator 用坏 resolver 会永久毒化后续所有 evaluator。

**为什么改:** 插件里会创建多个 evaluator（不同 session）；缓存把第 2+ 个 evaluator 的冷成本从 ~6ms 降到 ~0。

**设计约束（必须遵守）:** `test/analyzers/python.test.ts` 的 `a failing parser asset resolver reviews instead of allowing` 钉死了「坏 resolver 必须 review」。因此语言缓存 **必须按 resolver 实例隔离**，不能只按 languageId 全局缓存（否则坏 resolver 会吃到别人缓存的 Language 而 allow）。

**Files:**
- Modify: `src/internal/tree-sitter/runtime.ts`
- Modify: `src/shell.ts`（新增 `warmupShellPolicyEvaluator` 导出）
- Modify: `test/package/exports.test.mjs`（`'/shell'` 的期望键新增 `'warmupShellPolicyEvaluator'`——该测试是 `deepEqual` 精确键集）
- Modify: `docs/api.md`（shell 模块表加一行 warmup 说明）
- Test: `test/analyzers/tree-sitter-cache.test.ts`（新建；node test runner 每个文件独立进程，模块级缓存状态天然隔离）

- [ ] **Step 1: 写失败测试**

```ts
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import type { PolicyAssetReference } from '../../src/index.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

const assetUrls: Record<PolicyAssetReference['id'], URL> = {
  'tree-sitter-runtime': new URL(
    '../../node_modules/web-tree-sitter/web-tree-sitter.wasm', import.meta.url),
  'tree-sitter-bash': new URL(
    '../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-bash.wasm', import.meta.url),
  'tree-sitter-python': new URL(
    '../../node_modules/@vscode/tree-sitter-wasm/wasm/tree-sitter-python.wasm', import.meta.url),
};

function countingResolver(calls: Map<string, number>) {
  return (asset: PolicyAssetReference) => {
    calls.set(asset.id, (calls.get(asset.id) ?? 0) + 1);
    return fileURLToPath(assetUrls[asset.id]);
  };
}

test('a second evaluator with the same resolver reuses the loaded bash language', async () => {
  const calls = new Map<string, number>();
  const resolver = countingResolver(calls);
  const first = createShellPolicyEvaluator({ assetResolver: resolver });
  const second = createShellPolicyEvaluator({ assetResolver: resolver });
  assert.equal((await first.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal((await second.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal(calls.get('tree-sitter-bash'), 1); // RED: 现状是 2
  assert.equal(calls.get('tree-sitter-runtime'), 1);
});

test('a failing resolver still fails closed after another resolver succeeded', async () => {
  const good = createShellPolicyEvaluator();
  assert.equal((await good.evaluate({ sourceText: 'uptime' })).action, 'allow');
  const bad = createShellPolicyEvaluator({
    assetResolver() { throw new Error('controlled test failure'); },
  });
  const decision = await bad.evaluate({ sourceText: 'uptime' });
  assert.equal(decision.action, 'review');
  assert.equal(decision.reasonCode, 'policy.initialization_failed');
});

test('warmup preloads runtime and bash so evaluate pays no cold cost', async () => {
  const calls = new Map<string, number>();
  const resolver = countingResolver(calls);
  const { warmupShellPolicyEvaluator } = await import('../../src/shell.ts');
  await warmupShellPolicyEvaluator({ assetResolver: resolver });
  const evaluator = createShellPolicyEvaluator({ assetResolver: resolver });
  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal(calls.get('tree-sitter-bash'), 1);
  assert.equal(calls.get('tree-sitter-python') ?? 0, 0);
});
```

- [ ] **Step 2: RED**

Run: `node --import tsx --test test/analyzers/tree-sitter-cache.test.ts`
Expected: FAIL——第一个测试 `tree-sitter-bash` 计数为 2；第三个测试 `warmupShellPolicyEvaluator` 不存在（import 报错）。第二个测试现状 PASS（它是防止实现错缓存键的守卫）。

- [ ] **Step 3: 实现**

打开 `src/internal/tree-sitter/runtime.ts`：

1. 在 `loadLanguage` 上方加按 resolver 隔离的缓存：

```ts
type LanguageId = 'tree-sitter-bash' | 'tree-sitter-python';

const defaultLanguageCache = new Map<LanguageId, Promise<Language>>();
const resolverLanguageCaches = new WeakMap<
  PolicyAssetResolver,
  Map<LanguageId, Promise<Language>>
>();

function languageCacheFor(
  resolver: PolicyAssetResolver | undefined,
): Map<LanguageId, Promise<Language>> {
  if (!resolver) {
    return defaultLanguageCache;
  }
  let cache = resolverLanguageCaches.get(resolver);
  if (!cache) {
    cache = new Map();
    resolverLanguageCaches.set(resolver, cache);
  }
  return cache;
}

async function loadLanguage(
  id: LanguageId,
  resolver: PolicyAssetResolver | undefined,
): Promise<Language> {
  const cache = languageCacheFor(resolver);
  let pending = cache.get(id);
  if (!pending) {
    pending = (async () => {
      await initializeRuntime(resolver);
      const source = sourceForLoader(
        await (resolver ?? defaultResolveAsset)(assetById[id]),
      );
      return Language.load(source);
    })();
    cache.set(id, pending);
    // 失败不缓存：既避免毒化同 resolver 的后续调用，也保住 fail-closed 重试。
    pending.catch(() => cache.delete(id));
  }
  return pending;
}
```

2. `initializeRuntime` 同样在失败时清空 `runtimeInitialization`（`runtimeInitialization.catch(() => { runtimeInitialization = undefined; })` 挂在赋值后），消除「首个坏 resolver 毒化整个进程」。成功语义保持 first-wins 不变（`Parser.init` 是 Emscripten 全局，本来只能 init 一次）。

3. 打开 `src/shell.ts`，新增导出：

```ts
import { createTreeSitterParser } from './internal/tree-sitter/runtime.js';

/**
 * Optionally pre-initializes the tree-sitter runtime and bash grammar so the
 * first evaluate() call pays no cold-start cost. Failures reject here, but
 * evaluators stay independent and still fail closed to review on evaluate().
 */
export async function warmupShellPolicyEvaluator(
  options: Pick<ShellPolicyEvaluatorOptions, 'assetResolver'> = {},
): Promise<void> {
  const handle = await createTreeSitterParser(
    'tree-sitter-bash',
    options.assetResolver,
  );
  handle.dispose();
}
```

4. （可选子步骤）`src/internal/shell/evaluator.ts` 的 `createDeterministicShellEvaluator` 里，在定义 `getParser` 后 fire-and-forget：`void getParser().catch(() => {});`。收益是不调用 warmup 的消费者也能隐藏冷启动；代价是 `createShellPolicyEvaluator()` 从纯构造变成会触发 IO。**默认不做**，若做必须 `.catch` 吞掉避免 unhandledRejection——evaluate 会 await 同一个（可能已 rejected 的）`parserPromise`，fail-closed 不受影响，但要注意 rejected 的 `parserPromise` 是 evaluator 级 sticky（现状已如此，不新增问题）。

- [ ] **Step 4: GREEN**

Run: `node --import tsx --test test/analyzers/tree-sitter-cache.test.ts`
Expected: PASS（3 个测试全绿）。

- [ ] **Step 5: 更新 exports 测试与文档**

`test/package/exports.test.mjs` 中 `'@at-series/command-policy/shell'` 的期望数组改为 `['createShellPolicyEvaluator', 'warmupShellPolicyEvaluator']`；`docs/api.md` 补一行。然后：

Run: `npm run build && npm run test:package:runtime`
Expected: PASS。

- [ ] **Step 6: 不变量回归**

Run: `node --import tsx --test test/analyzers/accuracy-matrix.test.ts test/analyzers/shell-structure.test.ts test/analyzers/python.test.ts test/internal/fail-closed.test.ts`
Expected: PASS——特别是 `python.test.ts` 的 failing-resolver 用例（按 resolver 隔离缓存的守卫）。

**效果不变量:** 缺 wasm / 坏 resolver 仍 `policy.initialization_failed` review；同一 resolver 的缓存命中不改变任何决策字段。
**风险:** 缓存键设计错误（按 id 全局共享）会让坏 resolver 吃到别人的 Language 变 allow——Step 1 第二个测试就是防这个。WeakMap 键是 resolver 函数实例：消费者若每次 new 闭包则不命中，属可接受的保守行为。
**DoD:** 3 个新测试 + exports 测试 GREEN；`npm run verify` GREEN。

---

### Task 3: `inputExceedsLimit` 快路径

**前置依赖:** 无。

**现状:** `src/internal/analysis/limits.ts` 的 `inputExceedsLimit` 每次调用 `new TextEncoder().encode(sourceText)`——70KiB 超限输入 ~311µs 的主因；而且 shell 的嵌套分析（`evaluator.ts` 的 `analyzeNestedShell`）对每个嵌套 payload 都会再调它。

**为什么改:** 一个 UTF-16 code unit 至多编码为 3 字节 UTF-8（surrogate pair 2 个 code unit → 4 字节 ≤ 2×3），所以 `sourceText.length * 3 <= maxInputBytes` 时必然不超限，无需编码。边界情况用 `Buffer.byteLength`（Node 平台，比 TextEncoder 快且零分配）。

**Files:**
- Modify: `src/internal/analysis/limits.ts`
- Test: `test/internal/limits.test.ts`（新建）

- [ ] **Step 1: 写特征化测试（本 Task 是纯性能重构，行为不变，测试的作用是钉死语义防回归）**

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  inputExceedsLimit,
  resolvePolicyLimits,
} from '../../src/internal/analysis/limits.ts';

const limits8 = resolvePolicyLimits({ maxInputBytes: 8 });

test('inputExceedsLimit matches exact UTF-8 byte semantics', () => {
  assert.equal(inputExceedsLimit('', limits8), false);
  assert.equal(inputExceedsLimit('a'.repeat(8), limits8), false); // 恰好边界
  assert.equal(inputExceedsLimit('a'.repeat(9), limits8), true);
  assert.equal(inputExceedsLimit('€€', limits8), false); // 6 字节，length*3=6 走快路径
  assert.equal(inputExceedsLimit('€€€', limits8), true); // 9 字节，length*3=9>8 走精确路径
  assert.equal(inputExceedsLimit('😀😀', limits8), false); // 8 字节，length=4 走精确路径
  assert.equal(inputExceedsLimit('😀😀a', limits8), true); // 9 字节
});
```

- [ ] **Step 2: RED 命令（预期直接 PASS）**

Run: `node --import tsx --test test/internal/limits.test.ts`
Expected: **PASS**——本 Task 无法产生行为级 RED（纯性能重构），这是有意的偏差，记录在 commit message 里。可选的本地证据（勿提交为测试）：`node --import tsx -e` 里对 60KiB ASCII 跑 1 万次前后对比耗时。

- [ ] **Step 3: 实现**

打开 `src/internal/analysis/limits.ts`，替换 `inputExceedsLimit`：

```ts
export function inputExceedsLimit(
  sourceText: string,
  limits: PolicyAnalysisLimits,
): boolean {
  // A UTF-16 code unit encodes to at most 3 UTF-8 bytes, so short inputs
  // can never exceed the byte limit without exact encoding.
  if (sourceText.length * 3 <= limits.maxInputBytes) {
    return false;
  }
  return Buffer.byteLength(sourceText, 'utf8') > limits.maxInputBytes;
}
```

不要动任何调用点：超限检查必须保持在 parse 之前（shell/python/sqlite/mysql 的 evaluate 顺序都是 空串→超限→parse）。

- [ ] **Step 4: GREEN**

Run: `node --import tsx --test test/internal/limits.test.ts`
Expected: PASS。

- [ ] **Step 5: 不变量回归**

Run: `node --import tsx --test test/analyzers/accuracy-matrix.test.ts test/analyzers/shell-structure.test.ts test/analyzers/python.test.ts test/analyzers/sql.test.ts test/internal/fail-closed.test.ts`
Expected: PASS（`python.test.ts` 里 `maxInputBytes: 8` 的超限用例覆盖了小 limit 场景）。

**效果不变量:** 超限判定与 `new TextEncoder().encode(x).byteLength > max` 完全等价；超限仍 fail-closed `policy.resource_limit_exceeded`。
**风险:** 快路径系数写错（如用 4 而不是 3 不会错但少省；用 2 会 false-negative 漏掉超限）——Step 1 的 `€€€` 用例覆盖 3 字节字符恰在快路径边界外。
**DoD:** 新测试 GREEN；相关 analyzer 回归 GREEN。

---

### Task 4: MySQL 可执行注释 fail-closed（准确率 P0，独立 commit）

**前置依赖:** 无。**不得与 Task 9 等高风险项合并。**

**现状:** `src/internal/sql/mysql-evaluator.ts` 的 `evaluate` 把 `sourceText` 交给 `node-sql-parser` 的 `astify`，而 node-sql-parser **丢弃 MySQL 可执行注释** `/*! ... */` 的内容。已现场复现：`SELECT 1 /*! , authentication_string FROM mysql.user */` 当前返回 `allow` / `mysql.read_only`，但 MySQL 服务器会执行注释内的 `, authentication_string FROM mysql.user`——这是 false-allow。

**为什么这样修:** 用源文本预扫描 `/\/\*!/` fail-closed 到 review。**不要**为此替换整个 parser（见 Epic-later）。可执行注释在运维 SQL 里罕见，review 的误伤率可接受。

**钉死的决策形态:** 命中预扫描 → `createAnalyzedDecision('mysql', input, MYSQL_PARSER_VERSION, [reviewEffect('mysql', 'unknown')])`，即 `action: 'review'`、**`reasonCode: 'mysql.unknown'`**、effectCode `mysql.database.unknown`（复用 `src/internal/sql/common.ts` 的 `reviewEffect`，不新造 reason）。不用 `parse-failed`：SQL 本身能 parse，语义是「注释内内容不可静态确定」。

**Files:**
- Modify: `src/internal/sql/mysql-evaluator.ts`
- Modify: `src/core/version.ts`（`POLICY_RULE_VERSIONS.mysql` `'0.1.1'` → `'0.1.2'`）
- Modify: `test/contracts/root-api.test.ts`（两处钉死 `mysql: '0.1.1'` 的字面量同步为 `'0.1.2'`）
- Modify: `test/fixtures/accuracy-regression.json`（追加 acc-044 / acc-045）
- Test: `test/analyzers/sql.test.ts`（新增用例）

- [ ] **Step 1: 写失败测试**

`test/analyzers/sql.test.ts` 新增：

```ts
test('mysql executable comments fail closed to review', async () => {
  const evaluator = createMysqlPolicyEvaluator();
  const smuggled = await evaluator.evaluate({
    sourceText: 'SELECT 1 /*! , authentication_string FROM mysql.user */',
  });
  assert.equal(smuggled.action, 'review');
  assert.equal(smuggled.reasonCode, 'mysql.unknown');

  const versioned = await evaluator.evaluate({
    sourceText: 'SELECT /*!40001 SQL_NO_CACHE */ id FROM users',
  });
  assert.equal(versioned.action, 'review');

  // 普通注释与普通读不受影响
  assert.equal(
    (await evaluator.evaluate({ sourceText: 'SELECT id FROM users /* plain */' })).action,
    'allow',
  );
  assert.equal(
    (await evaluator.evaluate({ sourceText: 'SELECT * FROM mysql.user' })).action,
    'review',
  );
});
```

`test/fixtures/accuracy-regression.json` 末尾追加（id 必须连续，当前最后一条是 `acc-043`）：

```json
{
  "id": "acc-044",
  "domain": "mysql",
  "family": "executable-comment",
  "sourceText": "SELECT 1 /*! , authentication_string FROM mysql.user */",
  "expectedAction": "review",
  "class": "false_allow_fix"
},
{
  "id": "acc-045",
  "domain": "shell",
  "family": "executable-comment",
  "sourceText": "mysql -e 'SELECT 1 /*! , authentication_string FROM mysql.user */'",
  "expectedAction": "review",
  "class": "false_allow_fix"
}
```

- [ ] **Step 2: RED**

Run: `node --import tsx --test test/analyzers/sql.test.ts test/analyzers/accuracy-matrix.test.ts`
Expected: FAIL——新用例 predicted `allow`，且混淆矩阵报出 2 条 false-allow。

- [ ] **Step 3: 实现**

打开 `src/internal/sql/mysql-evaluator.ts`：

1. 模块级常量：`const executableCommentPattern = /\/\*!/;`
2. 在 `createDeterministicMysqlEvaluator` 的 `evaluate` 里，空串检查与超限检查之后、`parser.astify` **之前** 插入：

```ts
if (executableCommentPattern.test(sourceText)) {
  // node-sql-parser drops MySQL executable comments (/*! ... */), so their
  // payload is invisible to AST analysis. Fail closed instead of allowing.
  return createAnalyzedDecision('mysql', input, MYSQL_PARSER_VERSION, [
    reviewEffect('mysql', 'unknown'),
  ]);
}
```

3. `src/core/version.ts`：`POLICY_RULE_VERSIONS` 的 `mysql: '0.1.1'` → `'0.1.2'`（规则表变更，按 P1-3 约定 bump）。同步改 `test/contracts/root-api.test.ts` 里两处 `mysql: '0.1.1'` 字面量（约在 107 行与 219 行附近）。

- [ ] **Step 4: GREEN**

Run: `node --import tsx --test test/analyzers/sql.test.ts test/analyzers/accuracy-matrix.test.ts test/contracts/root-api.test.ts`
Expected: PASS，混淆矩阵 false-allow==0。

- [ ] **Step 5: 不变量回归**

Run: `npm test`
Expected: PASS（全量，确认 shell 嵌入路径 `mysql -e ...` 也变 review 且无其它决策漂移）。

**效果不变量:** 只新增 review，无任何 allow→allow 之外的松动；`SELECT id FROM users` 家族仍 allow。
**风险:** 预扫描是文本级的，字符串字面量里出现 `/*!`（如 `SELECT '/*!'`）也会 review——方向是更严，可接受；在测试里加一条注释说明这是已知的保守误伤。
**DoD:** 语料 45 条全绿、false-allow==0、rule version bump 完成、`npm run verify` GREEN。

---

### Task 5: 共享 tree-sitter runtime chunk（去重 Emscripten glue）

**前置依赖:** Task 1（同文件 `scripts/build.mjs`，先后做避免冲突）、Task 2（缓存与 chunk 叠加后语义才完整）。

**现状:** `src/internal/tree-sitter/runtime.ts` 被 `src/internal/shell/evaluator.ts` 和 `src/internal/python/evaluator.ts` 静态 import（`src/internal/shell/ir.ts` 只有 `import type`，擦除后无运行时依赖）。esbuild 逐 entry 打包，把 web-tree-sitter 的 ~153KB glue **分别**内联进 `dist/shell.js` 和 `dist/python.js`——两份独立的模块单例导致 `python -c` 冷路径要付第二次 `Parser.init`（~6–34ms），且体积白多 ~150KB×2（ESM+CJS 共 ~300KB+）。

**为什么这样改:** 复用现有 `external: ['./mysql.js', ...]` 的兄弟文件模式：把 runtime 提成独立 entry `dist/tree-sitter-runtime.{js,cjs}`，其它 entry 对它 external。esbuild 的 `splitting: true` 只支持 ESM，CJS 构建必须用 external 子文件模式——两种格式统一用同一个 plugin 实现，不搞两套形态。**不加进 `package.json` 的 exports map**：包内相对导入不经过 exports map，保持公共 API 面不变；消费者打包时两个 entry 解析到同一文件，glue 自动去重。

**Files:**
- Modify: `scripts/build.mjs`
- Modify: `test/package/tarball-manifest.test.mjs`（expectedFiles 精确追加 `'dist/tree-sitter-runtime.js'` 与 `'dist/tree-sitter-runtime.cjs'`，无 `.d.ts`/`.d.cts`——它不是公共入口，`scripts/build-cjs-types.mjs` 的 `publicEntries` 不要加）
- Modify: `test/package/exports.test.mjs`（在 `internal modules are blocked` 测试里追加断言 `@at-series/command-policy/tree-sitter-runtime` 抛 `ERR_PACKAGE_PATH_NOT_EXPORTED`）
- Test: `test/package/runtime-chunk.test.mjs`（新建，dist 级）

- [ ] **Step 1: 写失败测试**

```js
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const assetsDirectory = new URL('../../dist/assets/', import.meta.url);

test('shell and python entries share one tree-sitter runtime instance', async () => {
  const { createShellPolicyEvaluator } = await import(
    new URL('../../dist/shell.js', import.meta.url).href
  );
  const calls = new Map();
  const resolver = (asset) => {
    calls.set(asset.id, (calls.get(asset.id) ?? 0) + 1);
    return fileURLToPath(new URL(asset.fileName, assetsDirectory));
  };
  const evaluator = createShellPolicyEvaluator({ assetResolver: resolver });

  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
  assert.equal(calls.get('tree-sitter-python') ?? 0, 0); // uptime 不得加载 python.wasm
  assert.equal(calls.get('tree-sitter-runtime'), 1);

  const embedded = await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' });
  assert.equal(embedded.action, 'allow');
  assert.equal(calls.get('tree-sitter-python'), 1);
  // RED: dist 里 glue 有两份单例时，python.js 会再次初始化 runtime → 计数为 2
  assert.equal(calls.get('tree-sitter-runtime'), 1);
});
```

- [ ] **Step 2: RED**

Run: `npm run build && node --test test/package/runtime-chunk.test.mjs`
Expected: FAIL——`tree-sitter-runtime` 被解析 2 次（python.js 的独立 glue 再次 `Parser.init`）。

- [ ] **Step 3: 实现**

打开 `scripts/build.mjs`：

1. `entryPoints` 增加：`'tree-sitter-runtime': 'src/internal/tree-sitter/runtime.ts'`。
2. 加 per-format plugin，把对 runtime 模块的相对导入改写为兄弟文件 external：

```js
function treeSitterRuntimeChunkPlugin(importPath) {
  return {
    name: 'tree-sitter-runtime-chunk',
    setup(build) {
      build.onResolve(
        { filter: /^\.\.?\/.*tree-sitter\/runtime\.js$/ },
        (args) =>
          args.kind === 'entry-point'
            ? null
            : { path: importPath, external: true },
      );
    },
  };
}
```

3. ESM 构建加 `plugins: [treeSitterRuntimeChunkPlugin('./tree-sitter-runtime.js')]`；CJS 构建加 `plugins: [treeSitterRuntimeChunkPlugin('./tree-sitter-runtime.cjs')]`。CJS 的 `banner`/`define` 会照常作用于 runtime chunk（它自身使用 `import.meta.url`），无需额外处理。
4. `runtime.ts` 对 `../../index.js` 的 import 全部是 `import type`，chunk 不会反向内联 index——实现后用 `node -e "require('./dist/tree-sitter-runtime.cjs')"` 冒烟确认无副作用报错。

- [ ] **Step 4: GREEN**

Run: `npm run build && node --test test/package/runtime-chunk.test.mjs`
Expected: PASS——`tree-sitter-runtime` 恰好 1 次，`uptime` 从不触发 `tree-sitter-python`。

- [ ] **Step 5: 更新打包契约测试**

`test/package/tarball-manifest.test.mjs` 的 `expectedFiles` 追加两个精确文件名（不要走 `publicEntries` 的 flatMap，因为没有类型文件）：

```js
'dist/tree-sitter-runtime.js',
'dist/tree-sitter-runtime.cjs',
```

`test/package/exports.test.mjs` 的 blocked 测试追加：

```js
await assert.rejects(import('@at-series/command-policy/tree-sitter-runtime'), {
  code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
});
```

Run: `npm run build && npm run test:package:runtime && npm run lint:package`
Expected: PASS（若 `publint --strict` 对无类型的内部 dist 文件报错——预期不会，因为 publint 只检查 exports map 引用的文件——则回退方案是把 `tree-sitter-runtime` 加入 `scripts/build-cjs-types.mjs` 的 `publicEntries` 生成 `.d.ts`/`.d.cts` 并相应更新 manifest 期望，但仍不加 exports map）。

- [ ] **Step 6: 不变量回归**

Run: `node --import tsx --test test/analyzers/accuracy-matrix.test.ts test/analyzers/shell-structure.test.ts test/analyzers/python.test.ts && npm run test:package:runtime`
Expected: PASS——`installed-tarball.test.mjs` 从干净安装验证 CJS `require('./tree-sitter-runtime.cjs')` 相对路径成立。注意 chunk 文件缺失的失败模式与缺 wasm 不同：它不是 `policy.initialization_failed`（那是资产解析失败），而是模块加载错误——`dist/shell.js` 对 chunk 是静态 import，文件缺失时 shell 入口本身加载失败。所以 tarball-manifest 测试必须精确断言这两个文件存在，这是打包完整性的守卫。

**效果不变量:** 决策向量抽查（Task 1 Step 5 的脚本）逐条一致；`uptime` 仍不加载 `tree-sitter-python.wasm`；惰性 `import('./python.js')` 仍只在嵌入命令出现时发生。
**风险:** plugin 的 filter 误匹配（比如未来有人加 `runtime.js` 同名文件）——filter 锚定 `tree-sitter/runtime.js` 结尾且排除 entry-point，风险低；CJS 消费者用旧 bundler 深引 dist 路径的行为不受影响（相对 require 不经过 exports）。
**DoD:** runtime-chunk 测试 GREEN；tarball-manifest / exports / publint GREEN；`dist/shell.js`+`dist/python.js` 合计比 Task 1 后再减 ~150KB（ESM，CJS 同理）；`npm run verify` GREEN。

---

### Task 6: README 插件打包配方

**前置依赖:** Task 5（配方要提到 runtime chunk 文件）、Task 2（提到 warmup）。

**现状:** `README.md` 的 "Bundled consumers (VS Code / Electron)" 一节只给了 `copyPolicyAssets` + 一句 "define `import.meta.url`" 的提示。实测：消费者单 CJS 再打包若不 define，`python3 -c` 会 **静默全 review**（`import.meta.url` 为空 → 嵌入 python evaluator 初始化失败 → fail-closed），没有任何报错，极难排查。

**为什么改:** 这是纯文档任务，把实测结论固化为可复制的配方与冒烟断言。

**Files:**
- Modify: `README.md`
- Modify: `docs/api.md`（如 warmup/assets 说明需要同步）

- [ ] **Step 1: 重写 "Bundled consumers" 一节，必须包含以下全部内容**

1. 完整 esbuild 参数（banner+define 是硬要求）：

```js
import { build } from 'esbuild';

await build({
  entryPoints: ['src/policy-runtime.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  outfile: 'dist/policy-runtime.js',
  banner: {
    js: 'var __policyModuleUrl = require("node:url").pathToFileURL(__filename).href;',
  },
  define: { 'import.meta.url': '__policyModuleUrl' },
});
```

并用醒目的告警块写明：**不 define `import.meta.url` 时没有构建错误，运行时 `python3 -c` 全部静默 review**（fail-closed 掩盖了配置错误）。

2. wasm 资产：构建脚本调用 `copyPolicyAssets({ destinationDirectory })`，运行时用 `assetResolver` 传绝对路径或 bytes（保留现有示例，补全 `assetDir` 的来历）。
3. 字节级懒加载的取舍：单文件 bundle 会把 `./python.js`/`./sqlite.js`/`./mysql.js`/`./redis.js`/`./tree-sitter-runtime.js` 全部内联（shell 单文件 ~1.29MB），但 **执行级懒加载仍然成立**（未命中嵌入命令不会执行那些模块的初始化代码）。想保住字节边界的两个选项：
   - external 五个子文件（`*/mysql.js`、`*/python.js`、`*/sqlite.js`、`*/redis.js`、`*/tree-sitter-runtime.js` 的通配 external），并把对应 `dist/*.cjs|js` 文件拷到 bundle 旁边；
   - 或消费者侧改用 ESM 输出 + `splitting: true`（esbuild 的 splitting 不支持 CJS）。
4. 可选 `warmupShellPolicyEvaluator()`：在扩展激活时预热，首次 evaluate 省 ~18–20ms。
5. 打包后冒烟断言（写进消费者 CI 的示例）：

```js
const evaluator = createShellPolicyEvaluator({ assetResolver });
assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
assert.equal(
  (await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' })).action,
  'allow', // 若 import.meta.url 没 define 好，这里会是 review
);
```

- [ ] **Step 2: 校对与回归**

Run: `npm run verify`
Expected: PASS（纯文档改动，verify 作为格式/构建无回归的确认）。

**DoD:** README 配方按上述 5 点齐全、代码块可直接粘贴运行；`docs/api.md` 与 README 无互相矛盾的说法。

---

### Task 7: embedded 同步门闩（去掉每命令的无谓 await）

**前置依赖:** 无硬依赖；建议排在 Task 5 之后，便于把性能收益归因区分开（chunk 去重的冷路径收益 vs 门闩的热路径收益）。

**现状:** `src/internal/shell/evaluator.ts` 的 `effectsForIr` 对 **每条** 命令执行 `const embedded = await analyzeEmbeddedCommand(command, options.embeddedEvaluators)`——即使命令显然不是 python/sqlite3/mysql/redis-cli，也要付一次 promise 往返；且 `analyzeEmbeddedCommand`（`embedded.ts`）和 `analyzeShellCommand`（`contracts.ts`）各自调一遍 `normalizeExecutable`。

**为什么改:** 热路径（`uptime`、`ps aux | head` 等）占比最高，同步门闩把「非嵌入命令」的成本降为一次 `normalizeExecutable` + 若干字符串比较，零 promise 分配。

**Files:**
- Modify: `src/internal/shell/embedded.ts`
- Modify: `src/internal/shell/evaluator.ts`
- Modify: `src/internal/shell/contracts.ts`（`analyzeShellCommand` 加可选 `normalizedName` 参数）
- Test: `test/analyzers/embedded-gate.test.ts`（新建）

- [ ] **Step 1: 写失败测试**

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import { embeddedDomainForExecutable } from '../../src/internal/shell/embedded.ts';
import { createShellPolicyEvaluator } from '../../src/shell.ts';

test('embedded domain gate matches exactly the four client executables', () => {
  assert.equal(embeddedDomainForExecutable('python3'), 'python');
  assert.equal(embeddedDomainForExecutable('python3.12'), 'python');
  assert.equal(embeddedDomainForExecutable('sqlite3'), 'sqlite');
  assert.equal(embeddedDomainForExecutable('mysql'), 'mysql');
  assert.equal(embeddedDomainForExecutable('redis-cli'), 'redis');
  assert.equal(embeddedDomainForExecutable('uptime'), undefined);
  assert.equal(embeddedDomainForExecutable('mysqldump'), undefined);
  assert.equal(embeddedDomainForExecutable(undefined), undefined);
});

test('gate does not change embedded and fall-through behavior', async () => {
  const evaluator = createShellPolicyEvaluator();
  const python = await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' });
  assert.equal(python.action, 'allow');
  assert.equal(
    python.effects.some((effect) => effect.effectCode === 'shell.embedded.python'),
    true,
  );
  assert.equal(
    (await evaluator.evaluate({ sourceText: 'python3 --version' })).action,
    'allow', // 仍落回 shell contracts（P2-2 行为）
  );
  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
});
```

- [ ] **Step 2: RED**

Run: `node --import tsx --test test/analyzers/embedded-gate.test.ts`
Expected: FAIL——`embeddedDomainForExecutable` 尚不存在（import 报错）。第二个测试是行为守卫，实现后必须保持 PASS。

- [ ] **Step 3: 实现**

1. 打开 `src/internal/shell/embedded.ts`，把 `analyzeEmbeddedCommand` 里的名字匹配逻辑抽成同步导出（正则提升为模块级常量）：

```ts
export type EmbeddedDomain = 'python' | 'sqlite' | 'mysql' | 'redis';

const pythonExecutablePattern = /^python3?(?:\.\d+)*$/;

export function embeddedDomainForExecutable(
  name: string | undefined,
): EmbeddedDomain | undefined {
  if (!name) return undefined;
  if (pythonExecutablePattern.test(name)) return 'python';
  if (name === 'sqlite3') return 'sqlite';
  if (name === 'mysql') return 'mysql';
  if (name === 'redis-cli') return 'redis';
  return undefined;
}
```

`analyzeEmbeddedCommand` 改签名为 `(command, loaders, normalizedName = normalizeExecutable(command.name))` 并内部改用 `embeddedDomainForExecutable(normalizedName)` 分派；`versionOrHelpOnly` 的 python fall-through 逻辑 **留在** `analyzePython` 入口前不动（门闩只看名字，不看参数）。

2. 打开 `src/internal/shell/evaluator.ts`，`effectsForIr` 的命令循环改为：

```ts
for (const command of ir.commands) {
  const name = normalizeExecutable(command.name);
  const embedded = embeddedDomainForExecutable(name)
    ? await analyzeEmbeddedCommand(command, options.embeddedEvaluators, name)
    : undefined;
  const commandEffects =
    embedded ??
    (await analyzeShellCommand(
      command,
      {
        analyzeNestedShell,
        analyzeEmbedded: (nestedCommand) =>
          analyzeEmbeddedCommand(nestedCommand, options.embeddedEvaluators),
      },
      0,
      name,
    ));
  effects.push(...withLocation(commandEffects, command.location));
}
```

（`normalizeExecutable` 从 `./contracts.js` import，evaluator 现在还没引它。）

3. 打开 `src/internal/shell/contracts.ts`，`analyzeShellCommand` 签名加第 4 个可选参数并用它替代内部第一行的重复计算：

```ts
export async function analyzeShellCommand(
  command: ShellCommandIr,
  hooks?: ShellContractHooks,
  wrapperDepth = 0,
  normalizedName = normalizeExecutable(command.name),
): Promise<readonly AnalyzedEffect[]> {
  const name = normalizedName;
  ...
```

wrapper 递归调用 `analyzeShellCommand(child, hooks, wrapperDepth + 1)` 不传第 4 参（child 自行计算），行为不变。contracts 内 `hooks.analyzeEmbedded?.(child)` 路径保持现状（wrapper 深路径本来就冷）。

- [ ] **Step 4: GREEN**

Run: `node --import tsx --test test/analyzers/embedded-gate.test.ts`
Expected: PASS。

- [ ] **Step 5: 不变量回归**

Run: `node --import tsx --test test/analyzers/shell-contracts.test.ts test/analyzers/shell-structure.test.ts test/analyzers/accuracy-matrix.test.ts test/analyzers/evidence-location.test.ts test/replay/remote-command-replay.test.ts`
Expected: PASS——`uptime` 热路径 effectCode 序列不变；`python3 -c` 仍产出 `shell.embedded.python`；wrapper 场景（`sudo python3 -c ...`）仍走 `hooks.analyzeEmbedded`。

**效果不变量:** 门闩只是「名字不匹配就不 await」；任何名字匹配的命令走的代码路径与现状完全一致（含 `--version` fall-through 返回 `undefined` 落回 contracts）。
**风险:** 门闩名字集合与 `analyzeEmbeddedCommand` 内部分派不同步会造成静默行为漂移——实现时让 `analyzeEmbeddedCommand` 内部 **复用** `embeddedDomainForExecutable`（单一事实源），而不是维护两份匹配。
**DoD:** 新测试 GREEN、全量 `npm test` GREEN。

---

### Task 8: `createAnalyzedDecision` 懒算 wholeSourceLocation

**前置依赖:** 无。

**现状:** `src/internal/analysis/decision.ts` 的 `createAnalyzedDecision` 无条件执行 `const fallbackLocation = wholeSourceLocation(sourceText)`——逐字符扫描全源统计行号。shell 域自 P2-1 起几乎所有 effect 都自带 `location`，这次扫描通常是纯浪费；大输入（接近 64KiB）时开销可观。注意：超限 fail-closed 路径走的是 `src/internal/redacted-evidence.ts` 的 `createFailureEvidence`，其 whole-source 扫描 **语义上必需**（证据必须覆盖全源），不在本 Task 范围；超限路径的提速来自 Task 3。

**Files:**
- Modify: `src/internal/analysis/decision.ts`
- Test: 复用 `test/analyzers/evidence-location.test.ts`、`test/contracts/domain-api.test.ts`、`test/internal/fail-closed.test.ts`（特征化，不新建文件）

- [ ] **Step 1: 确认既有测试钉死了 fallback 语义**

`test/contracts/domain-api.test.ts` 的 unknown-semantics 用例精确断言 `evidence[0].location` 等于全源 location（`{ start: {offset:0,line:1,column:1}, end: {...} }`）——懒算实现必须产出 **完全相同** 的值。先跑一遍确认基线：

Run: `node --import tsx --test test/contracts/domain-api.test.ts test/analyzers/evidence-location.test.ts`
Expected: PASS（基线）。

- [ ] **Step 2: RED 命令（预期直接 PASS）**

本 Task 与 Task 3 同理是纯性能重构，无行为级 RED，记录在 commit message。

- [ ] **Step 3: 实现**

打开 `src/internal/analysis/decision.ts`，把 `createAnalyzedDecision` 里的：

```ts
const fallbackLocation = wholeSourceLocation(sourceText);
const evidence: PolicyEvidence[] = effectsToUse.map((effect) =>
  Object.freeze({
    kind: effect.kind,
    location: effect.location ?? fallbackLocation,
    ...
```

改为惰性 memo：

```ts
let fallbackLocation: SourceLocation | undefined;
const fallback = () => (fallbackLocation ??= wholeSourceLocation(sourceText));
const evidence: PolicyEvidence[] = effectsToUse.map((effect) =>
  Object.freeze({
    kind: effect.kind,
    location: effect.location ?? fallback(),
    ...
```

`wholeSourceLocation` 本体与空 effects 时的 noop 分支都不要动。

- [ ] **Step 4: GREEN + 不变量回归**

Run: `node --import tsx --test test/contracts/domain-api.test.ts test/analyzers/evidence-location.test.ts test/internal/fail-closed.test.ts test/analyzers/accuracy-matrix.test.ts`
Expected: PASS——所有 fallback location 值 bit-for-bit 相同，只是没人用时不再计算。

**效果不变量:** 任何缺 `location` 的 effect 仍拿到与现状相同的全源 location；决策 JSON 逐字段一致。
**风险:** 几乎为零；唯一注意点是 memo 变量别放到函数外（跨调用共享会串 sourceText）。
**DoD:** 上述 4 个测试文件 GREEN。

---

### Task 9: IR TreeCursor 单遍遍历（P1，独立 PR，可丢弃）

**前置依赖:** Tasks 1–8 全部 GREEN 后再做。**这是纯性能项：若回归失败且不能快速定位，允许放弃本 Task 或拆成单独 PR 搁置，绝不为速度放松 fail-closed 或改变决策。**

**现状:** `src/internal/shell/ir.ts` 的 `parseShellIr` 用显式栈遍历，但每个节点都取 `node.children`（web-tree-sitter 每次调用都跨 wasm 边界物化一个 JS 数组）；`containsDynamicSyntax` 对每个 name/argument 节点又各自做一次 `namedChildren` 子遍历。IR 遍历成本随脚本大小线性放大（中等脚本 ~168µs 的主要成分）。

**关键语义约束（先读懂再动手）:**
1. 现有栈是 `pop()` 后把 children 正序 push——即 **每层按逆序访问**。`createAnalyzedDecision` 选 reasonCode 时取「第一个最严 effect」，effects 顺序由 commands 收集顺序决定，**改变遍历顺序会改变多 effect 脚本的 reasonCode 选择**。因此实现必须保持与现状完全相同的节点访问顺序：推荐只把「物化 `node.children` 数组」替换为「用 `TreeCursor` 枚举 children 后压入同一个栈」，算法结构一字不动。
2. `&`（background）检测、`unsupportedNodeTypes`、`command`/`file_redirect` 捕获都依赖 **匿名节点也被访问**——`TreeCursor.gotoFirstChild/gotoNextSibling` 会走匿名节点，`namedChildren` 不会，别搞混。
3. `maxAstNodes`/`maxWorkUnits`/`maxNestingDepth` 计数只许更严不许更松（同样的输入，新实现的计数值 ≥ 旧实现即可接受，< 则是漏数节点，必须修）。
4. **严禁在持有 `tree`/cursor 期间 `await`**：`reset+parse+遍历+delete` 必须保持同步原子块（这是「同一 evaluator 并发 0 竞态」的前提）。cursor 也要在 `finally` 里 `delete()`。

**Files:**
- Modify: `src/internal/shell/ir.ts`
- Test: 无新文件；靠强回归（下方命令）

- [ ] **Step 1: 先建立行为快照（防 reasonCode 漂移）**

写一个临时脚本（勿提交）对一组多 effect 脚本采集 `(action, reasonCode, effects[].effectCode 顺序)`：

```sh
node --import tsx -e '
import("./src/shell.ts").then(async ({ createShellPolicyEvaluator }) => {
  const e = createShellPolicyEvaluator();
  const cases = [
    "sed -i s/a/b/ /etc/hosts; uname -a",
    "true && rm /tmp/x; cat /etc/shadow",
    "ps aux | head; echo done > /tmp/log &",
    "for f in a b; do cat $f; done",
  ];
  for (const src of cases) {
    const d = await e.evaluate({ sourceText: src });
    console.log(JSON.stringify([src, d.action, d.reasonCode, d.effects.map((x) => x.effectCode)]));
  }
});
' > /tmp/ir-baseline.txt
```

- [ ] **Step 2: RED 命令（预期直接 PASS，本 Task 靠快照与全量回归兜底）**

- [ ] **Step 3: 实现**

打开 `src/internal/shell/ir.ts`：

1. `parseShellIr` 主循环：保留 `pending` 栈与所有计数/失败分支，仅把

```ts
for (const child of node.children) {
  if (child.type === '&') { background = true; }
  pending.push({ node: child, depth: depth + 1 });
}
```

替换为 cursor 枚举（不物化数组）：

```ts
const cursor = node.walk();
try {
  if (cursor.gotoFirstChild()) {
    do {
      const child = cursor.currentNode;
      if (child.type === '&') {
        background = true;
      }
      pending.push({ node: child, depth: depth + 1 });
    } while (cursor.gotoNextSibling());
  }
} finally {
  cursor.delete();
}
```

（若 profiling 显示每节点 `node.walk()` 的分配抵消收益，进阶版是整棵树单 cursor 的 goto 深遍历——但那会改变访问顺序，必须先证明 reasonCode 快照不变才允许。）
2. `containsDynamicSyntax` 同法改 cursor 版（它只看 `namedChildren`——cursor 版要用 `currentNode.isNamed` 过滤，保持只判 named 节点的现状语义）。
3. `commandFromNode`/`redirectFromNode`/`decodeStaticShellText`/`nodeLocation` 不动。

- [ ] **Step 4: GREEN + 快照比对**

重跑 Step 1 的脚本输出与 `/tmp/ir-baseline.txt` diff，必须逐字节一致。然后强回归：

Run: `node --import tsx --test test/analyzers/shell-structure.test.ts test/analyzers/shell-contracts.test.ts test/analyzers/adversarial.test.ts test/analyzers/fuzz.test.ts test/analyzers/accuracy-matrix.test.ts test/analyzers/evidence-location.test.ts test/replay/remote-command-replay.test.ts`
Expected: 全部 PASS。任何一个 FAIL → 修不动就整体回退本 Task（`git revert`），不要局部妥协。

- [ ] **Step 5: 收益确认（勿提交为测试）**

对中等脚本跑前后 p50 对比，收益写进 commit message。

**效果不变量:** 快照逐字节一致；限额只严不松；同步原子块保持。
**风险:** 高（顺序漂移、匿名节点漏访、cursor 生命周期泄漏）。已通过「保持栈结构只换 children 枚举」把风险压到最低。
**DoD:** 强回归全绿 + 快照一致 + `npm run verify` GREEN；或明确记录放弃并回退。

---

### Task 10: contracts 常量提升

**前置依赖:** 无（放在 Task 7 之后做可避免 rebase 冲突，两者都动 contracts.ts）。

**现状（逐个点名，`src/internal/shell/contracts.ts` @ `24816da`）:**
- `analyzeFind`（~500 行）：`args.some((argument) => new Set([...9 项...]).has(argument ?? ''))`——**每个参数** 分配一个 9 元素 Set。
- `analyzeCurl`（~774 行）：选项循环 **每轮迭代** 里 `new Set([...28 项...])`（~845 行）和 `new Set([...8 项...])`（~884 行）。
- `analyzeIp`（~480 行）、`analyzeSystemctl`（`readSubcommands`，~432 行）、`analyzeDate`（`valueOptions`，~610 行）、`analyzeGit`（两个 Set，~646/655 行）、`analyzeDocker`（`namespaceReads` 整个 Record + 内嵌 Sets，~711–753 行）、`analyzeShellCommand` 里 kubectl/virsh/timedatectl/apt/yum/npm 的 `onlyReadSubcommands(args, new Set([...]))`（~1134/1151/1204/1325/1347/1352 行）：每次调用重建。
- `src/internal/shell/embedded.ts` 的 `toResp`（~225 行）：每次调用 `new TextEncoder()`；`analyzeRedis` 里 `new Set(['--no-raw','--raw','--quoted-input'])` 在循环内（~271 行）。

**为什么改:** 纯分配削减，行为零变化。行为测试已全部存在（`shell-contracts.test.ts` 对上述每个命令族都有配对用例），本 Task 不新增测试。

**Files:**
- Modify: `src/internal/shell/contracts.ts`
- Modify: `src/internal/shell/embedded.ts`

- [ ] **Step 1: 基线**

Run: `node --import tsx --test test/analyzers/shell-contracts.test.ts`
Expected: PASS（基线；本 Task 无行为级 RED）。

- [ ] **Step 2: 实现**

把上面点名的每个内联 `new Set(...)` / Record / `new TextEncoder()` 提升为模块级 `const`（命名风格对齐现有 `safeSedShortFlags`），例如：

```ts
const findMutatingExpressions = new Set([
  '-delete', '-exec', '-execdir', '-fls', '-fprintf',
  '-fprint', '-fprint0', '-ok', '-okdir',
]);
```

只做提升，不改任何集合的成员和判断逻辑。`toResp` 用模块级 `const respEncoder = new TextEncoder();`。

- [ ] **Step 3: GREEN + 不变量回归**

Run: `node --import tsx --test test/analyzers/shell-contracts.test.ts test/analyzers/redis.test.ts test/analyzers/accuracy-matrix.test.ts test/analyzers/adversarial.test.ts`
Expected: PASS。

**效果不变量:** 集合成员一字不差（提升时逐个 diff）；决策不变。
**风险:** 手滑改了集合成员——用 `git diff` 逐行核对，每个 Set 只应有缩进/位置变化。
**DoD:** 回归 GREEN；`npm run verify` GREEN。

---

### Task 11: `copyPolicyAssets` 可选过滤（P2 产品项，默认行为不变）

**前置依赖:** Task 6（README 里要交叉引用准确率取舍）。

**现状:** `src/build.ts` 的 `copyPolicyAssets` 无条件拷贝 `POLICY_ASSET_MANIFEST` 全部 3 个 wasm。不用嵌入 python 分析的消费者也得背 ~447KB 的 `tree-sitter-python.wasm`。

**为什么改:** 给消费者一个显式的体积/准确率取舍开关。**默认全量不变**。缺 python wasm 时的失败路径要看准：python evaluator 初始化失败 **不抛异常**，而是返回 `policy.initialization_failed` 的 review 决策；`embedded.ts` 的 `evaluatePayload` 把该决策包成 action review、reasonCode `shell.embedded_python_review` 的 effect。所以 `python3 -c` fail-closed 到 review，永远不会 false-allow。

**Files:**
- Modify: `src/build.ts`
- Modify: `README.md`（Bundled consumers 一节补「省 python wasm 的准确率取舍」段）
- Test: `test/contracts/build-api.test.ts`（扩展）+ `test/analyzers/embedded-gate.test.ts`（追加缺资产行为用例，或新建 `test/analyzers/missing-asset.test.ts`）

- [ ] **Step 1: 写失败测试**

`test/contracts/build-api.test.ts` 新增：

```ts
test('copyPolicyAssets can copy an explicit asset subset', async () => {
  const destinationDirectory = await mkdtemp(join(tmpdir(), 'command-policy-subset-'));
  try {
    const copied = await build.copyPolicyAssets({
      destinationDirectory,
      include: ['tree-sitter-runtime', 'tree-sitter-bash'],
    });
    assert.deepEqual(copied.map((asset) => asset.id), [
      'tree-sitter-runtime',
      'tree-sitter-bash',
    ]);
    await assert.rejects(
      readFile(join(destinationDirectory, 'tree-sitter-python.wasm')),
      { code: 'ENOENT' },
    );
    await assert.rejects(
      build.copyPolicyAssets({ destinationDirectory, include: ['no-such-asset'] }),
      TypeError,
    );
  } finally {
    await rm(destinationDirectory, { recursive: true, force: true });
  }
});
```

运行时行为用例（缺 python wasm 时 fail-closed，uptime 不受影响）：

```ts
test('missing python grammar fails closed for python payloads only', async () => {
  const evaluator = createShellPolicyEvaluator({
    assetResolver(asset) {
      if (asset.id === 'tree-sitter-python') {
        throw new Error('excluded by copyPolicyAssets include list');
      }
      return fileURLToPath(assetUrls[asset.id]); // 同 Task 2 的 assetUrls 映射
    },
  });
  assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
  const python = await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' });
  assert.equal(python.action, 'review');
  assert.equal(python.reasonCode, 'shell.embedded_python_review');
});
```

- [ ] **Step 2: RED**

Run: `node --import tsx --test test/contracts/build-api.test.ts`
Expected: FAIL——`include` 选项不存在（TS 编译期报未知属性，或运行时全量拷贝导致断言失败）。

- [ ] **Step 3: 实现**

打开 `src/build.ts`：

```ts
export interface CopyPolicyAssetsOptions {
  readonly destinationDirectory: string;
  /**
   * Optional allowlist of asset ids to copy. Defaults to the complete
   * POLICY_ASSET_MANIFEST. Omitting an asset trades accuracy for size:
   * evaluators that need it fail closed to review, never to allow.
   */
  readonly include?: readonly string[];
}
```

`copyPolicyAssets` 开头校验并过滤：

```ts
const knownIds = new Set(POLICY_ASSET_MANIFEST.map((asset) => asset.id));
for (const id of options.include ?? []) {
  if (!knownIds.has(id)) {
    throw new TypeError(`Unknown policy asset id: ${id}`);
  }
}
const selected = options.include
  ? POLICY_ASSET_MANIFEST.filter((asset) => options.include!.includes(asset.id))
  : POLICY_ASSET_MANIFEST;
```

`Promise.all` 改为遍历 `selected`。`scripts/build.mjs` 里自家打包的调用 **不传 include**（tarball 仍 3 个 wasm，size-budget 的 `wasmFiles.length === 3` 断言不动）。

- [ ] **Step 4: GREEN**

Run: `node --import tsx --test test/contracts/build-api.test.ts test/analyzers/embedded-gate.test.ts`
Expected: PASS。

- [ ] **Step 5: 文档 + 不变量回归**

README Bundled consumers 补一段：`include: ['tree-sitter-runtime', 'tree-sitter-bash']` 可省 ~447KB，代价是所有 `python3 -c` payload 一律 review（fail-closed，绝不 false-allow）；需要嵌入 python 分析的插件不要用。

Run: `npm run build && npm run test:package:runtime && node --import tsx --test test/analyzers/accuracy-matrix.test.ts`
Expected: PASS——默认路径 tarball 与 size-budget 完全不变。

**效果不变量:** 不传 `include` 时行为与现状逐字节一致；缺资产只会把 allow 变 review，方向永远更严。
**风险:** 消费者误删 `tree-sitter-bash`——shell 域会全量 `policy.initialization_failed` review，fail-closed 兜底但可用性崩，README 必须写明 bash 与 runtime 是 shell 域的硬依赖。
**DoD:** 新测试 GREEN、README 更新、`npm run verify` GREEN。

---

## 5. 明确不做 / Epic-later（禁止在本计划内动手）

- **不要用正则替换 tree-sitter-bash / tree-sitter-python。** 词法级方案无法证明「每个可达 effect 都是普通读」，必然回到 false-allow 或全量 review。
- **不要默认移除嵌入语言分析。** `python3 -c`/`sqlite3`/`mysql -e` 的静态 payload 分析是这个包相对旧 blocklist 的核心价值。
- **不要在本计划替换 `node-sql-parser`。** 包体积分析的结论：自写 SQL parser 的失败模式是 false-allow（漏解析 → 误判读安全）。域分析建议的「MySQL 只读子集 parser」列为 **Epic-later**：仅当 Task 4 的预扫描证明不够（出现绕过预扫描的新型注入面）且备齐完整对抗语料时，另开独立计划评估。
- **不要 wasm-opt / 重编译官方 `@vscode/tree-sitter-wasm`。** ABI/版本对齐风险大于 ~10–15% 的体积收益。
- **不要删除 CJS parser 子路径。** Node 18 不能 `require` ESM（本包 engines `>=18`）。最多在 README/docs 标注 deprecated，删除留给下个 major。
- **不要改变 `deny > review > allow` 聚合、redacted evidence、`sourceText` 不进 summary 这三条铁律。** 任何性能/体积手段与之冲突时，放弃该手段。

## 6. 插件集成 checklist（交付给 AT Terminal MCP 侧）

- [ ] 依赖 **精确锁版**（无 `^`/`~`），升级走显式 PR。
- [ ] 单 CJS 打包时 `banner` + `define` `import.meta.url`（Task 6 配方），CI 里跑 `python3 -c "print(1)"` → allow 的冒烟断言。
- [ ] 构建期 `copyPolicyAssets` 到插件资产目录，运行时 `assetResolver` 传绝对路径或 bytes。
- [ ] 激活路径可选调 `warmupShellPolicyEvaluator()`（Task 2）隐藏 ~18–20ms 冷启动；失败可忽略（evaluate 自身 fail-closed）。
- [ ] 只在 limited-trust 路径加载 policy 引擎（独立 `policy-runtime.js` entry），信任映射/确认 UI/日志仍归插件。
- [ ] 日志绝不落 `sourceText`（决策 JSON 本身已 redacted，可整条落）。
- [ ] 若用 Task 11 的 `include` 过滤 wasm：确认产品接受「python payload 全 review」，且 `tree-sitter-runtime`+`tree-sitter-bash` 必须保留。

## 7. 建议 PR 切分

| PR | Tasks | 说明 |
| --- | --- | --- |
| PR-A | Task 1（minify）+ Task 4（MySQL 注释修复）+ Task 3（limits）+ Task 2（Language cache/warmup） | 高收益低风险打包；Task 4 单独 commit 便于 cherry-pick |
| PR-B | Task 5（runtime chunk）+ Task 6（README 配方） | 构建形态变化 + 面向消费者的文档一起评审 |
| PR-C | Task 7（embedded 门闩）+ Task 8(懒算 location) + Task 10（常量提升） | 热路径微优化，行为零变化 |
| PR-D | Task 9（IR cursor） | **可丢弃**；回归有任何异样直接关闭 PR |
| PR-E | Task 11（optional wasm filter） | 产品取舍项，可独立排期 |

每个 PR 合并前必须：`npm run verify` GREEN + `node --import tsx --test test/analyzers/accuracy-matrix.test.ts` false-allow==0。

## 8. 最终验收

- [ ] `npm run verify` GREEN（typecheck、全量测试、双构建、干净 tarball 消费者、publint、pack 检查）。
- [ ] `node --import tsx --test test/analyzers/accuracy-matrix.test.ts`：45 条语料全对，confusion matrix false-allow==0。
- [ ] `node --test test/package/runtime-chunk.test.mjs`：`uptime` 不加载 `tree-sitter-python.wasm`——在只 evaluate 过 `uptime` 的阶段对 `calls` 键集断言仅含 `tree-sitter-runtime` 与 `tree-sitter-bash`。mysql/python 的 JS 模块因惰性 `import()` 同样不加载（wasm 计数是其代理指标）。
- [ ] 体积：packed ≤ 2.5MB、恰好 3 个 wasm（默认）；raw dist JS 相比基线 −40% 以上，实测数字记入最终 PR 描述。
- [ ] 性能：在当前机器复测 uptime 热路径 p50、第二个 evaluator 冷成本、`python -c` 冷路径，与第 2 节基线对比后写入最终 PR 描述（数字不进测试断言）。
