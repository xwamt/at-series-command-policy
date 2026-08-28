# @at-series/command-policy

UI-independent command policy for AT Series plugins.

This repository publishes **one** Apache-2.0 npm package. Analyzers decide
whether a command or payload is `allow`, `review`, or `deny`. They do not map
trust levels, show confirmation UI, write logs, or execute anything.

当前状态：**0.1.0**。Shell / Python / SQLite / MySQL / Redis 分析器已落地，fail-closed，
双模块 CJS/ESM。第一位消费者是 **AT Terminal MCP** 的 limited-trust
`run_remote_command`。JumpServer 尚未接入。

---

## Why this package exists

Limited-trust agent commands used to be a plugin-local shell lexer plus a
blocklist. That rejected `# Purpose:` newlines, treated unknown binaries as
safe, and could not see into `python3 -c`, `sqlite3`, or `sudo` wrappers.

This package replaces that with deterministic parsers and command contracts:

- Parse the **exact** text that would be executed (`sourceText`).
- Prove ordinary reads before auto-allowing them.
- Confirm (or deny) writes, controls, sensitive reads, and anything unknown.
- Keep the same decision shape across Shell, Python, SQL, and Redis so more
  than one plugin can share it.

It is **not** an OS sandbox. A malicious binary whose name looks like `ls`
is out of scope. The policy only reasons about static, parseable source.

## Install

Node.js **>= 18**. No `vscode` runtime or peer dependency.

Published on npm under the `@at-series` org:

```sh
npm install @at-series/command-policy@0.1.0
```

Plugins must pin an **exact** version. Do not use `^` or `~` for a security
boundary.

```json
{
  "dependencies": {
    "@at-series/command-policy": "0.1.0"
  }
}
```

Package page: https://www.npmjs.com/package/@at-series/command-policy

The public TypeScript contract is in [`docs/api.md`](./docs/api.md).

## Package surface

| Entry | Role |
| --- | --- |
| `@at-series/command-policy` | Decision types, fail-closed reason codes, `combinePolicyDecisions`, version metadata |
| `@at-series/command-policy/shell` | Bash scripts; lazily embeds Python / SQLite / MySQL / Redis when those payloads are static |
| `@at-series/command-policy/python` | Python snippets (`-c` and equivalent) |
| `@at-series/command-policy/sqlite` | SQLite SQL and sqlite3 CLI dot-commands |
| `@at-series/command-policy/mysql` | MySQL SQL |
| `@at-series/command-policy/redis` | Redis commands / RESP arrays |
| `@at-series/command-policy/build` | Build-time copy of the WASM allowlist only |

Dual **ESM and CJS**, with `.d.ts` / `.d.cts`. Parsers are bundled into the
published tarball; they are not runtime `dependencies`.

## Usage

Pass the final command text. Do not rewrite `sourceText` after a decision.
Pass `cwd` separately; never concatenate it into the command.

```ts
import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';

const evaluator = createShellPolicyEvaluator();
const decision = await evaluator.evaluate({
  sourceText: finalCommandText,
  cwd,
});

switch (decision.action) {
  case 'allow':
    break;
  case 'review':
  case 'deny':
    // Plugin shows confirmation or refuses. This package does not.
    break;
}
```

`decision.evidence[].summary` is always redacted, plugin-controlled wording.
It never includes source text, cwd, or parser errors. Ranges are half-open
`[start, end)` over the exact UTF-16 source (CRLF is two code units).

### Bundled consumers (VS Code / Electron)

Default WASM resolution uses `import.meta.url` next to this package's
`dist/assets/`. After you re-bundle into a single CJS file, that URL is
wrong (or empty), so a bundled consumer must own two things: the
`import.meta.url` definition and the WASM asset paths.

#### 1. esbuild recipe (`banner` + `define` are mandatory for CJS)

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

> **Warning: skipping `banner`/`define` fails silently.** There is no build
> error and no runtime exception. `import.meta.url` becomes empty in CJS
> output, the embedded Python evaluator fails to initialize, and **every
> `python3 -c` payload silently fail-closes to `review`** instead of being
> analyzed. Plain shell commands keep working, so the misconfiguration is
> very hard to notice. Keep the smoke assertion from step 5 in your CI.

#### 2. WASM assets

Copy the allowlist at build time, then resolve bytes or absolute paths at
runtime through `assetResolver`:

```js
// Build script, next to the esbuild call above:
import { copyPolicyAssets } from '@at-series/command-policy/build';

await copyPolicyAssets({ destinationDirectory: 'dist/policy-assets' });
```

```ts
// Runtime (src/policy-runtime.ts). assetDir is the directory that
// copyPolicyAssets populated, resolved relative to the bundled file
// (__dirname works because the bundle above is CJS):
import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const assetDir = join(__dirname, 'policy-assets');

const evaluator = createShellPolicyEvaluator({
  assetResolver: (asset) => readFile(join(assetDir, asset.fileName)),
});
```

Allowlisted files:

- `web-tree-sitter.wasm`
- `tree-sitter-bash.wasm`
- `tree-sitter-python.wasm`

##### Optional: dropping the Python grammar (size / accuracy trade-off)

`copyPolicyAssets` accepts an `include` allowlist of asset ids. The
default (no `include`) copies all three WASM files and keeps today's
behavior exactly. A plugin that never needs embedded Python analysis can
skip `tree-sitter-python.wasm` (~447KB):

```js
await copyPolicyAssets({
  destinationDirectory: 'dist/policy-assets',
  include: ['tree-sitter-runtime', 'tree-sitter-bash'],
});
```

The cost is accuracy, never safety: with the grammar missing, every
`python3 -c` payload fail-closes to `review` (reason code
`shell.embedded_python_review`) instead of being analyzed — it can never
become a false `allow`. Commands without an embedded Python payload
(`uptime`, pipelines, `mysql -e`, …) are unaffected. Plugins that need
embedded Python analysis must not use this filter.

`tree-sitter-runtime` and `tree-sitter-bash` are **hard dependencies of
the shell domain**: dropping either one makes every shell evaluation fail
closed to `review` (`policy.initialization_failed`) — safe, but useless.
Unknown asset ids throw a `TypeError` at build time.

#### 3. Byte-level vs execution-level lazy loading

A single-file bundle inlines every lazily imported sibling module —
`./python.js`, `./sqlite.js`, `./mysql.js`, `./redis.js`, and
`./tree-sitter-runtime.js` — so a shell-only bundle grows to roughly
1.29MB (mostly the MySQL parser). **Execution-level lazy loading still
holds**: a command with no embedded payload never executes those modules'
initialization code. Only the byte boundary collapses.

To keep the byte boundary too (for example, to keep the MySQL parser out
of a VSIX), pick one of:

- Mark the five sibling files external and copy the matching
  `dist/*.js` / `dist/*.cjs` files next to your bundle:

```js
await build({
  // ...same options as step 1...
  external: [
    '*/mysql.js',
    '*/python.js',
    '*/sqlite.js',
    '*/redis.js',
    '*/tree-sitter-runtime.js',
  ],
});
```

- Or emit ESM with `splitting: true` (esbuild code splitting does not
  support CJS output).

#### 4. Optional warmup

`warmupShellPolicyEvaluator()` pre-initializes the Tree-sitter runtime and
the bash grammar so the first `evaluate()` pays no cold-start cost
(~18–20ms measured). Call it on extension activation; failures may be
ignored because `evaluate()` fails closed to `review` on its own.

```ts
import { warmupShellPolicyEvaluator } from '@at-series/command-policy/shell';

void warmupShellPolicyEvaluator({ assetResolver }).catch(() => {});
```

#### 5. Post-bundle smoke assertion (consumer CI)

Run this against the **bundled** output. The second assertion is the guard
for step 1: when `import.meta.url` is not defined, it reports `review`
instead of `allow`.

```js
const evaluator = createShellPolicyEvaluator({ assetResolver });
assert.equal((await evaluator.evaluate({ sourceText: 'uptime' })).action, 'allow');
assert.equal(
  (await evaluator.evaluate({ sourceText: 'python3 -c "print(1)"' })).action,
  'allow', // review here means import.meta.url was not defined correctly
);
```

## Decision model

| Action | Meaning for a plugin |
| --- | --- |
| `allow` | Every reachable effect is a proven ordinary read |
| `review` | Human should confirm (writes, sensitive reads, parse/init/limit/unknown) |
| `deny` | Hard reject where the contract says so (e.g. blocking Redis) |

Aggregation is always **`deny > review > allow`**.
`combinePolicyDecisions` picks the first strictest decision. A consumer may
only make an official result **stricter**.

Fail-closed reason codes:

- `policy.analysis_unavailable`
- `policy.initialization_failed`
- `policy.parse_failed`
- `policy.resource_limit_exceeded`
- `policy.unknown_semantics`
- `policy.invalid_decision`

Schema version is `1.0.0`. Each decision also carries parser/rule versions
from `POLICY_VERSION_METADATA`.

## What the analyzers cover

**Shell.** Tree-sitter Bash → policy IR. Observers such as `ls`, `ps`,
`systemctl status`, `docker ps`, `curl` GET/HEAD without credentials can
`allow`. Writes, service control, unknown binaries, substitutions that
execute, and sensitive paths (`/etc/shadow`, `.env`, SSH keys) are `review`.
Recognized wrappers (`sudo`, `env`, `busybox`, `timeout`, `bash -c` with a
static script) re-enter analysis instead of blindly blocking the wrapper
name. `# Purpose:` comments are comments, never authority.

**Python.** A strict expression/control-flow subset plus approved `sqlite3`
usage. Dynamic code, unknown imports, file writes, and sensitive SQL are
`review`.

**SQLite / MySQL.** Ordinary `SELECT` / metadata can `allow`. Writes,
controls, unknown functions, and secret-bearing tables or columns are
`review`. sqlite3 CLI: `.tables` / `.schema` allow; `.backup` / `.import`
review.

**Redis.** Non-blocking reads can `allow`. Writes and controls are `review`.
Known blocking commands (`BLPOP`, …) are `deny`.

Shell evaluation **lazily** loads the other analyzers only when a static
embedded payload is present, so a plain `uptime` does not initialize SQL
parsers.

## Plugin responsibilities

This library only returns `PolicyDecision`. The plugin still owns:

- Trust mapping (`none` / `policy` / `full` in AT Terminal)
- Confirmation UI and cancellation
- Execution
- Logging (must not log raw `sourceText` from this package’s evidence)

AT Terminal MCP loads the engine only under limited trust, from a separate
`policy-runtime.js` entry so the agentless base VSIX stays empty of policy
code and WASM.

JumpServer is **next phase**: `runTerminalCommand` should call `/shell` on
the same normalized text that will execute; `sendTerminalInput` stays
always-confirm. JumpServer has no trust levels today, so a shared `allow`
must not skip existing confirms until an explicit trust model exists.

## Development

```sh
npm install
npm run verify
```

`verify` runs typecheck, analyzer/replay/adversarial/fuzz tests, the dual
build, clean-tarball consumer tests, publint, and `npm pack --dry-run`.

CI (GitHub Actions) runs that matrix on Node **18 / 20 / 22**. Releases use
[Changesets](https://github.com/changesets/changesets) and npm provenance on
`main` when publishing credentials are configured.

```sh
npx changeset
```

## License

Apache-2.0. Bundled parser notices (Tree-sitter, sqlite3-parser,
node-sql-parser) are in [`NOTICE`](./NOTICE).
