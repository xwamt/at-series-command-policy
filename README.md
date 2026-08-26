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
`dist/assets/`. After you re-bundle into a single CJS file, that path is
wrong. Copy the allowlist at build time and pass bytes or absolute paths:

```ts
import { copyPolicyAssets } from '@at-series/command-policy/build';
import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

await copyPolicyAssets({ destinationDirectory: 'dist/policy-assets' });

const evaluator = createShellPolicyEvaluator({
  assetResolver: (asset) => readFile(join(assetDir, asset.fileName)),
});
```

Allowlisted files:

- `web-tree-sitter.wasm`
- `tree-sitter-bash.wasm`
- `tree-sitter-python.wasm`

If you emit CJS, define `import.meta.url` to `pathToFileURL(__filename).href`
(or equivalent). Empty `import.meta` makes Tree-sitter initialization fail
closed to `review`.

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
