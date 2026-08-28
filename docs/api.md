# Command policy API

Stable consumer contract for `@at-series/command-policy@0.1.1`.

Install from the npm `@at-series` organization. Pin the exact version:

```sh
npm install @at-series/command-policy@0.1.1
```

```json
{
  "dependencies": {
    "@at-series/command-policy": "0.1.1"
  }
}
```

Do not use `^` or `~`. This package is a security boundary.

Package: https://www.npmjs.com/package/@at-series/command-policy

This library only analyzes text and returns a `PolicyDecision`. It does not
map trust levels, show UI, write logs, or execute commands.

## Modules

| Import | Factory |
| --- | --- |
| `@at-series/command-policy` | types, `combinePolicyDecisions`, `POLICY_*` constants |
| `@at-series/command-policy/shell` | `createShellPolicyEvaluator`, `warmupShellPolicyEvaluator` |
| `@at-series/command-policy/python` | `createPythonPolicyEvaluator` |
| `@at-series/command-policy/sqlite` | `createSqlitePolicyEvaluator` |
| `@at-series/command-policy/mysql` | `createMysqlPolicyEvaluator` |
| `@at-series/command-policy/redis` | `createRedisPolicyEvaluator` |
| `@at-series/command-policy/build` | `copyPolicyAssets`, `POLICY_ASSET_MANIFEST` |

Node.js `>= 18`. Dual ESM / CJS. No `vscode` runtime dependency.

## Evaluate

```ts
import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';

const evaluator = createShellPolicyEvaluator();
const decision = await evaluator.evaluate({
  sourceText: finalCommandText,
  cwd,
});
```

| Field | Rule |
| --- | --- |
| `sourceText` | Exact text that would be executed. Do not rewrite it after the decision. |
| `cwd` | Optional. Pass separately. Never concatenate into `sourceText`. |

`createShellPolicyEvaluator` lazily loads Python / SQLite / MySQL / Redis
when a static embedded payload is present.

Options on language factories:

```ts
{
  assetResolver?: PolicyAssetResolver;
  limits?: Partial<PolicyAnalysisLimits>;
}
```

SQL and Redis factories take `limits` only. Python and Shell also take
`assetResolver` for Tree-sitter WASM.

## Warmup (optional)

```ts
import { warmupShellPolicyEvaluator } from '@at-series/command-policy/shell';

await warmupShellPolicyEvaluator({ assetResolver });
```

Pre-initializes the Tree-sitter runtime and the bash grammar so the first
`evaluate()` pays no cold-start cost. Entirely optional: a warmup failure
rejects here, but evaluators stay independent and still fail closed to
`review` on `evaluate()`.

## `PolicyDecision`

```ts
{
  schemaVersion: '1.0.0';
  action: 'allow' | 'review' | 'deny';
  effects: readonly PolicyEffect[];
  reasonCode: string;
  evidence: readonly PolicyEvidence[];
  versions: {
    policy: string;
    rules: Readonly<Record<string, string>>;
    parsers: Readonly<Record<string, string>>;
  };
}
```

| `action` | Plugin should |
| --- | --- |
| `allow` | Skip confirmation under limited trust |
| `review` | Confirm (writes, sensitive reads, parse/init/limit/unknown) |
| `deny` | Refuse or still confirm; never silently execute |

`combinePolicyDecisions(...): PolicyDecision` picks the first strictest
result: **`deny > review > allow`**. A consumer may only make an official
result stricter.

Evidence:

- `redacted` is always `true`
- `summary` is controlled wording — never source text, cwd, or parser errors
- `location` is a half-open `[start, end)` UTF-16 range over the exact source
- CRLF occupies two UTF-16 code units

## Fail-closed reason codes

| Code | When |
| --- | --- |
| `policy.analysis_unavailable` | Analyzer cannot run |
| `policy.initialization_failed` | WASM / parser init failed |
| `policy.parse_failed` | Syntax tree is incomplete or erroneous |
| `policy.resource_limit_exceeded` | Input / AST / nesting / work budget |
| `policy.unknown_semantics` | Effect cannot be proven ordinary-read |
| `policy.invalid_decision` | Malformed runtime decision |

All of these map to `review`, not `allow`.

## Bundling WASM

`@at-series/command-policy/build` is **build-time only**.

```ts
import { copyPolicyAssets } from '@at-series/command-policy/build';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createShellPolicyEvaluator } from '@at-series/command-policy/shell';

await copyPolicyAssets({ destinationDirectory: 'dist/policy-assets' });

const evaluator = createShellPolicyEvaluator({
  assetResolver: (asset) => readFile(join(assetDir, asset.fileName)),
});
```

Allowlist: `web-tree-sitter.wasm`, `tree-sitter-bash.wasm`,
`tree-sitter-python.wasm`.

`copyPolicyAssets` options:

| Option | Meaning |
| --- | --- |
| `destinationDirectory` | Required. Created recursively. |
| `include` | Optional allowlist of asset ids. Default: the complete `POLICY_ASSET_MANIFEST` (all three files, today's behavior). Unknown ids throw a `TypeError`. |

Omitting an asset trades accuracy for size, never safety: evaluators that
need it fail closed to `review`. Without `tree-sitter-python`, every
`python3 -c` payload reviews with reason code
`shell.embedded_python_review`. `tree-sitter-runtime` and
`tree-sitter-bash` are hard dependencies of the shell domain — without
them every shell evaluation reviews with `policy.initialization_failed`.

After a CJS rebundle, define `import.meta.url` as
`pathToFileURL(__filename).href` (esbuild: inject a `banner` and map it
with `define`; full recipe in the README's *Bundled consumers* section)
and pass file bytes or absolute paths through `assetResolver`. Skipping
the define produces no build or runtime error: embedded Python analysis
silently fail-closes and every `python3 -c` payload becomes `review`.

## Plugin mapping (AT Terminal)

| Trust | Load this package? | Behavior |
| --- | --- | --- |
| `none` | No | Always confirm |
| `policy` | Yes (MCP variant, lazy) | `allow` executes; `review`/`deny` confirm |
| `full` | No | Always execute |

The MCP VSIX ships a separate `policy-runtime.js`. The agentless base variant
must contain zero policy code and zero WASM.

JumpServer is not a consumer yet. When it is: evaluate the same normalized
command that will execute; do not let shared `allow` skip confirms until an
explicit trust model exists; `sendTerminalInput` stays always-confirm.
