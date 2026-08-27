import type { PolicyEvaluator } from '../../index.js';
import type { AnalyzedEffect } from '../analysis/decision.js';
import { isSensitivePath } from '../analysis/sensitivity.js';
import { normalizeExecutable } from './contracts.js';
import type { ShellCommandIr } from './ir.js';

export interface EmbeddedEvaluatorLoaders {
  readonly python: () => Promise<PolicyEvaluator>;
  readonly sqlite: () => Promise<PolicyEvaluator>;
  readonly mysql: () => Promise<PolicyEvaluator>;
  readonly redis: () => Promise<PolicyEvaluator>;
}

function unknownEmbedded(domain: string): readonly AnalyzedEffect[] {
  return [
    {
      effectCode: `shell.embedded.${domain}.unknown`,
      action: 'review',
      reasonCode: 'shell.unknown_semantics',
      kind: 'argument',
      summary: 'An embedded-language payload is not statically established.',
    },
  ];
}

function sensitiveResource(domain: string): readonly AnalyzedEffect[] {
  return [
    {
      effectCode: `shell.embedded.${domain}.sensitive_resource`,
      action: 'review',
      reasonCode: 'shell.sensitive_read',
      kind: 'path',
      summary: 'An embedded-language client may access a sensitive resource.',
    },
  ];
}

async function evaluatePayload(
  domain: 'python' | 'sqlite' | 'mysql' | 'redis',
  payload: string,
  loader: () => Promise<PolicyEvaluator>,
): Promise<readonly AnalyzedEffect[]> {
  try {
    const decision = await (await loader()).evaluate({ sourceText: payload });
    return [
      {
        effectCode: `shell.embedded.${domain}`,
        action: decision.action,
        reasonCode: `shell.embedded_${domain}_${decision.action}`,
        kind: 'argument',
        summary: `A static ${domain} payload was analyzed by its domain policy.`,
      },
    ];
  } catch {
    return unknownEmbedded(domain);
  }
}

function optionValue(
  argument: string,
  longName: string,
): string | undefined {
  return argument.startsWith(`${longName}=`)
    ? argument.slice(longName.length + 1)
    : undefined;
}

async function analyzePython(
  command: ShellCommandIr,
  loaders: EmbeddedEvaluatorLoaders,
): Promise<readonly AnalyzedEffect[]> {
  const codeIndex = command.arguments.findIndex(
    (argument) => argument === '-c',
  );
  if (codeIndex < 0) {
    return unknownEmbedded('python');
  }
  const payload = command.arguments[codeIndex + 1];
  if (!payload) {
    return unknownEmbedded('python');
  }
  return evaluatePayload('python', payload, loaders.python);
}

async function analyzeSqlite(
  command: ShellCommandIr,
  loaders: EmbeddedEvaluatorLoaders,
): Promise<readonly AnalyzedEffect[]> {
  const operands: (string | undefined)[] = [];
  const valueOptions = new Set(['-cmd', '-init', '-separator']);
  for (let index = 0; index < command.arguments.length; index += 1) {
    const argument = command.arguments[index];
    if (!argument) {
      return unknownEmbedded('sqlite');
    }
    if (valueOptions.has(argument)) {
      return unknownEmbedded('sqlite');
    }
    if (argument === '--') {
      operands.push(...command.arguments.slice(index + 1));
      break;
    }
    if (argument.startsWith('-')) {
      continue;
    }
    operands.push(argument);
  }
  const [database, query] = operands;
  if (!database || !query || operands.length !== 2) {
    return unknownEmbedded('sqlite');
  }
  if (database !== ':memory:' && isSensitivePath(database)) {
    return sensitiveResource('sqlite');
  }
  const metaCommand = sqliteMetaCommand(query);
  if (metaCommand === 'read') {
    return [
      {
        effectCode: 'shell.embedded.sqlite.meta_read',
        action: 'allow',
        reasonCode: 'shell.read_only',
        kind: 'argument',
        summary: 'A sqlite3 meta-command has a read-only contract.',
      },
    ];
  }
  if (metaCommand === 'write') {
    return [
      {
        effectCode: 'shell.embedded.sqlite.meta_write',
        action: 'review',
        reasonCode: 'shell.write',
        kind: 'argument',
        summary: 'A sqlite3 meta-command may modify state.',
      },
    ];
  }
  return evaluatePayload('sqlite', query, loaders.sqlite);
}

const readOnlySqliteMetaCommands = new Set([
  'databases',
  'dump',
  'fullschema',
  'help',
  'indexes',
  'indices',
  'schema',
  'tables',
  'version',
]);

function sqliteMetaCommand(query: string): 'read' | 'write' | undefined {
  const match = /^\s*\.([A-Za-z]+)(?:\s|$)/.exec(query);
  if (!match) {
    return undefined;
  }
  const command = match[1]?.toLowerCase();
  if (!command) {
    return undefined;
  }
  return readOnlySqliteMetaCommands.has(command) ? 'read' : 'write';
}

async function analyzeMysql(
  command: ShellCommandIr,
  loaders: EmbeddedEvaluatorLoaders,
): Promise<readonly AnalyzedEffect[]> {
  let query: string | undefined;
  const sensitiveOptions = [
    '--defaults-extra-file',
    '--defaults-file',
    '--login-path',
    '--password',
    '--ssl-cert',
    '--ssl-key',
    '-p',
  ];
  const valueOptions = new Set([
    '--database',
    '--host',
    '--port',
    '--protocol',
    '--socket',
    '--user',
    '-D',
    '-h',
    '-P',
    '-S',
    '-u',
  ]);
  for (let index = 0; index < command.arguments.length; index += 1) {
    const argument = command.arguments[index];
    if (!argument) {
      return unknownEmbedded('mysql');
    }
    if (
      sensitiveOptions.some(
        (option) => argument === option || argument.startsWith(`${option}=`),
      ) ||
      /^-p.+/.test(argument)
    ) {
      return sensitiveResource('mysql');
    }
    if (argument === '-e' || argument === '--execute') {
      query = command.arguments[index + 1];
      index += 1;
      continue;
    }
    const attached = optionValue(argument, '--execute');
    if (attached !== undefined) {
      query = attached;
      continue;
    }
    if (valueOptions.has(argument)) {
      index += 1;
    }
  }
  return query
    ? evaluatePayload('mysql', query, loaders.mysql)
    : unknownEmbedded('mysql');
}

function toResp(arguments_: readonly string[]): string {
  const encoder = new TextEncoder();
  return [
    `*${arguments_.length}\r\n`,
    ...arguments_.flatMap((argument) => [
      `$${encoder.encode(argument).byteLength}\r\n`,
      `${argument}\r\n`,
    ]),
  ].join('');
}

async function analyzeRedis(
  command: ShellCommandIr,
  loaders: EmbeddedEvaluatorLoaders,
): Promise<readonly AnalyzedEffect[]> {
  const protocolArguments: string[] = [];
  const valueOptions = new Set([
    '--dbnum',
    '--host',
    '--port',
    '--socket',
    '-h',
    '-n',
    '-p',
    '-s',
  ]);
  const sensitiveOptions = new Set([
    '--askpass',
    '--pass',
    '--user',
    '-a',
  ]);
  let commandStarted = false;
  for (let index = 0; index < command.arguments.length; index += 1) {
    const argument = command.arguments[index];
    if (!argument) {
      return unknownEmbedded('redis');
    }
    if (!commandStarted && sensitiveOptions.has(argument)) {
      return sensitiveResource('redis');
    }
    if (!commandStarted && valueOptions.has(argument)) {
      index += 1;
      continue;
    }
    if (
      !commandStarted &&
      new Set(['--no-raw', '--raw', '--quoted-input']).has(argument)
    ) {
      continue;
    }
    commandStarted = true;
    protocolArguments.push(argument);
  }
  return protocolArguments.length > 0
    ? evaluatePayload('redis', toResp(protocolArguments), loaders.redis)
    : unknownEmbedded('redis');
}

function versionOrHelpOnly(
  args: readonly (string | undefined)[],
): boolean {
  return (
    args.length > 0 &&
    args.every(
      (argument) =>
        argument === '--version' ||
        argument === '-V' ||
        argument === '--help' ||
        argument === '-h',
    )
  );
}

export async function analyzeEmbeddedCommand(
  command: ShellCommandIr,
  loaders: EmbeddedEvaluatorLoaders,
): Promise<readonly AnalyzedEffect[] | undefined> {
  const name = normalizeExecutable(command.name);
  if (!name) {
    return undefined;
  }
  if (/^python3?(?:\.\d+)*$/.test(name)) {
    // Let `--version`/`--help` fall through to shell contracts.
    if (versionOrHelpOnly(command.arguments)) {
      return undefined;
    }
    return analyzePython(command, loaders);
  }
  if (name === 'sqlite3') {
    return analyzeSqlite(command, loaders);
  }
  if (name === 'mysql') {
    return analyzeMysql(command, loaders);
  }
  if (name === 'redis-cli') {
    return analyzeRedis(command, loaders);
  }
  return undefined;
}
