import type { AnalyzedEffect } from '../analysis/decision.js';
import {
  hasUrlCredentials,
  isSensitiveHeader,
  isSensitivePath,
} from '../analysis/sensitivity.js';
import { commandContracts, type CommandContract } from './command-table.js';
import type { ShellCommandIr } from './ir.js';

const trustedBinaryPrefixes = [
  '/bin/',
  '/sbin/',
  '/usr/bin/',
  '/usr/sbin/',
  '/usr/local/bin/',
  '/usr/local/sbin/',
  '/opt/homebrew/bin/',
  '/opt/homebrew/sbin/',
];

function effect(
  effectCode: string,
  action: 'allow' | 'review',
  reasonCode: string,
  summary: string,
  kind: AnalyzedEffect['kind'] = 'command',
): AnalyzedEffect {
  return { effectCode, action, reasonCode, summary, kind };
}

const ordinaryRead = () =>
  effect(
    'shell.command.read',
    'allow',
    'shell.read_only',
    'A recognized command has an ordinary read-only contract.',
  );

const processLocal = () =>
  effect(
    'shell.process.local',
    'allow',
    'shell.read_only',
    'A recognized command has only process-local effects.',
  );

const writesState = () =>
  effect(
    'shell.command.write',
    'review',
    'shell.write',
    'A recognized command may modify state.',
  );

const unknown = () =>
  effect(
    'shell.command.unknown',
    'review',
    'shell.unknown_semantics',
    'Command semantics are not statically established.',
  );

const sensitiveRead = () =>
  effect(
    'shell.filesystem.sensitive_read',
    'review',
    'shell.sensitive_read',
    'A command may read a sensitive filesystem resource.',
    'path',
  );

export function normalizeExecutable(
  executable: string | undefined,
): string | undefined {
  if (!executable || executable.includes('\0')) {
    return undefined;
  }
  if (executable.includes('/')) {
    if (
      !trustedBinaryPrefixes.some(
        (prefix) =>
          executable.startsWith(prefix) &&
          !executable.slice(prefix.length).includes('/'),
      )
    ) {
      return undefined;
    }
    return executable.slice(executable.lastIndexOf('/') + 1);
  }
  return /^[a-z0-9][a-z0-9._+-]*$/i.test(executable)
    ? executable
    : undefined;
}

function classifyPaths(paths: readonly (string | undefined)[]): AnalyzedEffect {
  if (paths.some((path) => path === undefined)) {
    return unknown();
  }
  return paths.some((path) => path !== undefined && isSensitivePath(path))
    ? sensitiveRead()
    : ordinaryRead();
}

function nonOptionArguments(
  args: readonly (string | undefined)[],
): readonly (string | undefined)[] {
  let optionsEnded = false;
  const operands: (string | undefined)[] = [];
  for (const argument of args) {
    if (argument === '--') {
      optionsEnded = true;
    } else if (
      argument === undefined ||
      optionsEnded ||
      !argument.startsWith('-') ||
      argument === '-'
    ) {
      operands.push(argument);
    }
  }
  return operands;
}

function applyContract(
  contract: CommandContract,
  args: readonly (string | undefined)[],
): AnalyzedEffect {
  if (contract.defaultEffect === 'write') {
    return writesState();
  }
  if (contract.defaultEffect === 'processLocal') {
    return processLocal();
  }
  if (contract.defaultEffect === 'unknown') {
    return unknown();
  }
  if (!contract.operandsAreFiles) {
    return ordinaryRead();
  }
  const operands = nonOptionArguments(args);
  if (contract.skipFirstOperand) {
    return operands.length <= 1
      ? ordinaryRead()
      : classifyPaths(operands.slice(1));
  }
  return classifyPaths(operands);
}

function versionOrHelpOnly(args: readonly (string | undefined)[]): boolean {
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

function analyzeGrep(args: readonly (string | undefined)[]): AnalyzedEffect {
  const operands = nonOptionArguments(args);
  if (operands.length <= 1) {
    return ordinaryRead();
  }
  return classifyPaths(operands.slice(1));
}

function analyzeHeadOrTail(
  args: readonly (string | undefined)[],
): AnalyzedEffect {
  const operands = nonOptionArguments(args).filter(
    (argument) => argument === undefined || !/^\+?-?\d+$/.test(argument),
  );
  return classifyPaths(operands);
}

function analyzeSort(args: readonly (string | undefined)[]): AnalyzedEffect {
  if (
    args.some(
      (argument) =>
        argument === '-o' ||
        argument === '--output' ||
        argument?.startsWith('--output='),
    )
  ) {
    return writesState();
  }
  return classifyPaths(nonOptionArguments(args));
}

function sedScriptMayWriteOrExecute(script: string): boolean {
  let index = 0;
  const skipDelimited = (delimiter: string): boolean => {
    while (index < script.length) {
      const character = script[index]!;
      if (character === '\\') {
        index += 2;
        continue;
      }
      index += 1;
      if (character === delimiter) {
        return true;
      }
      if (character === '\n') {
        return false;
      }
    }
    return false;
  };
  const skipToLineEnd = () => {
    while (index < script.length && script[index] !== '\n') {
      index += 1;
    }
  };

  while (index < script.length) {
    const character = script[index]!;
    if (/[\s;,!$~+]/.test(character)) {
      index += 1;
      continue;
    }
    if (/\d/.test(character)) {
      index += 1;
      continue;
    }
    if (character === '/') {
      index += 1;
      if (!skipDelimited('/')) {
        return true;
      }
      while (index < script.length && /[IM]/.test(script[index]!)) {
        index += 1;
      }
      continue;
    }
    if (character === '\\') {
      const delimiter = script[index + 1];
      if (delimiter === undefined) {
        return true;
      }
      index += 2;
      if (!skipDelimited(delimiter)) {
        return true;
      }
      continue;
    }
    if (character === '{' || character === '}') {
      index += 1;
      continue;
    }
    if (character === '#') {
      skipToLineEnd();
      continue;
    }
    if (character === 'w' || character === 'W' || character === 'e') {
      return true;
    }
    if (character === 's' || character === 'y') {
      const delimiter = script[index + 1];
      if (delimiter === undefined || delimiter === '\n') {
        return true;
      }
      index += 2;
      if (!skipDelimited(delimiter) || !skipDelimited(delimiter)) {
        return true;
      }
      if (character === 's') {
        while (index < script.length && !/[;\n]/.test(script[index]!)) {
          const flag = script[index]!;
          if (flag === 'w' || flag === 'e') {
            return true;
          }
          if (!/[\dgimpIM\s]/.test(flag)) {
            return true;
          }
          index += 1;
        }
      }
      continue;
    }
    if (character === 'a' || character === 'i' || character === 'c') {
      index += 1;
      while (index < script.length) {
        if (script[index] === '\\') {
          index += 2;
          continue;
        }
        if (script[index] === '\n') {
          break;
        }
        index += 1;
      }
      continue;
    }
    if (/[btT:]/.test(character)) {
      index += 1;
      while (index < script.length && !/[;\n]/.test(script[index]!)) {
        index += 1;
      }
      continue;
    }
    if (character === 'r' || character === 'R') {
      index += 1;
      skipToLineEnd();
      continue;
    }
    if (/[pPdDgGhHxnNlq=zF]/.test(character) || character === 'Q') {
      index += 1;
      continue;
    }
    return true;
  }
  return false;
}

const safeSedShortFlags = new Set(['n', 'r', 'E', 's', 'z', 'u']);

function analyzeSed(args: readonly (string | undefined)[]): AnalyzedEffect {
  const scripts: (string | undefined)[] = [];
  const operands: (string | undefined)[] = [];
  let expressionSeen = false;
  let optionsEnded = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      return unknown();
    }
    if (optionsEnded || !argument.startsWith('-') || argument === '-') {
      operands.push(argument);
      continue;
    }
    if (argument === '--') {
      optionsEnded = true;
      continue;
    }
    if (argument.startsWith('--')) {
      if (argument === '--in-place' || argument.startsWith('--in-place=')) {
        return writesState();
      }
      if (argument === '--file' || argument.startsWith('--file=')) {
        return unknown();
      }
      if (argument === '--expression') {
        expressionSeen = true;
        scripts.push(args[index + 1]);
        index += 1;
        continue;
      }
      if (argument.startsWith('--expression=')) {
        expressionSeen = true;
        scripts.push(argument.slice('--expression='.length));
        continue;
      }
      continue;
    }
    for (let position = 1; position < argument.length; position += 1) {
      const flag = argument[position]!;
      if (flag === 'i') {
        return writesState();
      }
      if (flag === 'f') {
        return unknown();
      }
      if (flag === 'e') {
        expressionSeen = true;
        const attached = argument.slice(position + 1);
        if (attached.length > 0) {
          scripts.push(attached);
        } else {
          scripts.push(args[index + 1]);
          index += 1;
        }
        break;
      }
      if (!safeSedShortFlags.has(flag)) {
        return unknown();
      }
    }
  }
  const scriptTexts = expressionSeen ? scripts : operands.slice(0, 1);
  const fileOperands = expressionSeen ? operands : operands.slice(1);
  if (scriptTexts.some((script) => script === undefined)) {
    return unknown();
  }
  if (
    scriptTexts.some(
      (script) => script !== undefined && sedScriptMayWriteOrExecute(script),
    )
  ) {
    return writesState();
  }
  return classifyPaths(fileOperands);
}

function analyzeAwk(args: readonly (string | undefined)[]): AnalyzedEffect {
  if (
    args.some(
      (argument) =>
        argument !== undefined &&
        (/^-f/.test(argument) ||
          /^--(?:exec|file|include|load|source)(?:=|$)/.test(argument) ||
          argument === '-E' ||
          argument === '-i' ||
          argument === '-l'),
    )
  ) {
    return unknown();
  }
  const operands = operandsWithOptionValues(
    args,
    new Set(['-F', '-v', '-W', '--assign', '--field-separator']),
  );
  const program = operands[0];
  if (
    program === undefined ||
    /\bsystem\s*\(|\|\s*getline\b|\|&|(?:^|[;{])\s*(?:print|printf)\b[^}\n]*[>|]/.test(
      program,
    )
  ) {
    return unknown();
  }
  return operands.length <= 1
    ? ordinaryRead()
    : classifyPaths(operands.slice(1));
}

const systemctlReadSubcommands = new Set([
  'cat',
  'get-default',
  'help',
  'is-active',
  'is-enabled',
  'is-failed',
  'is-system-running',
  'list-dependencies',
  'list-jobs',
  'list-machines',
  'list-sockets',
  'list-timers',
  'list-unit-files',
  'list-units',
  'show',
  'show-environment',
  'status',
]);

function analyzeSystemctl(
  args: readonly (string | undefined)[],
): AnalyzedEffect {
  const subcommand = args.find(
    (argument) => argument !== undefined && !argument.startsWith('-'),
  );
  if (
    !subcommand &&
    args.some((argument) =>
      ['--all', '--failed', '--state', '--type'].some(
        (flag) => argument === flag || argument?.startsWith(`${flag}=`),
      ),
    )
  ) {
    return ordinaryRead();
  }
  return subcommand && systemctlReadSubcommands.has(subcommand)
    ? ordinaryRead()
    : writesState();
}

const ipReadSubcommands = new Set([
  'get',
  'help',
  'list',
  'lst',
  'save',
  'show',
]);

function analyzeIp(args: readonly (string | undefined)[]): AnalyzedEffect {
  if (args.some((argument) => argument === undefined)) {
    return unknown();
  }
  const operands = args.filter(
    (argument): argument is string =>
      argument !== undefined && !argument.startsWith('-'),
  );
  if (operands.length < 2) {
    return ordinaryRead();
  }
  return ipReadSubcommands.has(operands[1]!) ? ordinaryRead() : writesState();
}

function analyzeTc(args: readonly (string | undefined)[]): AnalyzedEffect {
  if (args.some((argument) => argument === undefined)) {
    return unknown();
  }
  const operands = args.filter(
    (argument): argument is string =>
      argument !== undefined && !argument.startsWith('-'),
  );
  return operands.includes('show') || operands.includes('list')
    ? ordinaryRead()
    : writesState();
}

const findMutatingExpressions = new Set([
  '-delete',
  '-exec',
  '-execdir',
  '-fls',
  '-fprintf',
  '-fprint',
  '-fprint0',
  '-ok',
  '-okdir',
]);

function analyzeFind(args: readonly (string | undefined)[]): AnalyzedEffect {
  if (args.some((argument) => findMutatingExpressions.has(argument ?? ''))) {
    return writesState();
  }
  if (args.some((argument) => argument === undefined)) {
    return unknown();
  }
  const paths: string[] = [];
  for (const argument of args) {
    if (argument?.startsWith('-')) {
      break;
    }
    if (argument !== undefined) {
      paths.push(argument);
    }
  }
  return classifyPaths(paths);
}

function analyzeIptables(
  args: readonly (string | undefined)[],
): AnalyzedEffect {
  if (args.some((argument) => argument === undefined)) {
    return unknown();
  }
  const mutationLong = [
    '--append',
    '--delete',
    '--delete-chain',
    '--flush',
    '--insert',
    '--new-chain',
    '--policy',
    '--rename-chain',
    '--replace',
    '--zero',
  ];
  let reads = false;
  for (const argument of args) {
    if (!argument) {
      continue;
    }
    if (
      mutationLong.some(
        (option) => argument === option || argument.startsWith(`${option}=`),
      ) ||
      (/^-[^-]/.test(argument) && /[AIDRXPZFNE]/.test(argument.slice(1)))
    ) {
      return writesState();
    }
    if (
      ['--check', '--list', '--list-rules'].some(
        (option) => argument === option || argument.startsWith(`${option}=`),
      ) ||
      (/^-[^-]/.test(argument) && /[LSC]/.test(argument.slice(1)))
    ) {
      reads = true;
    }
  }
  return reads ? ordinaryRead() : unknown();
}

function analyzeNft(args: readonly (string | undefined)[]): AnalyzedEffect {
  if (args.some((argument) => argument === undefined)) {
    return unknown();
  }
  const subcommand = args.find(
    (argument) => argument !== undefined && !argument.startsWith('-'),
  );
  return subcommand === 'list' ? ordinaryRead() : writesState();
}

function operandsWithOptionValues(
  args: readonly (string | undefined)[],
  valueOptions: ReadonlySet<string>,
): readonly (string | undefined)[] {
  const operands: (string | undefined)[] = [];
  let optionsEnded = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!optionsEnded && argument === '--') {
      optionsEnded = true;
    } else if (!optionsEnded && argument && valueOptions.has(argument)) {
      index += 1;
    } else if (
      argument === undefined ||
      optionsEnded ||
      !argument.startsWith('-')
    ) {
      operands.push(argument);
    }
  }
  return operands;
}

const dateValueOptions = new Set([
  '-d',
  '--date',
  '-r',
  '--reference',
  '-f',
  '--file',
]);

function analyzeDate(args: readonly (string | undefined)[]): AnalyzedEffect {
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      return unknown();
    }
    if (
      argument === '-s' ||
      argument === '--set' ||
      argument.startsWith('--set=')
    ) {
      return writesState();
    }
    if (argument.startsWith('+')) {
      continue;
    }
    if (dateValueOptions.has(argument)) {
      index += 1;
      continue;
    }
    if (argument.startsWith('-')) {
      continue;
    }
    return writesState();
  }
  return processLocal();
}

const gitValueOptions = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--exec-path',
  '--super-prefix',
]);

const gitReadSubcommands = new Set([
  'blame',
  'cat-file',
  'describe',
  'diff',
  'grep',
  'help',
  'log',
  'ls-files',
  'ls-remote',
  'ls-tree',
  'rev-parse',
  'show',
  'status',
  'version',
]);

function analyzeGit(args: readonly (string | undefined)[]): AnalyzedEffect {
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      return unknown();
    }
    if (gitValueOptions.has(argument)) {
      index += 1;
      continue;
    }
    if (argument.startsWith('-')) {
      continue;
    }
    return gitReadSubcommands.has(argument) ? ordinaryRead() : writesState();
  }
  return writesState();
}

function analyzeCrontab(args: readonly (string | undefined)[]): AnalyzedEffect {
  let listing = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      return unknown();
    }
    if (argument === '-l') {
      listing = true;
      continue;
    }
    if (argument === '-u') {
      index += 1;
      continue;
    }
    return writesState();
  }
  return listing ? ordinaryRead() : writesState();
}

const dockerValueOptions = new Set([
  '--config',
  '--context',
  '-H',
  '--host',
  '-l',
  '--log-level',
]);

const dockerReadSubcommands = new Set([
  'df',
  'diff',
  'events',
  'history',
  'images',
  'info',
  'inspect',
  'logs',
  'port',
  'ps',
  'search',
  'stats',
  'top',
  'version',
]);

const dockerNamespaceReads: Readonly<Record<string, ReadonlySet<string>>> = {
  compose: new Set(['config', 'images', 'logs', 'ps', 'top', 'version']),
  container: new Set([
    'diff',
    'inspect',
    'logs',
    'ls',
    'port',
    'stats',
    'top',
  ]),
  image: new Set(['history', 'inspect', 'ls']),
  network: new Set(['inspect', 'ls']),
  volume: new Set(['inspect', 'ls']),
};

function analyzeDocker(args: readonly (string | undefined)[]): AnalyzedEffect {
  const operands = operandsWithOptionValues(args, dockerValueOptions);
  if (operands.some((operand) => operand === undefined)) {
    return unknown();
  }
  const strings = operands as readonly string[];
  const first = strings[0];
  if (first && dockerReadSubcommands.has(first)) {
    return ordinaryRead();
  }
  return first && strings[1] && dockerNamespaceReads[first]?.has(strings[1])
    ? ordinaryRead()
    : writesState();
}

function onlyReadSubcommands(
  args: readonly (string | undefined)[],
  subcommands: ReadonlySet<string>,
): AnalyzedEffect {
  if (args.some((argument) => argument === undefined)) {
    return unknown();
  }
  const subcommand = args.find(
    (argument) => argument !== undefined && !argument.startsWith('-'),
  );
  return subcommand && subcommands.has(subcommand)
    ? ordinaryRead()
    : writesState();
}

const curlMutatingOptions = new Set([
  '--anyauth',
  '--aws-sigv4',
  '--basic',
  '--config',
  '--cookie',
  '--cookie-jar',
  '--data',
  '--data-ascii',
  '--data-binary',
  '--data-raw',
  '--digest',
  '--form',
  '--json',
  '--negotiate',
  '--netrc',
  '--netrc-file',
  '--oauth2-bearer',
  '--output',
  '--proxy-header',
  '--proxy-user',
  '--request-target',
  '--upload-file',
  '--user',
  '-F',
  '-T',
  '-b',
  '-c',
  '-d',
  '-n',
  '-o',
  '-u',
]);

const safeCurlLongOptions = new Set([
  '--compressed',
  '--fail',
  '--fail-with-body',
  '--location',
  '--no-progress-meter',
  '--silent',
  '--show-error',
  '--verbose',
]);

function analyzeCurl(args: readonly (string | undefined)[]): AnalyzedEffect {
  let method = 'GET';
  let optionsEnded = false;
  let url: string | undefined;
  const nextValue = (index: number) => args[index + 1];

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      return unknown();
    }
    if (optionsEnded || !argument.startsWith('-') || argument === '-') {
      if (url !== undefined) {
        return unknown();
      }
      url = argument;
      continue;
    }
    if (argument === '--') {
      optionsEnded = true;
      continue;
    }

    const [option, attachedValue] = argument.startsWith('--')
      ? argument.split(/=(.*)/s, 2)
      : [argument, undefined];
    if (option === '-I' || option === '--head') {
      method = 'HEAD';
      continue;
    }
    if (option === '-G' || option === '--get') {
      method = 'GET';
      continue;
    }
    if (option === '-X' || option === '--request') {
      const value = attachedValue ?? nextValue(index);
      if (attachedValue === undefined) {
        index += 1;
      }
      if (!value) {
        return unknown();
      }
      method = value.toUpperCase();
      continue;
    }
    if (option === '--url') {
      const value = attachedValue ?? nextValue(index);
      if (attachedValue === undefined) {
        index += 1;
      }
      if (!value || url !== undefined) {
        return unknown();
      }
      url = value;
      continue;
    }
    if (option === '-H' || option === '--header') {
      const value = attachedValue ?? nextValue(index);
      if (attachedValue === undefined) {
        index += 1;
      }
      if (!value || isSensitiveHeader(value)) {
        return {
          ...sensitiveRead(),
          effectCode: 'shell.http.sensitive',
          summary: 'An HTTP request may expose sensitive authentication data.',
        };
      }
      continue;
    }
    if (
      curlMutatingOptions.has(option) ||
      /^-[^-]*[FTbcCdDkKnoOu]/.test(option)
    ) {
      return writesState();
    }
    if (option.startsWith('--') && !safeCurlLongOptions.has(option)) {
      return unknown();
    }
    if (
      option.startsWith('-') &&
      !/^-[fLsSv]+$/.test(option)
    ) {
      return unknown();
    }
  }

  if (!url || (method !== 'GET' && method !== 'HEAD')) {
    return writesState();
  }
  if (
    hasUrlCredentials(url) ||
    /(?:^|[?&])(?:access_token|api[_-]?key|auth|password|secret|token)=/i.test(
      url,
    ) ||
    /^(?:https?:\/\/)?169\.254\.169\.254(?:\/|$)/i.test(url)
  ) {
    return {
      ...sensitiveRead(),
      effectCode: 'shell.http.sensitive',
      summary: 'An HTTP request may access or expose a sensitive resource.',
    };
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return unknown();
    }
  } catch {
    return unknown();
  }
  return {
    ...ordinaryRead(),
    effectCode: 'shell.http.read',
    summary: 'A static HTTP GET or HEAD request has a read-only contract.',
  };
}

function wrappedCommand(
  args: readonly (string | undefined)[],
  wrapper: string,
): ShellCommandIr | undefined {
  let index = 0;
  const skipValue = new Set<string>();
  if (wrapper === 'sudo') {
    for (const option of ['-C', '-D', '-R', '-T', '-g', '-h', '-p', '-u']) {
      skipValue.add(option);
    }
  } else if (wrapper === 'nice') {
    skipValue.add('-n');
    skipValue.add('--adjustment');
  } else if (wrapper === 'ionice') {
    for (const option of ['-c', '-n', '-t']) {
      skipValue.add(option);
    }
  } else if (wrapper === 'timeout') {
    for (const option of ['-k', '--kill-after', '-s', '--signal']) {
      skipValue.add(option);
    }
  } else if (wrapper === 'stdbuf') {
    for (const option of ['-e', '-i', '-o']) {
      skipValue.add(option);
    }
  } else if (wrapper === 'watch') {
    skipValue.add('-n');
    skipValue.add('--interval');
  }

  if (wrapper === 'env') {
    while (index < args.length) {
      const argument = args[index];
      if (argument === undefined) {
        return undefined;
      }
      if (argument === '--') {
        index += 1;
        break;
      }
      if (argument === '-u' || argument === '--unset') {
        index += 2;
        continue;
      }
      if (
        argument === '-i' ||
        argument === '--ignore-environment' ||
        argument.startsWith('--unset=')
      ) {
        index += 1;
        continue;
      }
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argument)) {
        if (/^(?:BASH_ENV|ENV|LD_|PATH=|PYTHONPATH=|SHELLOPTS=)/.test(argument)) {
          return undefined;
        }
        index += 1;
        continue;
      }
      break;
    }
  } else {
    while (index < args.length) {
      const argument = args[index];
      if (argument === undefined) {
        return undefined;
      }
      if (argument === '--') {
        index += 1;
        break;
      }
      if (
        wrapper === 'time' &&
        (argument === '-o' ||
          argument === '-a' ||
          argument === '--output' ||
          argument.startsWith('--output=') ||
          argument === '--append')
      ) {
        return undefined;
      }
      if (wrapper === 'timeout' && !argument.startsWith('-')) {
        index += 1;
        break;
      }
      if (skipValue.has(argument)) {
        index += 2;
        continue;
      }
      if (
        argument.startsWith('-') &&
        !/^-\d+$/.test(argument) &&
        !argument.includes('=')
      ) {
        index += 1;
        continue;
      }
      if (
        argument.startsWith('--') ||
        (wrapper === 'nice' && /^-\d+$/.test(argument))
      ) {
        index += 1;
        continue;
      }
      break;
    }
  }

  const name = args[index];
  if (!name) {
    return undefined;
  }
  return { name, arguments: args.slice(index + 1) };
}

const kubectlReadSubcommands = new Set([
  'api-resources',
  'api-versions',
  'cluster-info',
  'describe',
  'explain',
  'get',
  'logs',
  'top',
  'version',
]);

const virshReadSubcommands = new Set([
  'capabilities',
  'dominfo',
  'domstate',
  'domstats',
  'dumpxml',
  'list',
  'nodeinfo',
  'nodememstats',
  'version',
]);

const systemdControlReadSubcommands = new Set([
  'status',
  'show',
  'list-timezones',
  'list-locales',
  'list-keymaps',
  'help',
]);

const aptReadSubcommands = new Set([
  'changelog',
  'depends',
  'list',
  'policy',
  'search',
  'show',
]);

const yumReadSubcommands = new Set(['info', 'list', 'search']);

const npmReadSubcommands = new Set([
  'list',
  'ls',
  'outdated',
  'ping',
  'show',
  'view',
]);

export interface ShellContractHooks {
  readonly analyzeNestedShell: (
    sourceText: string,
    nestingDepth: number,
  ) => Promise<readonly AnalyzedEffect[]>;
  readonly analyzeEmbedded?: (
    command: ShellCommandIr,
  ) => Promise<readonly AnalyzedEffect[] | undefined>;
}

export async function analyzeShellCommand(
  command: ShellCommandIr,
  hooks?: ShellContractHooks,
  wrapperDepth = 0,
  normalizedName = normalizeExecutable(command.name),
): Promise<readonly AnalyzedEffect[]> {
  const name = normalizedName;
  if (!name) {
    return [unknown()];
  }
  const args = command.arguments;
  if (wrapperDepth > 16) {
    return [unknown()];
  }

  const unwrap = async (
    child: ShellCommandIr | undefined,
  ): Promise<readonly AnalyzedEffect[]> => {
    if (!child) {
      return [unknown()];
    }
    const embedded = await hooks?.analyzeEmbedded?.(child);
    return (
      embedded ?? analyzeShellCommand(child, hooks, wrapperDepth + 1)
    );
  };

  if (/^mkfs(?:\.|$)/.test(name)) {
    return [writesState()];
  }
  const contract = commandContracts.get(name);
  if (contract) {
    return [applyContract(contract, args)];
  }

  switch (name) {
    case 'grep':
    case 'egrep':
    case 'fgrep':
    case 'rg':
      return [analyzeGrep(args)];
    case 'head':
    case 'tail':
      return [analyzeHeadOrTail(args)];
    case 'sort':
      return [analyzeSort(args)];
    case 'sed':
      return [analyzeSed(args)];
    case 'awk':
    case 'gawk':
    case 'mawk':
    case 'nawk':
      return [analyzeAwk(args)];
    case 'find':
      return [analyzeFind(args)];
    case 'systemctl':
      return [analyzeSystemctl(args)];
    case 'ip':
      return [analyzeIp(args)];
    case 'tc':
      return [analyzeTc(args)];
    case 'iptables':
    case 'ip6tables':
      return [analyzeIptables(args)];
    case 'nft':
      return [analyzeNft(args)];
    case 'docker':
    case 'nerdctl':
    case 'podman':
      return [analyzeDocker(args)];
    case 'kubectl':
      return [onlyReadSubcommands(args, kubectlReadSubcommands)];
    case 'virsh':
      return [onlyReadSubcommands(args, virshReadSubcommands)];
    case 'curl':
      return [analyzeCurl(args)];
    case 'ss':
      return [
        args.some((argument) => argument === undefined)
          ? unknown()
          : args.some(
                (argument) =>
                  argument === '--kill' || /^-[^-]*K/.test(argument ?? ''),
              )
            ? writesState()
            : ordinaryRead(),
      ];
    case 'hostname':
      return [
        args.some((argument) => argument === undefined)
          ? unknown()
          : args.some(
                (argument) =>
                  argument !== undefined &&
                  (!argument.startsWith('-') ||
                    argument === '-F' ||
                    argument === '--file' ||
                    argument === '-b'),
              )
            ? writesState()
            : processLocal(),
      ];
    case 'date':
      return [analyzeDate(args)];
    case 'git':
      return [analyzeGit(args)];
    case 'crontab':
      return [analyzeCrontab(args)];
    case 'hostnamectl':
    case 'timedatectl':
    case 'localectl':
      return [onlyReadSubcommands(args, systemdControlReadSubcommands)];
    case 'sysctl':
      return [
        args.some((argument) => argument === undefined)
          ? unknown()
          : args.some(
                (argument) =>
                  argument === '-w' ||
                  argument === '--write' ||
                  argument === '-p' ||
                  argument === '--load' ||
                  argument === '--system' ||
                  argument?.includes('='),
              )
            ? writesState()
            : ordinaryRead(),
      ];
    case 'busybox': {
      const childName = args[0];
      return childName
        ? unwrap({ name: childName, arguments: args.slice(1) })
        : [unknown()];
    }
    case 'command': {
      if (
        args.some((argument) => argument === '-v' || argument === '-V') &&
        !args.some((argument) => argument === undefined)
      ) {
        return [processLocal()];
      }
      return unwrap(wrappedCommand(args, name));
    }
    case 'builtin':
    case 'ionice':
    case 'nice':
    case 'nohup':
    case 'setsid':
    case 'stdbuf':
    case 'sudo':
    case 'time':
    case 'timeout':
    case 'watch':
      return unwrap(wrappedCommand(args, name));
    case 'env': {
      const child = wrappedCommand(args, name);
      if (child) {
        return unwrap(child);
      }
      return [
        args.every(
          (argument) =>
            argument !== undefined &&
            !/^(?:BASH_ENV|ENV|LD_|PATH=|PYTHONPATH=|SHELLOPTS=)/.test(
              argument,
            ),
        )
          ? processLocal()
          : unknown(),
      ];
    }
    case 'bash':
    case 'sh': {
      const codeIndex = args.findIndex(
        (argument) =>
          argument !== undefined && /^-[A-Za-z]*c[A-Za-z]*$/.test(argument),
      );
      const payload = codeIndex >= 0 ? args[codeIndex + 1] : undefined;
      return payload && hooks
        ? hooks.analyzeNestedShell(payload, wrapperDepth + 1)
        : [unknown()];
    }
    case 'eval':
    case 'exec':
    case 'source':
    case '.':
      return [unknown()];
    case 'journalctl':
      return [
        args.some((argument) =>
          [
            '--flush',
            '--relinquish-var',
            '--rotate',
            '--setup-keys',
            '--smart-relinquish-var',
            '--sync',
            '--update-catalog',
            '--vacuum-files',
            '--vacuum-size',
            '--vacuum-time',
          ].some(
            (flag) => argument === flag || argument?.startsWith(`${flag}=`),
          ),
        )
          ? writesState()
          : ordinaryRead(),
      ];
    case 'dmesg':
      return [
        args.some(
          (argument) =>
            argument === '--clear' ||
            argument === '--read-clear' ||
            /^-[^-]*[CcDEn]/.test(argument ?? ''),
        )
          ? writesState()
          : ordinaryRead(),
      ];
    case 'apt':
      return [onlyReadSubcommands(args, aptReadSubcommands)];
    case 'apt-get':
      return [
        args.some(
          (argument) =>
            argument === '-s' ||
            argument === '--simulate' ||
            argument === '--dry-run',
        )
          ? ordinaryRead()
          : writesState(),
      ];
    case 'yum':
      return [onlyReadSubcommands(args, yumReadSubcommands)];
    case 'npm':
      return [onlyReadSubcommands(args, npmReadSubcommands)];
    case 'openssl':
      return [
        nonOptionArguments(args)[0] === 'version' || versionOrHelpOnly(args)
          ? processLocal()
          : unknown(),
      ];
    default:
      return [versionOrHelpOnly(args) ? processLocal() : unknown()];
  }
}
