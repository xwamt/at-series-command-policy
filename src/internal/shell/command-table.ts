export type ContractEffect = 'read' | 'processLocal' | 'write' | 'unknown';

export interface CommandContract {
  readonly name: string;
  readonly defaultEffect: ContractEffect;
  readonly operandsAreFiles?: boolean;
  readonly skipFirstOperand?: boolean;
}

function family(
  defaultEffect: ContractEffect,
  names: readonly string[],
  shape: Pick<CommandContract, 'operandsAreFiles' | 'skipFirstOperand'> = {},
): readonly CommandContract[] {
  return names.map((name) => ({ name, defaultEffect, ...shape }));
}

const processLocalCommands = [
  ':',
  '[',
  'echo',
  'false',
  'groups',
  'id',
  'nproc',
  'printenv',
  'printf',
  'pwd',
  'test',
  'true',
  'uname',
  'uptime',
  'users',
  'who',
  'whoami',
];

const hostObserverCommands = [
  'blkid',
  'df',
  'dig',
  'free',
  'getconf',
  'getenforce',
  'host',
  'iostat',
  'ipcs',
  'last',
  'lastb',
  'logread',
  'lscpu',
  'lsblk',
  'lsof',
  'mpstat',
  'netstat',
  'nslookup',
  'pgrep',
  'pidof',
  'ps',
  'top',
  'vmstat',
  'w',
  'whereis',
  'which',
];

const fileReaderCommands = [
  'base32',
  'base64',
  'cat',
  'cksum',
  'cut',
  'du',
  'expand',
  'file',
  'fold',
  'hexdump',
  'ls',
  'lsattr',
  'md5sum',
  'namei',
  'nl',
  'od',
  'readlink',
  'realpath',
  'sha1sum',
  'sha256sum',
  'sha512sum',
  'stat',
  'strings',
  'tr',
  'tree',
  'unexpand',
  'uniq',
  'wc',
  'xxd',
];

const alwaysWriteCommands = [
  'chattr',
  'chgrp',
  'chmod',
  'chown',
  'cp',
  'dd',
  'install',
  'kill',
  'killall',
  'ln',
  'mkdir',
  'mkfifo',
  'mknod',
  'mv',
  'pkill',
  'reboot',
  'rename',
  'rm',
  'rmdir',
  'rsync',
  'shutdown',
  'sudoedit',
  'tee',
  'touch',
  'truncate',
  'unlink',
  'useradd',
  'userdel',
  'usermod',
];

export const commandContracts: ReadonlyMap<string, CommandContract> = new Map(
  [
    ...family('processLocal', processLocalCommands),
    ...family('read', hostObserverCommands),
    ...family('read', fileReaderCommands, { operandsAreFiles: true }),
    ...family('read', ['jq'], {
      operandsAreFiles: true,
      skipFirstOperand: true,
    }),
    ...family('write', alwaysWriteCommands),
  ].map((contract) => [contract.name, contract]),
);
