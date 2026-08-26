import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const [sourcePath, destinationPath] = process.argv.slice(2);
if (!sourcePath || !destinationPath) {
  throw new Error(
    'Usage: node scripts/generate-redacted-replay.mjs <source.jsonl> <destination.json>',
  );
}

const canonicalPaths = new Set([
  '/dev/null',
  '/etc/hosts',
  '/etc/os-release',
  '/etc/passwd',
  '/etc/shadow',
  '/proc/cpuinfo',
  '/proc/meminfo',
  '/var/log/messages',
  '/var/log/syslog',
]);

function sanitizedPath(path) {
  if (canonicalPaths.has(path)) {
    return path;
  }
  if (/^\/proc\/(?:\*|\d+|self)(?:\/|$)/.test(path)) {
    return path.replace(/\/\d+\//g, '/1/');
  }
  if (/^\/sys\//.test(path)) {
    return path
      .replace(/\/net\/[^/]+/g, '/net/eth0')
      .replace(/\/brif\/[^/]+/g, '/brif/eth1');
  }
  if (/^\/var\/log(?:\/|$)/.test(path)) {
    const extension = /\.[a-z0-9]+$/i.exec(path)?.[0] ?? '.log';
    return `/var/log/service/application${extension}`;
  }
  if (/^\/etc(?:\/|$)/.test(path)) {
    return '/etc/service/config';
  }
  if (/^\/(?:Users|home|root)(?:\/|$)/.test(path)) {
    return '/home/operator/workspace';
  }
  if (/^\/tmp(?:\/|$)/.test(path)) {
    return '/tmp/generated';
  }
  if (/^\/(?:opt|srv|var\/lib|var\/www)(?:\/|$)/.test(path)) {
    return '/srv/application';
  }
  return '/path/resource';
}

function sanitizeCommand(rawCommand) {
  let command = rawCommand
    .replace(/^#\s*Purpose:[^\r\n]*(?:\r?\n|$)/gim, '# Purpose: [redacted]\n')
    .replace(
      /\bhttps?:\/\/[^\s"'`|;]+/gi,
      'https://example.invalid/resource',
    )
    .replace(
      /\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){2,3}\b/g,
      '198.51.100.10',
    )
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
      '[id]',
    )
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, 'user@example.invalid')
    .replace(
      /\b(Authorization|Proxy-Authorization|Cookie|X-Api-Key):[^\r\n"']*/gi,
      '$1: [redacted]',
    )
    .replace(
      /\b(password|passwd|token|secret|api[_-]?key)=([^\s"'&;]+)/gi,
      '$1=[redacted]',
    )
    .replace(
      /\/(?:[A-Za-z0-9._*?[\]{}:+@%-]+\/)*[A-Za-z0-9._*?[\]{}:+@%-]*/g,
      (path) => sanitizedPath(path),
    )
    .replace(
      /\b(systemctl\s+(?:status|show|is-active|is-enabled|restart|reload|stop|start|enable|disable)\s+)[^\s;|&]+/gi,
      '$1service',
    )
    .replace(/\b(journalctl\s+-u\s+)[^\s;|&]+/gi, '$1service')
    .replace(/\b(service\s+)[^\s;|&]+/gi, '$1service')
    .replace(/\b(dev\s+)[A-Za-z0-9_.:@-]+/g, '$1eth0')
    .replace(/\b(br-|veth|ens|enp|eth)\w+/gi, 'eth0')
    .replace(/\b[0-9a-f]{24,}\b/gi, '[value]')
    .replace(/[ \t]+\n/g, '\n')
    .trim();

  if (!command) {
    command = '# Purpose: [redacted]\ntrue';
  }
  return command;
}

function categoryFor(command) {
  if (
    /(?:^|[;&|]\s*)(?:rm|mv|cp|tee|touch|mkdir|chmod|chown|kill|pkill|useradd|apt|yum)\b/im.test(
      command,
    ) ||
    /\bsystemctl\s+(?:start|stop|restart|reload|enable|disable|daemon-reload)\b/i.test(
      command,
    ) ||
    /\btc\b[^\n;]*(?:add|change|del|delete|replace)\b/i.test(command) ||
    /\bip\b[^\n;]*(?:add|delete|del|replace|set|flush)\b/i.test(command) ||
    /\b(?:UPDATE|INSERT|DELETE|CREATE|DROP|ALTER|ATTACH)\b/i.test(command) ||
    /\bcurl\b[^\n;]*(?:-d|--data|-X\s+(?:POST|PUT|PATCH|DELETE)|--upload-file|-T)\b/i.test(
      command,
    ) ||
    /(?:^|[^<])>{1,2}\s*(?!\/dev\/null)/m.test(command)
  ) {
    return 'state_modification';
  }
  if (
    /\/etc\/shadow|\/etc\/gshadow|\.env|\.ssh|credential|password|api[_-]?key|private[_-]?key|Authorization:/i.test(
      command,
    )
  ) {
    return 'sensitive_read';
  }
  if (
    /\b(?:eval|source|exec|xargs)\b|\$\{!?[A-Za-z_]|\$\(\s*\$\{|\/path\/resource/i.test(
      command,
    )
  ) {
    return 'unknown';
  }
  return 'ordinary_query';
}

const lines = (await readFile(resolve(sourcePath), 'utf8'))
  .split(/\r?\n/)
  .filter(Boolean);
const records = [];
for (const line of lines) {
  const record = JSON.parse(line);
  if (
    record?.toolName === 'run_remote_command' &&
    typeof record?.params?.command === 'string'
  ) {
    records.push(record.params.command);
  }
}

if (records.length < 86) {
  throw new Error(`Expected at least 86 command records, received ${records.length}`);
}

const fixture = records.slice(0, 86).map((rawCommand, index) => {
  const commandShape = sanitizeCommand(rawCommand);
  const category = categoryFor(commandShape);
  return {
    id: `rrc-${String(index + 1).padStart(3, '0')}`,
    commandShape,
    category,
    expectedAction: category === 'ordinary_query' ? 'allow' : 'review',
  };
});

await writeFile(resolve(destinationPath), `${JSON.stringify(fixture, null, 2)}\n`);

const counts = Object.fromEntries(
  ['ordinary_query', 'sensitive_read', 'state_modification', 'unknown'].map(
    (category) => [
      category,
      fixture.filter((entry) => entry.category === category).length,
    ],
  ),
);
console.log(JSON.stringify({ sourceRecords: records.length, emitted: 86, counts }));
