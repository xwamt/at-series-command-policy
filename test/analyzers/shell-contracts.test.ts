import assert from 'node:assert/strict';
import test from 'node:test';

import { createShellPolicyEvaluator } from '../../src/shell.ts';

const evaluator = createShellPolicyEvaluator();

async function action(sourceText: string) {
  return (await evaluator.evaluate({ sourceText })).action;
}

test('allows the migrated at-terminal observer and transform surface', async () => {
  const commands = [
    'ls -la /var/log',
    'cat /etc/hosts',
    'tail -n 100 /var/log/service/error.log',
    'grep -n error /var/log/syslog',
    'df -h',
    'du -sh /var/log',
    'free -m',
    'netstat -tulnp | grep 8080',
    'iostat -x 1 3',
    'pgrep -a service',
    'stat /etc/hosts',
    'sort /var/log/sizes | uniq -c | head',
    'find /var/log -name "*.log" -mtime -1',
    "awk 'NR>1 {print $4}' /var/log/metrics.log",
    "sed -n '1,5p' /etc/hosts",
    '/usr/bin/uptime',
    'logread | tail -n 30',
    'which nginx',
    'command -v nginx',
    'hostname -f',
    'date +%s',
    'git status --short',
    'crontab -l',
  ];
  for (const command of commands) {
    assert.equal(await action(command), 'allow', command);
  }
});

test('reviews writes and command-specific mutation variants', async () => {
  const commands = [
    'rm -rf /tmp/generated',
    'mv a b',
    'cp -r a b',
    'tee /tmp/out',
    'chmod 600 /tmp/key',
    'kill -9 1234',
    'find / -delete',
    'find / -name x -exec rm {} \\;',
    'sed -i s/a/b/ /etc/hosts',
    "awk 'BEGIN{system(\"rm -rf /tmp/generated\")}'",
    'sort -o /tmp/out /var/log/sizes',
    'ss --kill dst 10.0.0.1',
    'git push',
    'date -s "2020-01-01 00:00:00"',
    'hostname web01',
    'crontab jobs.txt',
  ];
  for (const command of commands) {
    assert.equal(await action(command), 'review', command);
  }
});

test('separates read-only service and network forms from controls', async () => {
  const cases = [
    ['systemctl status service', 'allow'],
    ['systemctl --failed --no-pager', 'allow'],
    ['systemctl restart service', 'review'],
    ['journalctl -u service -n 50', 'allow'],
    ['journalctl --vacuum-size=1M', 'review'],
    ['ip addr show', 'allow'],
    ['ip -br addr', 'allow'],
    ['ip link set eth0 down', 'review'],
    ['tc -s qdisc show dev eth0', 'allow'],
    ['tc qdisc replace dev eth0 root fq', 'review'],
    ['iptables -nvL', 'allow'],
    ['iptables -A INPUT -j DROP', 'review'],
    ['nft list ruleset', 'allow'],
    ['nft flush ruleset', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('separates read-only container forms from controls', async () => {
  const cases = [
    ['docker ps --format "{{.Names}}"', 'allow'],
    ['docker inspect app', 'allow'],
    ['docker compose ps', 'allow'],
    ['docker run image', 'review'],
    ['docker exec app sh', 'review'],
    ['kubectl get pods', 'allow'],
    ['kubectl describe node worker', 'allow'],
    ['kubectl apply -f deployment.yaml', 'review'],
    ['virsh list --all', 'allow'],
    ['virsh destroy guest', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('recursively analyzes recognized static wrappers', async () => {
  const cases = [
    ['sudo -- systemctl status service', 'allow'],
    ['sudo systemctl restart service', 'review'],
    ['env LANG=C ls /var/log', 'allow'],
    ['command -- cat /etc/hosts', 'allow'],
    ['nice -n 5 ps aux', 'allow'],
    ['timeout 5s journalctl -n 5', 'allow'],
    ['busybox cat /etc/hosts', 'allow'],
    ['busybox rm /tmp/generated', 'review'],
    ["bash -c 'uname -a; uptime'", 'allow'],
    ["sh -c 'rm /tmp/generated'", 'review'],
    ['bash -c "$SCRIPT"', 'review'],
    ['eval "uname -a"', 'review'],
    ['source /tmp/script', 'review'],
    ['exec uname -a', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('implements the strict curl method, body, output, and credential contract', async () => {
  const cases = [
    ['curl https://example.invalid/health', 'allow'],
    ['curl --head https://example.invalid/health', 'allow'],
    ['curl -X GET --url https://example.invalid/health', 'allow'],
    ['curl --request=HEAD https://example.invalid/health', 'allow'],
    ['curl -d value https://example.invalid/', 'review'],
    ['curl -X DELETE https://example.invalid/item', 'review'],
    ['curl -T /tmp/file https://example.invalid/', 'review'],
    ['curl -o /tmp/out https://example.invalid/', 'review'],
    [
      'curl -H "Authorization: Bearer redacted" https://example.invalid/',
      'review',
    ],
    ['curl https://user:password@example.invalid/', 'review'],
    ['curl http://169.254.169.254/latest/meta-data/', 'review'],
    ['curl --config /tmp/options', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('reviews sensitive paths, unknown commands, and executable masquerading', async () => {
  const commands = [
    'cat /etc/shadow',
    'cat ~/.ssh/id_ed25519',
    'grep token .env',
    '/tmp/systemctl status service',
    './inspect.sh',
    'custom-observer --status',
  ];
  for (const command of commands) {
    assert.equal(await action(command), 'review', command);
  }
});

test('preserves quoted multiline python payloads', async () => {
  assert.equal(
    await action(
      [
        'sudo python3 -c "',
        'import json',
        'print(json.loads(\'{"value": 1}\')["value"])',
        '"',
      ].join('\n'),
    ),
    'allow',
  );
});

test('classifies file operands of transform commands instead of allowing unconditionally', async () => {
  const cases = [
    ['wc -l /var/log/syslog', 'allow'],
    ['cut -d: -f1 /etc/hosts', 'allow'],
    ['tr -d x', 'allow'],
    ['uniq -c /var/log/list', 'allow'],
    ['jq .', 'allow'],
    ['jq .status /tmp/response.json', 'allow'],
    ['wc -l ~/.aws/credentials', 'review'],
    ['cut -c1 /root/.ssh/id_rsa', 'review'],
    ['jq .key ~/.kube/config', 'review'],
    ['uniq ~/.netrc', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('reviews awk and sed forms that execute commands or write files', async () => {
  const cases = [
    ['awk \'BEGIN{"id"|getline x; print x}\'', 'review'],
    ['awk \'BEGIN{"cmd" |& getline line}\'', 'review'],
    ['awk -f /tmp/prog.awk /etc/hosts', 'review'],
    ["awk '{print $1}' /etc/hosts", 'allow'],
    ["awk -F: '{print $1}' /var/log/report", 'allow'],
    ["awk -v limit=10 'NR<limit' /var/log/report", 'allow'],
    ["sed 'w /tmp/out' /etc/hosts", 'review'],
    ["sed -e 'w /tmp/out' /etc/hosts", 'review'],
    ["sed 's/a/b/w /tmp/out' /etc/hosts", 'review'],
    ["sed '1e touch /tmp/marker' /etc/hosts", 'review'],
    ['sed -f /tmp/script.sed /etc/hosts', 'review'],
    ["sed -i.bak 's/a/b/' /etc/hosts", 'review'],
    ["sed -n '1,5p' /etc/hosts", 'allow'],
    ["sed 's/error/warning/g' /var/log/syslog", 'allow'],
    ["sed -n -e '1p' -e '$p' /etc/hosts", 'allow'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('classifies paths for the read-only viewer and encoder commands', async () => {
  const cases = [
    ['xxd /etc/hosts', 'allow'],
    ['strings /etc/hosts', 'allow'],
    ['od -c /etc/hosts', 'allow'],
    ['hexdump -C /etc/hosts', 'allow'],
    ['base64 /etc/hosts', 'allow'],
    ['base32 /etc/hosts', 'allow'],
    ['nl /etc/hosts', 'allow'],
    ['fold -s /var/log/syslog', 'allow'],
    ['expand /tmp/notes.txt', 'allow'],
    ['unexpand /tmp/notes.txt', 'allow'],
    ['namei /var/log/syslog', 'allow'],
    ['tree /var/log', 'allow'],
    ['lsattr /tmp', 'allow'],
    ['xxd ~/.ssh/id_rsa', 'review'],
    ['strings /etc/shadow', 'review'],
    ['base64 ~/.aws/credentials', 'review'],
    ['less /etc/hosts', 'review'],
    ['more /etc/hosts', 'review'],
    ['view /etc/hosts', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('recursively analyzes the added wrappers while keeping xargs reviewed', async () => {
  const cases = [
    ['nohup uname -a', 'allow'],
    ['nohup rm -rf /tmp/generated', 'review'],
    ['setsid ps aux', 'allow'],
    ['time uname -a', 'allow'],
    ['time ls /var/log', 'allow'],
    ['time --output=/tmp/out ls', 'review'],
    ['watch -n 5 free -m', 'allow'],
    ['watch rm -rf /tmp/generated', 'review'],
    ['xargs cat', 'review'],
    ['xargs rm', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('treats bare env as process-local and finds -c inside short option clusters', async () => {
  const cases = [
    ['env', 'allow'],
    ['env LANG=C', 'allow'],
    ['env LD_PRELOAD=/tmp/x.so', 'review'],
    ['printenv', 'allow'],
    ['printenv HOME', 'allow'],
    ["bash -lc 'uname -a'", 'allow'],
    ["bash -xc 'uptime'", 'allow'],
    ["sh -euc 'uname -a'", 'allow'],
    ["bash -lc 'rm -rf /tmp/generated'", 'review'],
    ['bash -lc "$SCRIPT"', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('separates read-only package manager queries from mutations', async () => {
  const cases = [
    ['apt list --installed', 'allow'],
    ['apt show curl', 'allow'],
    ['apt search vim', 'allow'],
    ['apt policy curl', 'allow'],
    ['apt install curl', 'review'],
    ['apt-get -s install curl', 'allow'],
    ['apt-get --dry-run upgrade', 'allow'],
    ['apt-get install curl', 'review'],
    ['apt-get update', 'review'],
    ['yum list installed', 'allow'],
    ['yum info curl', 'allow'],
    ['yum install curl', 'review'],
    ['npm ls', 'allow'],
    ['npm view lodash version', 'allow'],
    ['npm outdated', 'allow'],
    ['npm ping', 'allow'],
    ['npm install lodash', 'review'],
    ['npm run build', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('allows version and help probes without opening up unknown binaries', async () => {
  const cases = [
    ['node --version', 'allow'],
    ['node --help', 'allow'],
    ['node', 'review'],
    ['node script.js', 'review'],
    ['python3 --version', 'allow'],
    ['python -V', 'allow'],
    ['python3 --help', 'allow'],
    ['python3 /tmp/script.py', 'review'],
    ['openssl version', 'allow'],
    ['openssl version -a', 'allow'],
    ['openssl enc -d', 'review'],
    ['rm --help', 'review'],
    ['custom-binary --version', 'allow'],
    ['custom-binary --version --extra', 'review'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});

test('analyzes static interpreter and datastore payloads instead of trusting names', async () => {
  const cases = [
    ["python3 -c 'print(1 + 2)'", 'allow'],
    ["python -c 'open(\"/tmp/generated\", \"w\").write(\"value\")'", 'review'],
    ['python3 -c "$PYTHON_CODE"', 'review'],
    ['python3 /tmp/script.py', 'review'],
    ["sqlite3 /tmp/application.db '.tables'", 'allow'],
    ["sqlite3 /tmp/application.db '.schema users'", 'allow'],
    ["sqlite3 /tmp/application.db '.backup /tmp/copy.db'", 'review'],
    ["sqlite3 /tmp/application.db 'SELECT id FROM users'", 'allow'],
    ["sqlite3 /tmp/application.db 'SELECT password_hash FROM users'", 'review'],
    ["sqlite3 /tmp/application.db 'DELETE FROM users'", 'review'],
    ["mysql --execute 'SHOW STATUS' application", 'allow'],
    ["mysql -e 'UPDATE users SET name=\"changed\"' application", 'review'],
    ["mysql --password=secret -e 'SELECT id FROM users' application", 'review'],
    ['redis-cli GET cache:item', 'allow'],
    ['redis-cli SET cache:item value', 'review'],
    ['redis-cli BLPOP queue 0', 'deny'],
  ] as const;
  for (const [command, expected] of cases) {
    assert.equal(await action(command), expected, command);
  }
});
