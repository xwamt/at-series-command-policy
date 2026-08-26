import { createShellPolicyEvaluator } from '../src/shell.ts';
import { createPythonPolicyEvaluator } from '../src/python.ts';
import { createSqlitePolicyEvaluator } from '../src/sqlite.ts';
import { createMysqlPolicyEvaluator } from '../src/mysql.ts';
import { createRedisPolicyEvaluator } from '../src/redis.ts';

export interface TestCase {
  readonly round: number;
  readonly roundTitle: string;
  readonly id: string;
  readonly domain: 'shell' | 'python' | 'sqlite' | 'mysql' | 'redis';
  readonly category: string;
  readonly command: string;
  readonly expectedAction: 'allow' | 'review' | 'deny';
  readonly expectedReasonPrefix?: string;
  readonly description: string;
}

export const fullTestMatrix: TestCase[] = [
  // =========================================================================
  // ROUND 1: Simple Queries & Observers (单命令基础查询与只读放行)
  // =========================================================================
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-001', domain: 'shell', category: 'Host Observer', command: 'uname -a', expectedAction: 'allow', description: 'Kernel version' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-002', domain: 'shell', category: 'Host Observer', command: 'uptime', expectedAction: 'allow', description: 'System uptime' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-003', domain: 'shell', category: 'Host Observer', command: 'df -h', expectedAction: 'allow', description: 'Filesystem usage' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-004', domain: 'shell', category: 'Host Observer', command: 'free -m', expectedAction: 'allow', description: 'Memory usage' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-005', domain: 'shell', category: 'Host Observer', command: 'ps aux', expectedAction: 'allow', description: 'Process table' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-006', domain: 'shell', category: 'Host Observer', command: 'top -b -n 1', expectedAction: 'allow', description: 'Top snapshot' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-007', domain: 'shell', category: 'Host Observer', command: 'vmstat 1 3', expectedAction: 'allow', description: 'Virtual memory' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-008', domain: 'shell', category: 'Host Observer', command: 'iostat -xz 1 2', expectedAction: 'allow', description: 'IO stats' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-009', domain: 'shell', category: 'Host Observer', command: 'lsblk -f', expectedAction: 'allow', description: 'Block devices' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-010', domain: 'shell', category: 'Host Observer', command: 'lscpu', expectedAction: 'allow', description: 'CPU info' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-011', domain: 'shell', category: 'Host Observer', command: 'whoami', expectedAction: 'allow', description: 'Current user' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-012', domain: 'shell', category: 'Host Observer', command: 'id -u', expectedAction: 'allow', description: 'User ID' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-013', domain: 'shell', category: 'Host Observer', command: 'pwd', expectedAction: 'allow', description: 'Working directory' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-014', domain: 'shell', category: 'Host Observer', command: 'date +"%Y-%m-%d %H:%M:%S"', expectedAction: 'allow', description: 'Current date' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-015', domain: 'shell', category: 'Host Observer', command: 'which python3', expectedAction: 'allow', description: 'Which executable' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-016', domain: 'shell', category: 'Host Observer', command: 'whereis nginx', expectedAction: 'allow', description: 'Whereis' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-017', domain: 'shell', category: 'Host Observer', command: 'netstat -tuln', expectedAction: 'allow', description: 'Netstat listening' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-018', domain: 'shell', category: 'Host Observer', command: 'ss -antp', expectedAction: 'allow', description: 'Socket statistics' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-019', domain: 'shell', category: 'Host Observer', command: 'ip addr show eth0', expectedAction: 'allow', description: 'IP address show' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-020', domain: 'shell', category: 'Host Observer', command: 'ip route show', expectedAction: 'allow', description: 'IP routes' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-021', domain: 'shell', category: 'Host Observer', command: 'pgrep -l node', expectedAction: 'allow', description: 'Find process node' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-022', domain: 'shell', category: 'Host Observer', command: 'crontab -l', expectedAction: 'allow', description: 'List crontab' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-023', domain: 'shell', category: 'Host Observer', command: 'systemctl status sshd', expectedAction: 'allow', description: 'Systemctl status' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-024', domain: 'shell', category: 'Host Observer', command: 'systemctl is-active docker', expectedAction: 'allow', description: 'Systemctl is-active' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-025', domain: 'shell', category: 'Host Observer', command: 'journalctl -n 50 --no-pager', expectedAction: 'allow', description: 'Journalctl view' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-026', domain: 'shell', category: 'Host Observer', command: 'docker ps', expectedAction: 'allow', description: 'Docker running containers' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-027', domain: 'shell', category: 'Host Observer', command: 'docker images', expectedAction: 'allow', description: 'Docker images list' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-028', domain: 'shell', category: 'Host Observer', command: 'docker compose ps', expectedAction: 'allow', description: 'Docker compose ps' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-029', domain: 'shell', category: 'Host Observer', command: 'kubectl get nodes', expectedAction: 'allow', description: 'Kubectl get nodes' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-028', domain: 'shell', category: 'Host Observer', command: 'kubectl get svc', expectedAction: 'allow', description: 'Kubectl get services' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-030', domain: 'shell', category: 'Host Observer', command: 'iptables -S', expectedAction: 'allow', description: 'Iptables list rules' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-031', domain: 'shell', category: 'Host Observer', command: 'git log -n 10', expectedAction: 'allow', description: 'Git log read' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-032', domain: 'shell', category: 'File Reading', command: 'cat /etc/os-release', expectedAction: 'allow', description: 'Read os-release' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-033', domain: 'shell', category: 'File Reading', command: 'cat /etc/resolv.conf', expectedAction: 'allow', description: 'Read resolv.conf' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-034', domain: 'shell', category: 'File Reading', command: 'ls -la /var/log', expectedAction: 'allow', description: 'List /var/log' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-035', domain: 'shell', category: 'File Reading', command: 'head -n 20 /var/log/messages', expectedAction: 'allow', description: 'Head messages' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-036', domain: 'shell', category: 'File Reading', command: 'tail -n 100 /var/log/nginx/access.log', expectedAction: 'allow', description: 'Tail access.log' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-037', domain: 'shell', category: 'File Reading', command: 'grep "GET /api" /var/log/nginx/access.log', expectedAction: 'allow', description: 'Grep in log' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-038', domain: 'shell', category: 'File Reading', command: 'find /var/log -type f -name "*.log"', expectedAction: 'allow', description: 'Find log files' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-039', domain: 'shell', category: 'File Reading', command: 'du -sh /var/log', expectedAction: 'allow', description: 'Disk usage of directory' },
  { round: 1, roundTitle: 'Round 1: Simple Read-Only Queries', id: 'R1-040', domain: 'shell', category: 'File Reading', command: 'curl -s https://httpbin.org/get', expectedAction: 'allow', description: 'Safe HTTP GET' },

  // =========================================================================
  // ROUND 2: Dangerous, State-Modifying & Sensitive Commands (状态修改与敏感拦截)
  // =========================================================================
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-001', domain: 'shell', category: 'State Mutation', command: 'rm -rf /tmp/data', expectedAction: 'review', description: 'Recursive file deletion' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-002', domain: 'shell', category: 'State Mutation', command: 'touch /tmp/marker.lock', expectedAction: 'review', description: 'File creation' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-003', domain: 'shell', category: 'State Mutation', command: 'mkdir -p /opt/myapp', expectedAction: 'review', description: 'Directory creation' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-004', domain: 'shell', category: 'State Mutation', command: 'cp /tmp/a /tmp/b', expectedAction: 'review', description: 'File copy' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-005', domain: 'shell', category: 'State Mutation', command: 'mv /tmp/a /tmp/b', expectedAction: 'review', description: 'File move' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-006', domain: 'shell', category: 'State Mutation', command: 'chmod 777 /var/www', expectedAction: 'review', description: 'Permission modification' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-007', domain: 'shell', category: 'State Mutation', command: 'chown -R root:root /tmp/dir', expectedAction: 'review', description: 'Owner modification' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-008', domain: 'shell', category: 'State Mutation', command: 'kill -9 12345', expectedAction: 'review', description: 'Kill process' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-009', domain: 'shell', category: 'State Mutation', command: 'pkill -9 nginx', expectedAction: 'review', description: 'Pkill process' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-010', domain: 'shell', category: 'State Mutation', command: 'systemctl restart nginx', expectedAction: 'review', description: 'Service restart' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-011', domain: 'shell', category: 'State Mutation', command: 'systemctl stop firewalld', expectedAction: 'review', description: 'Service stop' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-012', domain: 'shell', category: 'State Mutation', command: 'docker run -d --name test nginx', expectedAction: 'review', description: 'Docker run' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-013', domain: 'shell', category: 'State Mutation', command: 'docker exec -it test sh', expectedAction: 'review', description: 'Docker exec' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-014', domain: 'shell', category: 'State Mutation', command: 'docker rm -f test', expectedAction: 'review', description: 'Docker remove' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-015', domain: 'shell', category: 'State Mutation', command: 'kubectl delete pod pod-1', expectedAction: 'review', description: 'Kubectl delete pod' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-016', domain: 'shell', category: 'State Mutation', command: 'iptables -F', expectedAction: 'review', description: 'Flush iptables' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-017', domain: 'shell', category: 'State Mutation', command: 'ip link set dev eth0 down', expectedAction: 'review', description: 'Network interface disable' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-018', domain: 'shell', category: 'State Mutation', command: 'sed -i "s/foo/bar/g" /tmp/test.conf', expectedAction: 'review', description: 'In-place sed' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-019', domain: 'shell', category: 'State Mutation', command: 'find /tmp -name "*.old" -delete', expectedAction: 'review', description: 'Find with delete flag' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-020', domain: 'shell', category: 'State Mutation', command: 'reboot', expectedAction: 'review', description: 'System reboot' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-021', domain: 'shell', category: 'Sensitive Access', command: 'cat /etc/shadow', expectedAction: 'review', description: 'Read /etc/shadow' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-022', domain: 'shell', category: 'Sensitive Access', command: 'cat /etc/gshadow', expectedAction: 'review', description: 'Read /etc/gshadow' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-023', domain: 'shell', category: 'Sensitive Access', command: 'cat ~/.ssh/id_rsa', expectedAction: 'review', description: 'Read SSH private key' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-024', domain: 'shell', category: 'Sensitive Access', command: 'cat ~/.aws/credentials', expectedAction: 'review', description: 'Read AWS credentials' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-025', domain: 'shell', category: 'Sensitive Access', command: 'cat ~/.kube/config', expectedAction: 'review', description: 'Read Kubernetes tokens' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-026', domain: 'shell', category: 'Sensitive Access', command: 'cat .env', expectedAction: 'review', description: 'Read .env' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-027', domain: 'shell', category: 'Sensitive Access', command: 'cat server.key', expectedAction: 'review', description: 'Read TLS key' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-028', domain: 'shell', category: 'Sensitive Access', command: 'curl -H "Authorization: Bearer secret_tok" https://api.internal', expectedAction: 'review', description: 'Curl with auth header' },
  { round: 2, roundTitle: 'Round 2: State-Changing & Dangerous Operations', id: 'R2-029', domain: 'shell', category: 'Sensitive Access', command: 'curl http://169.254.169.254/latest/meta-data/', expectedAction: 'review', description: 'Cloud metadata access' },

  // =========================================================================
  // ROUND 3: Complex Combinations, Pipelines, Redirects, Subshells (复杂组合测试)
  // =========================================================================
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-001', domain: 'shell', category: 'Pipe: Read Only', command: 'ps aux | grep nginx | grep -v grep | awk \'{print $2}\'', expectedAction: 'allow', description: 'Multi-pipe process extraction' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-002', domain: 'shell', category: 'Pipe: Read Only', command: 'netstat -tulnp | grep ":80" | sort | uniq -c', expectedAction: 'allow', description: 'Multi-pipe socket aggregation' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-003', domain: 'shell', category: 'Pipe: Read Only', command: 'cat /var/log/syslog | grep "CRON" | head -n 30 | wc -l', expectedAction: 'allow', description: 'Log counting pipeline' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-004', domain: 'shell', category: 'Pipe: Read Only', command: 'dmesg | tail -n 100 | grep -i error', expectedAction: 'allow', description: 'Dmesg error filter' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-005', domain: 'shell', category: 'Pipe: Contaminated', command: 'ps aux | grep bad_proc | xargs kill -9', expectedAction: 'review', description: 'Pipe feeding into kill' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-006', domain: 'shell', category: 'Pipe: Contaminated', command: 'cat /etc/shadow | grep -i root', expectedAction: 'review', description: 'Pipe reading sensitive shadow file' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-007', domain: 'shell', category: 'Pipe: Contaminated', command: 'ls /var/log | tee /tmp/output.txt', expectedAction: 'review', description: 'Tee writing to file' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-008', domain: 'shell', category: 'Chaining: Pure Read', command: 'uname -a && uptime && df -h; free -m', expectedAction: 'allow', description: '4 chained read commands' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-009', domain: 'shell', category: 'Chaining: Mixed Write', command: 'uptime && rm -rf /tmp/test_dir', expectedAction: 'review', description: 'Read && write chain' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-010', domain: 'shell', category: 'Chaining: Mixed Write', command: 'touch /tmp/run.pid || echo "failed"', expectedAction: 'review', description: 'Write || echo chain' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-011', domain: 'shell', category: 'Chaining: Sensitive Read', command: 'df -h; cat /etc/shadow; free -m', expectedAction: 'review', description: 'Read ; sensitive ; read' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-012', domain: 'shell', category: 'Redirect: Safe', command: 'cat /etc/hosts 2>/dev/null', expectedAction: 'allow', description: 'Standard error redirect' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-013', domain: 'shell', category: 'Redirect: Safe', command: 'grep localhost < /etc/hosts', expectedAction: 'allow', description: 'Input redirect from normal file' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-014', domain: 'shell', category: 'Redirect: Unsafe', command: 'cat /etc/hosts > /tmp/hosts.txt', expectedAction: 'review', description: 'File overwrite redirect' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-015', domain: 'shell', category: 'Redirect: Unsafe', command: 'echo "127.0.0.1 custom" >> /etc/hosts', expectedAction: 'review', description: 'Append redirect' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-016', domain: 'shell', category: 'Redirect: Unsafe', command: 'grep root < /etc/shadow', expectedAction: 'review', description: 'Input redirect from sensitive file' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-017', domain: 'shell', category: 'Subshell: Safe', command: 'printf "Kernel: %s\\n" "$(uname -r)"', expectedAction: 'allow', description: 'Subshell uname read' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-018', domain: 'shell', category: 'Subshell: Safe', command: 'echo "My host is: $(cat /etc/hostname)"', expectedAction: 'allow', description: 'Subshell cat hostname' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-019', domain: 'shell', category: 'Subshell: Unsafe', command: 'echo "Password: $(cat /etc/shadow)"', expectedAction: 'review', description: 'Subshell cat shadow' },
  { round: 3, roundTitle: 'Round 3: Complex Pipelines & Composition', id: 'R3-020', domain: 'shell', category: 'Subshell: Unsafe', command: '$(printf "rm") -rf /tmp/data', expectedAction: 'review', description: 'Subshell dynamic executable' },

  // =========================================================================
  // ROUND 4: Wrappers & Multi-language Payloads (包装器与嵌入语言)
  // =========================================================================
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-001', domain: 'shell', category: 'Wrapper: Safe', command: 'sudo -- uname -a', expectedAction: 'allow', description: 'Sudo with safe command' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-002', domain: 'shell', category: 'Wrapper: Safe', command: 'timeout 10s ps aux', expectedAction: 'allow', description: 'Timeout with safe command' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-003', domain: 'shell', category: 'Wrapper: Safe', command: 'nice -n 10 df -h', expectedAction: 'allow', description: 'Nice with safe command' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-004', domain: 'shell', category: 'Wrapper: Safe', command: 'env LANG=en_US.UTF-8 date', expectedAction: 'allow', description: 'Env with safe variable' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-005', domain: 'shell', category: 'Wrapper: Safe', command: 'bash -c "uname -a && uptime"', expectedAction: 'allow', description: 'Bash -c with static safe script' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-006', domain: 'shell', category: 'Wrapper: Unsafe', command: 'sudo systemctl restart nginx', expectedAction: 'review', description: 'Sudo with restart command' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-007', domain: 'shell', category: 'Wrapper: Unsafe', command: 'sudo rm -rf /tmp/data', expectedAction: 'review', description: 'Sudo with rm' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-008', domain: 'shell', category: 'Wrapper: Unsafe', command: 'env PATH=/tmp/bin:$PATH ls', expectedAction: 'review', description: 'Env PATH override' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-009', domain: 'shell', category: 'Wrapper: Unsafe', command: 'bash -c "$UNVERIFIED_VAR"', expectedAction: 'review', description: 'Bash -c dynamic code' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-010', domain: 'shell', category: 'Wrapper: Unsafe', command: 'eval "uname -a"', expectedAction: 'review', description: 'Eval execution' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-011', domain: 'shell', category: 'Embedded Python', command: 'python3 -c "import json; print(json.dumps({\'k\': 1}))"', expectedAction: 'allow', description: 'Embedded python json dumps' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-012', domain: 'shell', category: 'Embedded Python', command: 'python3 -c "import os; os.remove(\'/tmp/f\')"', expectedAction: 'review', description: 'Embedded python os.remove' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-013', domain: 'shell', category: 'Embedded SQLite', command: 'sqlite3 /tmp/db.sqlite ".schema"', expectedAction: 'allow', description: 'Embedded sqlite3 .schema' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-014', domain: 'shell', category: 'Embedded SQLite', command: 'sqlite3 /tmp/db.sqlite "SELECT id, name FROM users"', expectedAction: 'allow', description: 'Embedded sqlite3 SELECT' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-015', domain: 'shell', category: 'Embedded SQLite', command: 'sqlite3 /tmp/db.sqlite "DROP TABLE users"', expectedAction: 'review', description: 'Embedded sqlite3 DROP' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-016', domain: 'shell', category: 'Embedded MySQL', command: 'mysql -e "SHOW STATUS" mydb', expectedAction: 'allow', description: 'Embedded mysql SHOW STATUS' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-017', domain: 'shell', category: 'Embedded MySQL', command: 'mysql -e "UPDATE users SET active=1" mydb', expectedAction: 'review', description: 'Embedded mysql UPDATE' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-018', domain: 'shell', category: 'Embedded Redis', command: 'redis-cli GET cache:item', expectedAction: 'allow', description: 'Embedded redis-cli GET' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-019', domain: 'shell', category: 'Embedded Redis', command: 'redis-cli SET cache:item 123', expectedAction: 'review', description: 'Embedded redis-cli SET' },
  { round: 4, roundTitle: 'Round 4: Wrappers & Embedded Payloads', id: 'R4-020', domain: 'shell', category: 'Embedded Redis', command: 'redis-cli KEYS *', expectedAction: 'deny', description: 'Embedded redis-cli KEYS *' },

  // =========================================================================
  // ROUND 5: Domain Analyzers (Python, SQLite, MySQL, Redis AST Engines)
  // =========================================================================
  // Python AST
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-01', domain: 'python', category: 'Python Engine', command: 'print([x**2 for x in range(10)])', expectedAction: 'allow', description: 'List comprehension' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-02', domain: 'python', category: 'Python Engine', command: 'import math, statistics\nprint(statistics.mean([1, 2, 3]))', expectedAction: 'allow', description: 'Math & statistics imports' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-03', domain: 'python', category: 'Python Engine', command: 'print(open("/etc/hosts", "r").read())', expectedAction: 'allow', description: 'Open static hosts read' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-04', domain: 'python', category: 'Python Engine', command: 'print(open("/etc/shadow", "r").read())', expectedAction: 'review', description: 'Open sensitive shadow file' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-05', domain: 'python', category: 'Python Engine', command: 'open("/tmp/evil.py", "w").write("code")', expectedAction: 'review', description: 'Open with write mode' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-06', domain: 'python', category: 'Python Engine', command: 'import subprocess\nsubprocess.check_output(["id"])', expectedAction: 'review', description: 'Subprocess execution' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-PY-07', domain: 'python', category: 'Python Engine', command: 'eval("print(1)")', expectedAction: 'review', description: 'Eval execution' },
  // SQLite AST
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-SQL-01', domain: 'sqlite', category: 'SQLite Engine', command: 'SELECT count(*) FROM orders WHERE status = "completed"', expectedAction: 'allow', description: 'Aggregate query' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-SQL-02', domain: 'sqlite', category: 'SQLite Engine', command: 'PRAGMA table_info(users)', expectedAction: 'allow', description: 'Table schema pragma' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-SQL-03', domain: 'sqlite', category: 'SQLite Engine', command: 'INSERT INTO audit_log(action) VALUES ("login")', expectedAction: 'review', description: 'Insert statement' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-SQL-04', domain: 'sqlite', category: 'SQLite Engine', command: 'DELETE FROM users WHERE id = 10', expectedAction: 'review', description: 'Delete statement' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-SQL-05', domain: 'sqlite', category: 'SQLite Engine', command: 'SELECT password_hash FROM admin', expectedAction: 'review', description: 'Sensitive column select' },
  // MySQL AST
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-MY-01', domain: 'mysql', category: 'MySQL Engine', command: 'SELECT id, username FROM users WHERE is_active = 1', expectedAction: 'allow', description: 'Read query' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-MY-02', domain: 'mysql', category: 'MySQL Engine', command: 'SHOW TABLES', expectedAction: 'allow', description: 'Show tables' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-MY-03', domain: 'mysql', category: 'MySQL Engine', command: 'UPDATE accounts SET balance = balance + 10 WHERE id = 1', expectedAction: 'review', description: 'Update statement' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-MY-04', domain: 'mysql', category: 'MySQL Engine', command: 'DROP TABLE logs', expectedAction: 'review', description: 'Drop table' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-MY-05', domain: 'mysql', category: 'MySQL Engine', command: 'SELECT api_token FROM users', expectedAction: 'review', description: 'Sensitive api_token select' },
  // Redis Engine
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-01', domain: 'redis', category: 'Redis Engine', command: 'GET user:session:100', expectedAction: 'allow', description: 'Redis GET' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-02', domain: 'redis', category: 'Redis Engine', command: 'HGETALL user:profile', expectedAction: 'allow', description: 'Redis HGETALL' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-03', domain: 'redis', category: 'Redis Engine', command: 'SET user:session:100 "active"', expectedAction: 'review', description: 'Redis SET write' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-04', domain: 'redis', category: 'Redis Engine', command: 'DEL user:session:100', expectedAction: 'review', description: 'Redis DEL write' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-05', domain: 'redis', category: 'Redis Engine', command: 'KEYS *', expectedAction: 'deny', description: 'Redis KEYS * deny' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-06', domain: 'redis', category: 'Redis Engine', command: 'BLPOP job:queue 0', expectedAction: 'deny', description: 'Redis BLPOP deny' },
  { round: 5, roundTitle: 'Round 5: Specialized Domain AST Analyzers', id: 'R5-RD-07', domain: 'redis', category: 'Redis Engine', command: 'MONITOR', expectedAction: 'deny', description: 'Redis MONITOR deny' },
];

async function runMultiRoundTests() {
  console.log('======================================================================');
  console.log('   AT-SERIES-COMMAND-POLICY: MULTI-ROUND COMPREHENSIVE TEST SUITE     ');
  console.log('======================================================================\n');

  const shellEvaluator = createShellPolicyEvaluator();
  const pythonEvaluator = createPythonPolicyEvaluator();
  const sqliteEvaluator = createSqlitePolicyEvaluator();
  const mysqlEvaluator = createMysqlPolicyEvaluator();
  const redisEvaluator = createRedisPolicyEvaluator();

  const evaluators = {
    shell: shellEvaluator,
    python: pythonEvaluator,
    sqlite: sqliteEvaluator,
    mysql: mysqlEvaluator,
    redis: redisEvaluator,
  };

  const rounds: Record<number, { title: string; total: number; passed: number; failed: number; TP: number; TN: number; FP: number; FN: number; latencySum: number }> = {};
  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;
  let totalTP = 0;
  let totalTN = 0;
  let totalFP = 0;
  let totalFN = 0;

  const failureLog: Array<{ id: string; round: number; domain: string; category: string; command: string; expected: string; actual: string; reason: string }> = [];

  const overallStartTime = Date.now();

  for (const tc of fullTestMatrix) {
    totalTests += 1;
    if (!rounds[tc.round]) {
      rounds[tc.round] = { title: tc.roundTitle, total: 0, passed: 0, failed: 0, TP: 0, TN: 0, FP: 0, FN: 0, latencySum: 0 };
    }
    const r = rounds[tc.round];
    r.total += 1;

    const t0 = performance.now();
    const evaluator = evaluators[tc.domain];
    const decision = await evaluator.evaluate({ sourceText: tc.command });
    const latency = performance.now() - t0;
    r.latencySum += latency;

    const actual = decision.action;

    let isMatch = false;
    if (tc.expectedAction === 'allow') {
      if (actual === 'allow') {
        isMatch = true;
        r.TN += 1;
        totalTN += 1;
      } else {
        r.FP += 1;
        totalFP += 1;
      }
    } else if (tc.expectedAction === 'deny') {
      if (actual === 'deny') {
        isMatch = true;
        r.TP += 1;
        totalTP += 1;
      } else if (actual === 'review') {
        isMatch = true; // Review is also an interception
        r.TP += 1;
        totalTP += 1;
      } else {
        r.FN += 1; // Critical leak!
        totalFN += 1;
      }
    } else { // expectedAction === 'review'
      if (actual === 'review' || actual === 'deny') {
        isMatch = true;
        r.TP += 1;
        totalTP += 1;
      } else {
        r.FN += 1; // Critical leak!
        totalFN += 1;
      }
    }

    if (isMatch) {
      r.passed += 1;
      totalPassed += 1;
    } else {
      r.failed += 1;
      totalFailed += 1;
      failureLog.push({
        id: tc.id,
        round: tc.round,
        domain: tc.domain,
        category: tc.category,
        command: tc.command,
        expected: tc.expectedAction,
        actual,
        reason: decision.reasonCode,
      });
    }
  }

  const totalTimeMs = Date.now() - overallStartTime;

  console.log('----------------------------------------------------------------------');
  console.log('                      ROUND-BY-ROUND RESULTS                          ');
  console.log('----------------------------------------------------------------------');

  for (const [roundNum, r] of Object.entries(rounds)) {
    const passRate = ((r.passed / r.total) * 100).toFixed(2);
    const avgLatency = (r.latencySum / r.total).toFixed(2);
    console.log(`[Round ${roundNum}] ${r.title}`);
    console.log(`          Cases: ${r.total} | Passed: ${r.passed} | Failed: ${r.failed} | Pass Rate: ${passRate}% | Avg Latency: ${avgLatency}ms`);
    console.log(`          TP: ${r.TP} | TN: ${r.TN} | FP: ${r.FP} | FN: ${r.FN}`);
    console.log('');
  }

  console.log('----------------------------------------------------------------------');
  console.log('                    OVERALL STATISTICAL METRICS                       ');
  console.log('----------------------------------------------------------------------');
  const overallAccuracy = (((totalTP + totalTN) / totalTests) * 100).toFixed(2);
  const precision = totalTP + totalFP > 0 ? ((totalTP / (totalTP + totalFP)) * 100).toFixed(2) : '100.00';
  const recall = totalTP + totalFN > 0 ? ((totalTP / (totalTP + totalFN)) * 100).toFixed(2) : '100.00';
  const f1 = (2 * Number(precision) * Number(recall) / (Number(precision) + Number(recall))).toFixed(2);

  console.log(`Total Evaluated Cases:     ${totalTests}`);
  console.log(`Overall Accuracy:          ${overallAccuracy}%`);
  console.log(`Precision (查准率):        ${precision}%`);
  console.log(`Recall / Coverage (查全率): ${recall}%`);
  console.log(`F1-Score:                  ${f1}%`);
  console.log(`True Positives (TP):       ${totalTP}`);
  console.log(`True Negatives (TN):       ${totalTN}`);
  console.log(`False Positives (FP):      ${totalFP} (Conservative reviews)`);
  console.log(`False Negatives (FN):      ${totalFN} (Safety bypasses - MUST BE 0)`);
  console.log(`Total Elapsed Time:        ${totalTimeMs}ms`);

  if (failureLog.length > 0) {
    console.log('\n----------------------------------------------------------------------');
    console.log('                         FAILURE LOG DETAILS                          ');
    console.log('----------------------------------------------------------------------');
    for (const f of failureLog) {
      console.log(`[${f.id}] [Round ${f.round}] Category: ${f.category}`);
      console.log(`     Command:  ${f.command}`);
      console.log(`     Expected: ${f.expected} | Actual: ${f.actual} | Reason: ${f.reason}\n`);
    }
  }

  console.log('======================================================================\n');

  return {
    rounds,
    totalTests,
    totalPassed,
    totalFailed,
    totalTP,
    totalTN,
    totalFP,
    totalFN,
    overallAccuracy,
    precision,
    recall,
    f1,
    totalTimeMs,
    failureLog,
  };
}

runMultiRoundTests().catch(console.error);
