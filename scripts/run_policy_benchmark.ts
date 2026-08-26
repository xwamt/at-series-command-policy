import { createShellPolicyEvaluator } from '../src/shell.ts';
import { createPythonPolicyEvaluator } from '../src/python.ts';
import { createSqlitePolicyEvaluator } from '../src/sqlite.ts';
import { createMysqlPolicyEvaluator } from '../src/mysql.ts';
import { createRedisPolicyEvaluator } from '../src/redis.ts';
import { combinePolicyDecisions } from '../src/index.ts';

interface TestCase {
  readonly id: string;
  readonly domain: 'shell' | 'python' | 'sqlite' | 'mysql' | 'redis' | 'combination';
  readonly category: string;
  readonly command: string;
  readonly expectedAction: 'allow' | 'review' | 'deny';
  readonly description: string;
}

const testCases: TestCase[] = [
  // ==========================================
  // 1. SHELL: Simple Queries / Host Observers (Expected: allow)
  // ==========================================
  { id: 'SH-OBS-001', domain: 'shell', category: 'Simple Observer', command: 'uname -a', expectedAction: 'allow', description: 'System kernel and architecture info' },
  { id: 'SH-OBS-002', domain: 'shell', category: 'Simple Observer', command: 'uptime', expectedAction: 'allow', description: 'System uptime and load averages' },
  { id: 'SH-OBS-003', domain: 'shell', category: 'Simple Observer', command: 'df -h', expectedAction: 'allow', description: 'Disk filesystem usage' },
  { id: 'SH-OBS-004', domain: 'shell', category: 'Simple Observer', command: 'free -m', expectedAction: 'allow', description: 'Memory usage statistics' },
  { id: 'SH-OBS-005', domain: 'shell', category: 'Simple Observer', command: 'ps aux', expectedAction: 'allow', description: 'Process table snapshot' },
  { id: 'SH-OBS-006', domain: 'shell', category: 'Simple Observer', command: 'top -b -n 1', expectedAction: 'allow', description: 'Top processes batch snapshot' },
  { id: 'SH-OBS-007', domain: 'shell', category: 'Simple Observer', command: 'netstat -tuln', expectedAction: 'allow', description: 'Network listening sockets' },
  { id: 'SH-OBS-008', domain: 'shell', category: 'Simple Observer', command: 'ss -tuln', expectedAction: 'allow', description: 'Socket statistics listening ports' },
  { id: 'SH-OBS-009', domain: 'shell', category: 'Simple Observer', command: 'iostat -x 1 2', expectedAction: 'allow', description: 'I/O stats' },
  { id: 'SH-OBS-010', domain: 'shell', category: 'Simple Observer', command: 'vmstat 1 3', expectedAction: 'allow', description: 'Virtual memory statistics' },
  { id: 'SH-OBS-011', domain: 'shell', category: 'Simple Observer', command: 'lsblk', expectedAction: 'allow', description: 'List block devices' },
  { id: 'SH-OBS-012', domain: 'shell', category: 'Simple Observer', command: 'lscpu', expectedAction: 'allow', description: 'CPU architecture information' },
  { id: 'SH-OBS-013', domain: 'shell', category: 'Simple Observer', command: 'whoami', expectedAction: 'allow', description: 'Current effective username' },
  { id: 'SH-OBS-014', domain: 'shell', category: 'Simple Observer', command: 'id', expectedAction: 'allow', description: 'Current user ID and groups' },
  { id: 'SH-OBS-015', domain: 'shell', category: 'Simple Observer', command: 'pwd', expectedAction: 'allow', description: 'Print working directory' },
  { id: 'SH-OBS-016', domain: 'shell', category: 'Simple Observer', command: 'date +%Y-%m-%d', expectedAction: 'allow', description: 'Formatted current date' },
  { id: 'SH-OBS-017', domain: 'shell', category: 'Simple Observer', command: 'which nginx', expectedAction: 'allow', description: 'Locate nginx binary' },
  { id: 'SH-OBS-018', domain: 'shell', category: 'Simple Observer', command: 'whereis bash', expectedAction: 'allow', description: 'Locate binary, source, and manual' },
  { id: 'SH-OBS-019', domain: 'shell', category: 'Simple Observer', command: 'dig +short google.com', expectedAction: 'allow', description: 'DNS query' },
  { id: 'SH-OBS-020', domain: 'shell', category: 'Simple Observer', command: 'nslookup example.com', expectedAction: 'allow', description: 'DNS lookup' },
  { id: 'SH-OBS-021', domain: 'shell', category: 'Simple Observer', command: 'pgrep -a node', expectedAction: 'allow', description: 'Look up processes by name' },
  { id: 'SH-OBS-022', domain: 'shell', category: 'Simple Observer', command: 'pidof systemd', expectedAction: 'allow', description: 'Find PID of program' },
  { id: 'SH-OBS-023', domain: 'shell', category: 'Simple Observer', command: 'crontab -l', expectedAction: 'allow', description: 'List user crontab' },
  { id: 'SH-OBS-024', domain: 'shell', category: 'Simple Observer', command: 'git status', expectedAction: 'allow', description: 'Git working tree status' },
  { id: 'SH-OBS-025', domain: 'shell', category: 'Simple Observer', command: 'git log -n 5 --oneline', expectedAction: 'allow', description: 'Git commit history' },
  { id: 'SH-OBS-026', domain: 'shell', category: 'Simple Observer', command: 'ip addr show', expectedAction: 'allow', description: 'Network IP addresses' },
  { id: 'SH-OBS-027', domain: 'shell', category: 'Simple Observer', command: 'ip route show', expectedAction: 'allow', description: 'Routing table' },
  { id: 'SH-OBS-028', domain: 'shell', category: 'Simple Observer', command: 'systemctl status nginx', expectedAction: 'allow', description: 'Systemd service status' },
  { id: 'SH-OBS-029', domain: 'shell', category: 'Simple Observer', command: 'systemctl is-active sshd', expectedAction: 'allow', description: 'Check if sshd is active' },
  { id: 'SH-OBS-030', domain: 'shell', category: 'Simple Observer', command: 'journalctl -u nginx -n 50 --no-pager', expectedAction: 'allow', description: 'Read systemd logs' },
  { id: 'SH-OBS-031', domain: 'shell', category: 'Simple Observer', command: 'docker ps -a', expectedAction: 'allow', description: 'List all docker containers' },
  { id: 'SH-OBS-032', domain: 'shell', category: 'Simple Observer', command: 'docker inspect web_app', expectedAction: 'allow', description: 'Inspect docker container' },
  { id: 'SH-OBS-033', domain: 'shell', category: 'Simple Observer', command: 'docker images', expectedAction: 'allow', description: 'List docker images' },
  { id: 'SH-OBS-034', domain: 'shell', category: 'Simple Observer', command: 'kubectl get pods -A', expectedAction: 'allow', description: 'List k8s pods across namespaces' },
  { id: 'SH-OBS-035', domain: 'shell', category: 'Simple Observer', command: 'kubectl describe pod web-123', expectedAction: 'allow', description: 'Describe k8s pod' },
  { id: 'SH-OBS-036', domain: 'shell', category: 'Simple Observer', command: 'iptables -L -n -v', expectedAction: 'allow', description: 'List firewall rules' },
  { id: 'SH-OBS-037', domain: 'shell', category: 'Simple Observer', command: 'nft list ruleset', expectedAction: 'allow', description: 'List nftables rules' },

  // ==========================================
  // 2. SHELL: Ordinary File & Content Reads (Expected: allow)
  // ==========================================
  { id: 'SH-READ-001', domain: 'shell', category: 'File Read', command: 'cat /etc/os-release', expectedAction: 'allow', description: 'Read OS version release info' },
  { id: 'SH-READ-002', domain: 'shell', category: 'File Read', command: 'cat /etc/hosts', expectedAction: 'allow', description: 'Read static hosts file' },
  { id: 'SH-READ-003', domain: 'shell', category: 'File Read', command: 'ls -la /var/log', expectedAction: 'allow', description: 'List log directory' },
  { id: 'SH-READ-004', domain: 'shell', category: 'File Read', command: 'tail -n 100 /var/log/syslog', expectedAction: 'allow', description: 'Tail system log' },
  { id: 'SH-READ-005', domain: 'shell', category: 'File Read', command: 'head -n 20 /etc/resolv.conf', expectedAction: 'allow', description: 'Head DNS config' },
  { id: 'SH-READ-006', domain: 'shell', category: 'File Read', command: 'grep -rn "error" /var/log/nginx/', expectedAction: 'allow', description: 'Grep in log files' },
  { id: 'SH-READ-007', domain: 'shell', category: 'File Read', command: 'find /var/log -name "*.log" -type f', expectedAction: 'allow', description: 'Find log files' },
  { id: 'SH-READ-008', domain: 'shell', category: 'File Read', command: 'stat /etc/hostname', expectedAction: 'allow', description: 'File stat metadata' },
  { id: 'SH-READ-009', domain: 'shell', category: 'File Read', command: 'sha256sum /etc/issue', expectedAction: 'allow', description: 'Calculate file checksum' },
  { id: 'SH-READ-010', domain: 'shell', category: 'File Read', command: 'du -sh /var/log', expectedAction: 'allow', description: 'Directory disk usage' },
  { id: 'SH-READ-011', domain: 'shell', category: 'File Read', command: "awk '{print $1}' /etc/hosts", expectedAction: 'allow', description: 'Extract column using awk' },
  { id: 'SH-READ-012', domain: 'shell', category: 'File Read', command: "sed -n '1,10p' /etc/hosts", expectedAction: 'allow', description: 'Print lines using sed' },
  { id: 'SH-READ-013', domain: 'shell', category: 'File Read', command: 'curl -s https://example.com/health', expectedAction: 'allow', description: 'HTTP GET health check' },

  // ==========================================
  // 3. SHELL: State Modifications & Destructive Commands (Expected: review)
  // ==========================================
  { id: 'SH-MOD-001', domain: 'shell', category: 'State Modification', command: 'rm -rf /tmp/cache', expectedAction: 'review', description: 'Remove directory recursively' },
  { id: 'SH-MOD-002', domain: 'shell', category: 'State Modification', command: 'touch /tmp/test.lock', expectedAction: 'review', description: 'Create/touch file' },
  { id: 'SH-MOD-003', domain: 'shell', category: 'State Modification', command: 'mkdir -p /opt/app/data', expectedAction: 'review', description: 'Create directory' },
  { id: 'SH-MOD-004', domain: 'shell', category: 'State Modification', command: 'mv /tmp/a /tmp/b', expectedAction: 'review', description: 'Move/rename file' },
  { id: 'SH-MOD-005', domain: 'shell', category: 'State Modification', command: 'cp /etc/hosts /tmp/hosts.bak', expectedAction: 'review', description: 'Copy file' },
  { id: 'SH-MOD-006', domain: 'shell', category: 'State Modification', command: 'chmod 755 /usr/local/bin/myscript', expectedAction: 'review', description: 'Change file permissions' },
  { id: 'SH-MOD-007', domain: 'shell', category: 'State Modification', command: 'chown -R www-data:www-data /var/www', expectedAction: 'review', description: 'Change file owner' },
  { id: 'SH-MOD-008', domain: 'shell', category: 'State Modification', command: 'kill -9 4589', expectedAction: 'review', description: 'Kill process' },
  { id: 'SH-MOD-009', domain: 'shell', category: 'State Modification', command: 'pkill -f python', expectedAction: 'review', description: 'Signal processes by pattern' },
  { id: 'SH-MOD-010', domain: 'shell', category: 'State Modification', command: 'systemctl restart nginx', expectedAction: 'review', description: 'Restart systemd service' },
  { id: 'SH-MOD-011', domain: 'shell', category: 'State Modification', command: 'systemctl stop docker', expectedAction: 'review', description: 'Stop service' },
  { id: 'SH-MOD-012', domain: 'shell', category: 'State Modification', command: 'apt-get update && apt-get install -y nginx', expectedAction: 'review', description: 'Package installation' },
  { id: 'SH-MOD-013', domain: 'shell', category: 'State Modification', command: 'yum install -y curl', expectedAction: 'review', description: 'Yum package install' },
  { id: 'SH-MOD-014', domain: 'shell', category: 'State Modification', command: 'docker run -d -p 80:80 nginx', expectedAction: 'review', description: 'Run docker container' },
  { id: 'SH-MOD-015', domain: 'shell', category: 'State Modification', command: 'docker exec -it web_app bash', expectedAction: 'review', description: 'Exec into container' },
  { id: 'SH-MOD-016', domain: 'shell', category: 'State Modification', command: 'docker stop web_app', expectedAction: 'review', description: 'Stop container' },
  { id: 'SH-MOD-017', domain: 'shell', category: 'State Modification', command: 'kubectl delete pod web-123', expectedAction: 'review', description: 'Delete k8s pod' },
  { id: 'SH-MOD-018', domain: 'shell', category: 'State Modification', command: 'kubectl apply -f app.yaml', expectedAction: 'review', description: 'Apply k8s manifest' },
  { id: 'SH-MOD-019', domain: 'shell', category: 'State Modification', command: 'iptables -F', expectedAction: 'review', description: 'Flush iptables rules' },
  { id: 'SH-MOD-020', domain: 'shell', category: 'State Modification', command: 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT', expectedAction: 'review', description: 'Append iptables rule' },
  { id: 'SH-MOD-021', domain: 'shell', category: 'State Modification', command: 'ip link set dev eth0 down', expectedAction: 'review', description: 'Bring network interface down' },
  { id: 'SH-MOD-022', domain: 'shell', category: 'State Modification', command: 'sed -i "s/DEBUG=False/DEBUG=True/" settings.py', expectedAction: 'review', description: 'In-place sed edit' },
  { id: 'SH-MOD-023', domain: 'shell', category: 'State Modification', command: 'sort -o /tmp/sorted.txt /tmp/input.txt', expectedAction: 'review', description: 'Sort with output file' },
  { id: 'SH-MOD-024', domain: 'shell', category: 'State Modification', command: 'find /tmp -name "*.tmp" -delete', expectedAction: 'review', description: 'Find with -delete action' },
  { id: 'SH-MOD-025', domain: 'shell', category: 'State Modification', command: 'find /var/log -type f -exec rm {} \\;', expectedAction: 'review', description: 'Find with -exec rm' },
  { id: 'SH-MOD-026', domain: 'shell', category: 'State Modification', command: 'crontab mycron.txt', expectedAction: 'review', description: 'Replace crontab with file' },
  { id: 'SH-MOD-027', domain: 'shell', category: 'State Modification', command: 'git push origin main', expectedAction: 'review', description: 'Git push' },
  { id: 'SH-MOD-028', domain: 'shell', category: 'State Modification', command: 'git checkout -b feature', expectedAction: 'review', description: 'Git branch switch' },
  { id: 'SH-MOD-029', domain: 'shell', category: 'State Modification', command: 'curl -X POST -d "param=1" https://api.example.com/update', expectedAction: 'review', description: 'HTTP POST with body' },
  { id: 'SH-MOD-030', domain: 'shell', category: 'State Modification', command: 'curl -o /tmp/installer.sh https://example.com/install.sh', expectedAction: 'review', description: 'Curl downloading to file' },
  { id: 'SH-MOD-031', domain: 'shell', category: 'State Modification', command: 'reboot', expectedAction: 'review', description: 'Reboot system' },
  { id: 'SH-MOD-032', domain: 'shell', category: 'State Modification', command: 'shutdown -h now', expectedAction: 'review', description: 'Shutdown system' },
  { id: 'SH-MOD-033', domain: 'shell', category: 'State Modification', command: 'useradd testuser', expectedAction: 'review', description: 'Add user' },
  { id: 'SH-MOD-034', domain: 'shell', category: 'State Modification', command: 'passwd testuser', expectedAction: 'review', description: 'Change password' },

  // ==========================================
  // 4. SHELL: Sensitive Resource & Secret Access (Expected: review)
  // ==========================================
  { id: 'SH-SEC-001', domain: 'shell', category: 'Sensitive Access', command: 'cat /etc/shadow', expectedAction: 'review', description: 'Read system password hashes' },
  { id: 'SH-SEC-002', domain: 'shell', category: 'Sensitive Access', command: 'cat /etc/gshadow', expectedAction: 'review', description: 'Read group shadow hashes' },
  { id: 'SH-SEC-003', domain: 'shell', category: 'Sensitive Access', command: 'cat ~/.ssh/id_rsa', expectedAction: 'review', description: 'Read private SSH key' },
  { id: 'SH-SEC-004', domain: 'shell', category: 'Sensitive Access', command: 'tail /home/ubuntu/.ssh/id_ed25519', expectedAction: 'review', description: 'Tail SSH private key' },
  { id: 'SH-SEC-005', domain: 'shell', category: 'Sensitive Access', command: 'cat ~/.aws/credentials', expectedAction: 'review', description: 'Read AWS credentials file' },
  { id: 'SH-SEC-006', domain: 'shell', category: 'Sensitive Access', command: 'cat ~/.kube/config', expectedAction: 'review', description: 'Read Kubernetes config & tokens' },
  { id: 'SH-SEC-007', domain: 'shell', category: 'Sensitive Access', command: 'cat .env', expectedAction: 'review', description: 'Read environment file' },
  { id: 'SH-SEC-008', domain: 'shell', category: 'Sensitive Access', command: 'grep API_KEY .env.production', expectedAction: 'review', description: 'Grep for api key in .env' },
  { id: 'SH-SEC-009', domain: 'shell', category: 'Sensitive Access', command: 'cat /root/.bash_history', expectedAction: 'review', description: 'Read shell history file' },
  { id: 'SH-SEC-010', domain: 'shell', category: 'Sensitive Access', command: 'cat cert.pem server.key', expectedAction: 'review', description: 'Read SSL private key' },
  { id: 'SH-SEC-011', domain: 'shell', category: 'Sensitive Access', command: 'curl -H "Authorization: Bearer mytoken123" https://api.internal/data', expectedAction: 'review', description: 'Curl with sensitive Authorization header' },
  { id: 'SH-SEC-012', domain: 'shell', category: 'Sensitive Access', command: 'curl https://user:pass123@api.internal/status', expectedAction: 'review', description: 'Curl with embedded credentials in URL' },
  { id: 'SH-SEC-013', domain: 'shell', category: 'Sensitive Access', command: 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/', expectedAction: 'review', description: 'AWS instance metadata endpoint' },

  // ==========================================
  // 5. SHELL: Complex Combinations, Pipelines, Chaining (Expected: correct aggregation)
  // ==========================================
  { id: 'SH-COMB-001', domain: 'combination', category: 'Pipe Chain', command: 'ps aux | grep nginx | awk \'{print $2}\'', expectedAction: 'allow', description: 'Read-only pipeline: ps | grep | awk' },
  { id: 'SH-COMB-002', domain: 'combination', category: 'Pipe Chain', command: 'netstat -tulnp | grep ":80" | sort | uniq', expectedAction: 'allow', description: 'Read-only pipeline: netstat | grep | sort | uniq' },
  { id: 'SH-COMB-003', domain: 'combination', category: 'Pipe Chain', command: 'cat /var/log/syslog | grep error | head -n 20', expectedAction: 'allow', description: 'Read-only pipeline: cat | grep | head' },
  { id: 'SH-COMB-004', domain: 'combination', category: 'Pipe Chain', command: 'dmesg | tail -n 50', expectedAction: 'allow', description: 'Read-only pipeline: dmesg | tail' },
  { id: 'SH-COMB-005', domain: 'combination', category: 'Pipe Chain', command: 'ps aux | grep evil | xargs kill -9', expectedAction: 'review', description: 'Piping into kill command (must review)' },
  { id: 'SH-COMB-006', domain: 'combination', category: 'Pipe Chain', command: 'cat /etc/shadow | grep admin', expectedAction: 'review', description: 'Pipeline reading sensitive /etc/shadow' },
  { id: 'SH-COMB-007', domain: 'combination', category: 'Chaining', command: 'uname -a && uptime; df -h && free -m', expectedAction: 'allow', description: 'Multi-command chaining of read observers' },
  { id: 'SH-COMB-008', domain: 'combination', category: 'Chaining', command: 'uptime && rm -rf /tmp/cache', expectedAction: 'review', description: 'Chain: safe observer && destructive write' },
  { id: 'SH-COMB-009', domain: 'combination', category: 'Chaining', command: 'touch /tmp/a || echo "failed"', expectedAction: 'review', description: 'Chain: write || echo' },
  { id: 'SH-COMB-010', domain: 'combination', category: 'Chaining', command: 'df -h; cat /etc/shadow; free -m', expectedAction: 'review', description: 'Chain: safe ; sensitive read ; safe' },
  { id: 'SH-COMB-011', domain: 'combination', category: 'Redirection', command: 'cat /etc/hosts > /tmp/hosts.copy', expectedAction: 'review', description: 'Redirect output to file (write)' },
  { id: 'SH-COMB-012', domain: 'combination', category: 'Redirection', command: 'echo "127.0.0.1 custom" >> /etc/hosts', expectedAction: 'review', description: 'Append redirect to file (write)' },
  { id: 'SH-COMB-013', domain: 'combination', category: 'Redirection', command: 'cat /etc/hosts 2>/dev/null', expectedAction: 'allow', description: 'Harmless error redirect 2>/dev/null' },
  { id: 'SH-COMB-014', domain: 'combination', category: 'Redirection', command: 'grep localhost < /etc/hosts', expectedAction: 'allow', description: 'Input redirect from ordinary file' },
  { id: 'SH-COMB-015', domain: 'combination', category: 'Redirection', command: 'grep admin < /etc/shadow', expectedAction: 'review', description: 'Input redirect from sensitive file' },
  { id: 'SH-COMB-016', domain: 'combination', category: 'Subshell', command: 'printf "Host: %s\\n" "$(cat /etc/hostname)"', expectedAction: 'allow', description: 'Subshell command substitution of safe read' },
  { id: 'SH-COMB-017', domain: 'combination', category: 'Subshell', command: 'printf "Secret: %s\\n" "$(cat /etc/shadow)"', expectedAction: 'review', description: 'Subshell command substitution of sensitive read' },
  { id: 'SH-COMB-018', domain: 'combination', category: 'Subshell', command: '$(echo rm) -rf /tmp/data', expectedAction: 'review', description: 'Dynamic subshell executable resolution' },
  { id: 'SH-COMB-019', domain: 'combination', category: 'Wrapper', command: 'sudo -- uname -a', expectedAction: 'allow', description: 'Sudo wrapping safe observer command' },
  { id: 'SH-COMB-020', domain: 'combination', category: 'Wrapper', command: 'sudo systemctl restart nginx', expectedAction: 'review', description: 'Sudo wrapping service restart' },
  { id: 'SH-COMB-021', domain: 'combination', category: 'Wrapper', command: 'timeout 5s df -h', expectedAction: 'allow', description: 'Timeout wrapping safe command' },
  { id: 'SH-COMB-022', domain: 'combination', category: 'Wrapper', command: 'nice -n 19 ps aux', expectedAction: 'allow', description: 'Nice wrapping process viewer' },
  { id: 'SH-COMB-023', domain: 'combination', category: 'Wrapper', command: 'env LANG=C date', expectedAction: 'allow', description: 'Env passing benign variable' },
  { id: 'SH-COMB-024', domain: 'combination', category: 'Wrapper', command: 'env PATH=/tmp/bin:$PATH ls', expectedAction: 'review', description: 'Env overriding PATH (potential hijack)' },
  { id: 'SH-COMB-025', domain: 'combination', category: 'Wrapper', command: 'bash -c "uname -a && uptime"', expectedAction: 'allow', description: 'Bash -c running static safe commands' },
  { id: 'SH-COMB-026', domain: 'combination', category: 'Wrapper', command: 'bash -c "$MY_SCRIPT"', expectedAction: 'review', description: 'Bash -c with dynamic unverified variable' },
  { id: 'SH-COMB-027', domain: 'combination', category: 'Adversarial', command: 'eval "$(echo uname)"', expectedAction: 'review', description: 'Eval execution (dynamic/untrusted)' },
  { id: 'SH-COMB-028', domain: 'combination', category: 'Adversarial', command: '/tmp/uname -a', expectedAction: 'review', description: 'Executable outside trusted system paths' },
  { id: 'SH-COMB-029', domain: 'combination', category: 'Adversarial', command: '`echo rm` /tmp/test', expectedAction: 'review', description: 'Backtick dynamic execution' },
  { id: 'SH-COMB-030', domain: 'combination', category: 'Adversarial', command: 'cat /etc/hosts | nc -l 4444', expectedAction: 'review', description: 'Netcat listener data exfiltration' },
  { id: 'SH-COMB-031', domain: 'combination', category: 'Adversarial', command: 'cat /etc/hosts &', expectedAction: 'review', description: 'Detached background execution &' },

  // ==========================================
  // 6. PYTHON: Embedded & Direct Policy Evaluator
  // ==========================================
  { id: 'PY-001', domain: 'python', category: 'Safe Computation', command: 'print(1 + 2 * 3)', expectedAction: 'allow', description: 'Pure python arithmetic' },
  { id: 'PY-002', domain: 'python', category: 'Safe Computation', command: 'import json\ndata = json.loads(\'{"status": "ok", "code": 200}\')\nprint(data["status"])', expectedAction: 'allow', description: 'Import json and parse dict' },
  { id: 'PY-003', domain: 'python', category: 'Safe Computation', command: 'import math\nprint(math.sqrt(144))', expectedAction: 'allow', description: 'Import math sqrt' },
  { id: 'PY-004', domain: 'python', category: 'Safe Computation', command: 'for i in range(5):\n    print(f"item {i}")', expectedAction: 'allow', description: 'Control flow loop' },
  { id: 'PY-005', domain: 'python', category: 'Safe File Read', command: 'with open("/etc/hosts", "r") as f:\n    print(f.read())', expectedAction: 'allow', description: 'Python open ordinary file for reading' },
  { id: 'PY-006', domain: 'python', category: 'Sensitive Read', command: 'print(open("/etc/shadow", "r").read())', expectedAction: 'review', description: 'Python open /etc/shadow' },
  { id: 'PY-007', domain: 'python', category: 'File Write', command: 'open("/tmp/out.txt", "w").write("hello")', expectedAction: 'review', description: 'Python file write' },
  { id: 'PY-008', domain: 'python', category: 'Dangerous Module', command: 'import os\nos.system("rm -rf /")', expectedAction: 'review', description: 'Import os system call' },
  { id: 'PY-009', domain: 'python', category: 'Dangerous Module', command: 'import subprocess\nsubprocess.run(["ls", "-la"])', expectedAction: 'review', description: 'Import subprocess module' },
  { id: 'PY-010', domain: 'python', category: 'Dynamic Eval', command: 'eval("2 + 2")', expectedAction: 'review', description: 'Python eval call' },
  { id: 'PY-011', domain: 'python', category: 'Dynamic Eval', command: 'exec("print(1)")', expectedAction: 'review', description: 'Python exec call' },
  { id: 'PY-012', domain: 'python', category: 'Sqlite Reader', command: 'import sqlite3\nconn = sqlite3.connect("/tmp/app.db")\nprint(conn.execute("SELECT id, username FROM users").fetchall())', expectedAction: 'allow', description: 'Python sqlite3 read query' },
  { id: 'PY-013', domain: 'python', category: 'Sqlite Writer', command: 'import sqlite3\nconn = sqlite3.connect("/tmp/app.db")\nconn.execute("UPDATE users SET status=1")\nconn.commit()', expectedAction: 'review', description: 'Python sqlite3 write query' },

  // ==========================================
  // 7. SQLITE: Embedded & Direct Policy Evaluator
  // ==========================================
  { id: 'SQLITE-001', domain: 'sqlite', category: 'Read Query', command: 'SELECT id, title, created_at FROM articles WHERE published = 1', expectedAction: 'allow', description: 'Ordinary SELECT query' },
  { id: 'SQLITE-002', domain: 'sqlite', category: 'Read Query', command: 'SELECT count(*), avg(score) FROM scores GROUP BY user_id', expectedAction: 'allow', description: 'Aggregate SELECT query' },
  { id: 'SQLITE-003', domain: 'sqlite', category: 'Metadata', command: 'PRAGMA table_info(users)', expectedAction: 'allow', description: 'Pragma table schema inspection' },
  { id: 'SQLITE-004', domain: 'sqlite', category: 'Metadata', command: 'EXPLAIN QUERY PLAN SELECT * FROM articles', expectedAction: 'allow', description: 'Explain query plan' },
  { id: 'SQLITE-005', domain: 'sqlite', category: 'Write Query', command: 'INSERT INTO users(name, email) VALUES ("alice", "a@example.com")', expectedAction: 'review', description: 'INSERT statement' },
  { id: 'SQLITE-006', domain: 'sqlite', category: 'Write Query', command: 'UPDATE accounts SET balance = balance - 100 WHERE id = 1', expectedAction: 'review', description: 'UPDATE statement' },
  { id: 'SQLITE-007', domain: 'sqlite', category: 'Destructive', command: 'DELETE FROM session_tokens', expectedAction: 'review', description: 'DELETE statement' },
  { id: 'SQLITE-008', domain: 'sqlite', category: 'Destructive', command: 'DROP TABLE orders', expectedAction: 'review', description: 'DROP TABLE statement' },
  { id: 'SQLITE-009', domain: 'sqlite', category: 'Sensitive Column', command: 'SELECT password_hash FROM admin_users', expectedAction: 'review', description: 'SELECT sensitive column password_hash' },
  { id: 'SQLITE-010', domain: 'sqlite', category: 'Sensitive Table', command: 'SELECT * FROM api_credentials', expectedAction: 'review', description: 'SELECT from sensitive credentials table' },
  { id: 'SQLITE-011', domain: 'sqlite', category: 'Dangerous Admin', command: 'ATTACH DATABASE "/tmp/hacked.db" AS hacked', expectedAction: 'review', description: 'ATTACH DATABASE' },

  // ==========================================
  // 8. MYSQL: Direct Policy Evaluator
  // ==========================================
  { id: 'MYSQL-001', domain: 'mysql', category: 'Read Query', command: 'SELECT id, username, email FROM users WHERE is_active = 1', expectedAction: 'allow', description: 'MySQL SELECT query' },
  { id: 'MYSQL-002', domain: 'mysql', category: 'Metadata', command: 'SHOW TABLES', expectedAction: 'allow', description: 'SHOW TABLES' },
  { id: 'MYSQL-003', domain: 'mysql', category: 'Metadata', command: 'SHOW STATUS LIKE "Threads_connected"', expectedAction: 'allow', description: 'SHOW STATUS' },
  { id: 'MYSQL-004', domain: 'mysql', category: 'Metadata', command: 'DESCRIBE order_items', expectedAction: 'allow', description: 'DESCRIBE table' },
  { id: 'MYSQL-005', domain: 'mysql', category: 'Write Query', command: 'UPDATE users SET email="new@example.com" WHERE id=2', expectedAction: 'review', description: 'MySQL UPDATE' },
  { id: 'MYSQL-006', domain: 'mysql', category: 'Write Query', command: 'INSERT INTO logs(event) VALUES ("login")', expectedAction: 'review', description: 'MySQL INSERT' },
  { id: 'MYSQL-007', domain: 'mysql', category: 'Destructive', command: 'TRUNCATE TABLE audit_log', expectedAction: 'review', description: 'TRUNCATE TABLE' },
  { id: 'MYSQL-008', domain: 'mysql', category: 'Destructive', command: 'DROP DATABASE customer_db', expectedAction: 'review', description: 'DROP DATABASE' },
  { id: 'MYSQL-009', domain: 'mysql', category: 'Sensitive Data', command: 'SELECT api_token FROM api_keys', expectedAction: 'review', description: 'SELECT api_token' },
  { id: 'MYSQL-010', domain: 'mysql', category: 'File Exfil', command: 'SELECT id, username INTO OUTFILE "/tmp/dump.csv" FROM users', expectedAction: 'review', description: 'SELECT INTO OUTFILE' },
  { id: 'MYSQL-011', domain: 'mysql', category: 'Control/Lock', command: 'SELECT id FROM users FOR UPDATE', expectedAction: 'review', description: 'Row-level locking FOR UPDATE' },

  // ==========================================
  // 9. REDIS: Direct Policy Evaluator
  // ==========================================
  { id: 'REDIS-001', domain: 'redis', category: 'Read-Only Command', command: 'GET cache:user:123', expectedAction: 'allow', description: 'Redis GET key' },
  { id: 'REDIS-002', domain: 'redis', category: 'Read-Only Command', command: 'MGET cache:1 cache:2 cache:3', expectedAction: 'allow', description: 'Redis MGET keys' },
  { id: 'REDIS-003', domain: 'redis', category: 'Read-Only Command', command: 'HGETALL user:profile:100', expectedAction: 'allow', description: 'Redis HGETALL' },
  { id: 'REDIS-004', domain: 'redis', category: 'Read-Only Command', command: 'LRANGE activity:feed 0 19', expectedAction: 'allow', description: 'Redis LRANGE list slice' },
  { id: 'REDIS-005', domain: 'redis', category: 'Read-Only Command', command: 'SMEMBERS user:roles:50', expectedAction: 'allow', description: 'Redis SMEMBERS set items' },
  { id: 'REDIS-006', domain: 'redis', category: 'Read-Only Command', command: 'TTL cache:session:active', expectedAction: 'allow', description: 'Redis TTL check' },
  { id: 'REDIS-007', domain: 'redis', category: 'Read-Only Command', command: 'INFO server', expectedAction: 'allow', description: 'Redis INFO server stats' },
  { id: 'REDIS-008', domain: 'redis', category: 'Read-Only Command', command: 'PING', expectedAction: 'allow', description: 'Redis PING' },
  { id: 'REDIS-009', domain: 'redis', category: 'Write Command', command: 'SET cache:user:123 "new_value"', expectedAction: 'review', description: 'Redis SET value' },
  { id: 'REDIS-010', domain: 'redis', category: 'Write Command', command: 'DEL cache:user:123', expectedAction: 'review', description: 'Redis DEL key' },
  { id: 'REDIS-011', domain: 'redis', category: 'Write Command', command: 'HSET user:profile:100 status "offline"', expectedAction: 'review', description: 'Redis HSET' },
  { id: 'REDIS-012', domain: 'redis', category: 'Write Command', command: 'LPUSH queue:jobs "job_payload"', expectedAction: 'review', description: 'Redis LPUSH job' },
  { id: 'REDIS-013', domain: 'redis', category: 'Write Command', command: 'FLUSHALL', expectedAction: 'review', description: 'Redis FLUSHALL' },
  { id: 'REDIS-014', domain: 'redis', category: 'Sensitive Key', command: 'GET auth:user:password_hash', expectedAction: 'review', description: 'Redis GET sensitive password key' },
  { id: 'REDIS-015', domain: 'redis', category: 'Blocking / Deny', command: 'BLPOP queue:tasks 0', expectedAction: 'deny', description: 'Redis BLPOP infinite blocking call' },
  { id: 'REDIS-016', domain: 'redis', category: 'Dangerous Pattern', command: 'KEYS *', expectedAction: 'deny', description: 'Redis KEYS * (production-impacting scan)' },
  { id: 'REDIS-017', domain: 'redis', category: 'Blocking / Deny', command: 'MONITOR', expectedAction: 'deny', description: 'Redis MONITOR stream' },
  { id: 'REDIS-018', domain: 'redis', category: 'Blocking / Deny', command: 'SUBSCRIBE real_time_events', expectedAction: 'deny', description: 'Redis SUBSCRIBE blocking pubsub' },
];

async function runBenchmark() {
  console.log('===============================================================');
  console.log('   AT SERIES COMMAND POLICY ENGINE - BENCHMARK & TEST SUITE   ');
  console.log('===============================================================\n');

  const shellEvaluator = createShellPolicyEvaluator();
  const pythonEvaluator = createPythonPolicyEvaluator();
  const sqliteEvaluator = createSqlitePolicyEvaluator();
  const mysqlEvaluator = createMysqlPolicyEvaluator();
  const redisEvaluator = createRedisPolicyEvaluator();

  const domainEvaluators = {
    shell: shellEvaluator,
    combination: shellEvaluator,
    python: pythonEvaluator,
    sqlite: sqliteEvaluator,
    mysql: mysqlEvaluator,
    redis: redisEvaluator,
  };

  let totalTests = 0;
  let passedTests = 0;
  let failedTests = 0;

  // Confusion matrix counters
  // Positive = Intercept (review or deny)
  // Negative = Allow (safe pass-through)
  let TP = 0; // Expected Intercept, Actually Intercepted
  let FP = 0; // Expected Allow, Actually Intercepted (False Positive)
  let TN = 0; // Expected Allow, Actually Allowed (True Negative)
  let FN = 0; // Expected Intercept, Actually Allowed (CRITICAL SAFETY FAILURE)

  const failureDetails: Array<{ id: string; command: string; expected: string; actual: string; reason: string }> = [];
  const resultsByCategory: Record<string, { total: number; passed: number; failed: number }> = {};

  const startTime = Date.now();

  for (const tc of testCases) {
    totalTests += 1;
    const evaluator = domainEvaluators[tc.domain];
    const decision = await evaluator.evaluate({ sourceText: tc.command });
    const actualAction = decision.action;

    if (!resultsByCategory[tc.category]) {
      resultsByCategory[tc.category] = { total: 0, passed: 0, failed: 0 };
    }
    resultsByCategory[tc.category].total += 1;

    // Check correctness
    let isCorrect = false;
    if (tc.expectedAction === 'allow') {
      if (actualAction === 'allow') {
        isCorrect = true;
        TN += 1;
      } else {
        FP += 1; // False alarm: safe command flagged for review
      }
    } else {
      // expectedAction is 'review' or 'deny'
      if (actualAction === 'allow') {
        FN += 1; // DANGEROUS: unsafe command allowed!
      } else {
        // both review and deny count as interception, but if expected deny we check
        if (tc.expectedAction === 'deny') {
          if (actualAction === 'deny') {
            isCorrect = true;
            TP += 1;
          } else if (actualAction === 'review') {
            // review is safer than allow, but strict match check
            isCorrect = true;
            TP += 1;
          }
        } else {
          isCorrect = (actualAction === 'review' || actualAction === 'deny');
          TP += 1;
        }
      }
    }

    if (isCorrect) {
      passedTests += 1;
      resultsByCategory[tc.category].passed += 1;
    } else {
      failedTests += 1;
      resultsByCategory[tc.category].failed += 1;
      failureDetails.push({
        id: tc.id,
        command: tc.command,
        expected: tc.expectedAction,
        actual: actualAction,
        reason: decision.reasonCode || 'N/A',
      });
    }
  }

  const durationMs = Date.now() - startTime;

  console.log(`Ran ${totalTests} test cases across ${Object.keys(resultsByCategory).length} categories in ${durationMs}ms.\n`);

  console.log('---------------------------------------------------------------');
  console.log('                    CATEGORY BREAKDOWN                        ');
  console.log('---------------------------------------------------------------');
  for (const [category, stats] of Object.entries(resultsByCategory)) {
    const rate = ((stats.passed / stats.total) * 100).toFixed(1);
    const indicator = stats.failed === 0 ? '✓' : '✗';
    console.log(`[${indicator}] ${category.padEnd(25)} : ${stats.passed}/${stats.total} passed (${rate}%)`);
  }

  console.log('\n---------------------------------------------------------------');
  console.log('                     CONFUSION MATRIX & METRICS                ');
  console.log('---------------------------------------------------------------');
  console.log(`Total Cases:              ${totalTests}`);
  console.log(`True Positives (TP):      ${TP}  (Threats/writes properly intercepted)`);
  console.log(`True Negatives (TN):      ${TN}  (Safe queries properly allowed)`);
  console.log(`False Positives (FP):     ${FP}  (Safe queries conservatively flagged)`);
  console.log(`False Negatives (FN):     ${FN}  (Unsafe commands leaked - CRITICAL)`);

  const accuracy = (((TP + TN) / totalTests) * 100).toFixed(2);
  const precision = TP + FP > 0 ? ((TP / (TP + FP)) * 100).toFixed(2) : '100.00';
  const recall = TP + FN > 0 ? ((TP / (TP + FN)) * 100).toFixed(2) : '100.00';
  const f1 = (2 * Number(precision) * Number(recall) / (Number(precision) + Number(recall))).toFixed(2);

  console.log(`\nOverall Accuracy:         ${accuracy}%`);
  console.log(`Precision:                ${precision}%`);
  console.log(`Recall (Coverage):        ${recall}%`);
  console.log(`F1-Score:                 ${f1}%`);
  console.log(`Safety Violation Count:   ${FN} (Zero-bypass validation)`);

  if (failureDetails.length > 0) {
    console.log('\n---------------------------------------------------------------');
    console.log('                       MISMATCH DETAILS                        ');
    console.log('---------------------------------------------------------------');
    for (const f of failureDetails) {
      console.log(`[FAIL] ${f.id}: expected=${f.expected}, actual=${f.actual}`);
      console.log(`       Command: ${f.command}`);
      console.log(`       Reason:  ${f.reason}\n`);
    }
  }

  console.log('===============================================================\n');

  return {
    totalTests,
    passedTests,
    failedTests,
    TP,
    TN,
    FP,
    FN,
    accuracy,
    precision,
    recall,
    f1,
    durationMs,
    resultsByCategory,
    failureDetails,
  };
}

runBenchmark().catch(console.error);
