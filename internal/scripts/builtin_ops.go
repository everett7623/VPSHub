package scripts

import "github.com/evenfrank/vpshub/internal/store"

// opsBuiltins extend the catalog with cleanup / security / optimize / monitor scripts.
// Low-risk read-only scripts ship published so operators can run them immediately.
// Mutating scripts stay draft until reviewed.
var opsBuiltins = []store.Script{
	{
		Name: "security-baseline", Category: "security", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
echo "=== sshd ==="
sshd -T 2>/dev/null | awk '/^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|maxauthtries) /{print}' || echo "sshd -T unavailable"
echo "=== firewall ==="
if command -v ufw >/dev/null 2>&1; then ufw status verbose 2>/dev/null || true
elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state 2>/dev/null; firewall-cmd --list-all 2>/dev/null || true
elif command -v nft >/dev/null 2>&1; then nft list ruleset 2>/dev/null | head -n 80 || true
else echo "no ufw/firewalld/nft detected"; fi
echo "=== fail2ban ==="
command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status 2>/dev/null || echo "fail2ban not installed"
echo "=== unattended upgrades ==="
systemctl is-enabled unattended-upgrades 2>/dev/null || systemctl is-enabled dnf-automatic.timer 2>/dev/null || echo "auto-updates unit not found"
`,
	},
	{
		Name: "conn-summary", Category: "network", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
echo "=== ss -s ==="
ss -s 2>/dev/null || true
echo "=== top listeners ==="
ss -lntupH 2>/dev/null | head -n 40 || netstat -lntup 2>/dev/null | head -n 40 || true
echo "=== established count by remote ==="
ss -ntH state established 2>/dev/null | awk '{print $5}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -nr | head -n 20 || true
`,
	},
	{
		Name: "process-top", Category: "ops", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
echo "=== load / mem ==="
uptime; free -h 2>/dev/null || true
echo "=== cpu top ==="
ps aux --sort=-%cpu 2>/dev/null | head -n 12 || ps aux | head -n 12
echo "=== mem top ==="
ps aux --sort=-%mem 2>/dev/null | head -n 12 || true
`,
	},
	{
		Name: "disk-inodes", Category: "ops", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: "#!/bin/sh\ndf -P; echo; df -Pi 2>/dev/null || df -i\n",
	},
	{
		Name: "large-files-tmp", Category: "ops", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
echo "=== /tmp /var/tmp /var/log large files (>50M) ==="
find /tmp /var/tmp /var/log -xdev -type f -size +50M 2>/dev/null | head -n 40
echo "=== journal disk ==="
journalctl --disk-usage 2>/dev/null || true
`,
	},
	{
		Name: "docker-prune-dry", Category: "docker-install", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
docker system df 2>/dev/null || { echo "docker not available"; exit 0; }
echo "=== prune dry-run ==="
docker system prune -af --volumes --dry-run 2>/dev/null || docker system prune -af --dry-run 2>/dev/null || true
`,
	},
	{
		Name: "docker-prune", Category: "docker-install", Version: "1.0.0", RiskLevel: "high",
		AllowBatch: false, AllowProduction: false, Status: "draft", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
# Destructive: removes unused containers/images/networks/volumes.
docker system df 2>/dev/null || { echo "docker not available"; exit 1; }
docker system prune -af --volumes
docker system df
`,
	},
	{
		Name: "apt-autoremove-dry", Category: "maintenance", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
if command -v apt-get >/dev/null 2>&1; then
  apt-get -s autoremove 2>/dev/null | tail -n 40
elif command -v dnf >/dev/null 2>&1; then
  dnf -q list --autoremove 2>/dev/null | head -n 40
else
  echo "apt/dnf not available"
fi
`,
	},
	{
		Name: "apt-autoremove", Category: "maintenance", Version: "1.0.0", RiskLevel: "medium",
		AllowBatch: false, AllowProduction: false, Status: "draft", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get -y autoremove --purge
elif command -v dnf >/dev/null 2>&1; then
  dnf -y autoremove
else
  echo "apt/dnf not available"; exit 1
fi
`,
	},
	{
		Name: "journal-vacuum", Category: "maintenance", Version: "1.0.0", RiskLevel: "medium",
		AllowBatch: true, AllowProduction: false, Status: "draft", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
journalctl --disk-usage 2>/dev/null || true
journalctl --vacuum-size=200M 2>/dev/null || journalctl --vacuum-time=7d 2>/dev/null || true
journalctl --disk-usage 2>/dev/null || true
`,
	},
	{
		Name: "sysctl-network-tune-check", Category: "ops", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
echo "=== current (read-only) ==="
sysctl net.core.somaxconn net.ipv4.tcp_tw_reuse net.ipv4.ip_local_port_range net.ipv4.tcp_max_syn_backlog 2>/dev/null || true
echo "=== suggestions (not applied) ==="
echo "net.core.somaxconn >= 1024 for busy reverse proxies"
echo "ensure BBR: sysctl net.ipv4.tcp_congestion_control"
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || true
`,
	},
	{
		Name: "auth-log-tail", Category: "security", Version: "1.0.0", RiskLevel: "low",
		AllowBatch: true, AllowProduction: true, Status: "published", Source: "builtin", CreatedBy: "system",
		Content: `#!/bin/sh
echo "=== recent auth failures ==="
if [ -f /var/log/auth.log ]; then
  grep -E 'Failed password|Invalid user|authentication failure' /var/log/auth.log 2>/dev/null | tail -n 40
elif [ -f /var/log/secure ]; then
  grep -E 'Failed password|Invalid user|authentication failure' /var/log/secure 2>/dev/null | tail -n 40
else
  journalctl -u ssh -u sshd --no-pager -n 80 2>/dev/null | grep -Ei 'fail|invalid|auth' | tail -n 40 || echo "no auth log"
fi
`,
	},
}
