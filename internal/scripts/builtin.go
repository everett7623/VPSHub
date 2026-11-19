package scripts

import "github.com/evenfrank/vpshub/internal/store"

// builtins are read-only drafts. They stay unapproved until an operator reviews them.
var builtins = []store.Script{
	{
		Name: "disk-report", Category: "backup", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\ndf -P\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "reboot-required", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nif [ -f /var/run/reboot-required ]; then echo yes; exit 0; fi\necho no\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "docker-ps", Category: "docker-install", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\ndocker ps -a --format '{{.Names}} {{.Image}} {{.Status}}'\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "failed-units", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nsystemctl --failed --no-pager --no-legend || true\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "listening-ports", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nss -lntuH 2>/dev/null || netstat -lntu 2>/dev/null || true\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "cert-files-present", Category: "backup", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nfor f in /etc/nginx /etc/caddy /etc/letsencrypt; do\n  if [ -e \"$f\" ]; then echo present \"$f\"; else echo absent \"$f\"; fi\ndone\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "security-update-count", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: `#!/bin/sh
# Read-only count. Does not install packages.
n=0
if command -v apt-get >/dev/null 2>&1; then
  n=$(apt-get -s upgrade 2>/dev/null | awk 'BEGIN{c=0} /^Inst / && /[Ss]ecurity/{c++} END{print c+0}' || true)
elif command -v dnf >/dev/null 2>&1; then
  n=$(dnf -q updateinfo list security 2>/dev/null | awk 'NF>=3 && $1 !~ /^Last/{c++} END{print c+0}' || true)
elif command -v yum >/dev/null 2>&1; then
  n=$(yum -q updateinfo list security 2>/dev/null | awk 'NF>=3 && $1 !~ /^Last/{c++} END{print c+0}' || true)
fi
case "$n" in
  ''|*[!0-9]*) n=0 ;;
esac
echo "$n"
`,
		Source: "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "uptime-load", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nuptime\ncat /proc/loadavg 2>/dev/null || true\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "swap-report", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nswapon --show 2>/dev/null || true\nfree -h 2>/dev/null || true\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "os-release", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\ncat /etc/os-release 2>/dev/null || true\nuname -a\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "ipv6-addresses", Category: "network", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nip -6 addr show 2>/dev/null || ifconfig -a 2>/dev/null || true\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "echo-params", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content:      "#!/bin/sh\necho \"MSG=${MSG:-}\"\necho \"TAG=${TAG:-}\"\n",
		ParamsSchema: `[{"name":"MSG","required":true},{"name":"TAG"}]`,
		Source:       "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "fail2ban-status", Category: "security", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\nif command -v fail2ban-client >/dev/null 2>&1; then\n  fail2ban-client status 2>/dev/null || true\nelse\n  echo 'fail2ban-client not installed'\nfi\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "docker-disk", Category: "docker-install", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\ndocker system df 2>/dev/null || echo 'docker not available'\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
	{
		Name: "timedate-sync", Category: "system-init", Version: "1.0.0", RiskLevel: "low",
		Content: "#!/bin/sh\ntimedatectl status 2>/dev/null || date -u\n",
		Source:  "builtin", Status: "draft", CreatedBy: "system",
	},
}

// Seed inserts missing builtin scripts. Existing rows are left untouched.
func Seed(db *store.DB) error {
	all := append(append([]store.Script{}, builtins...), opsBuiltins...)
	for i := range all {
		sc := all[i]
		exists, err := db.ScriptNameExists(sc.Name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		sc.SHA256 = ContentSHA256(sc.Content)
		if sc.OSFilter == "" {
			sc.OSFilter = "[]"
		}
		if sc.ParamsSchema == "" {
			sc.ParamsSchema = "[]"
		}
		if sc.Status == "" {
			sc.Status = "draft"
		}
		if sc.Source == "" {
			sc.Source = "builtin"
		}
		if _, err := db.CreateScript(&sc); err != nil {
			return err
		}
	}
	return nil
}
