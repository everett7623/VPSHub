package services

import (
	"fmt"
	"strings"
)

// Module describes a dedicated upgrade path (not a generic script).
type Module struct {
	Name          string   `json:"name"`
	DetectCmd     string   `json:"detect_cmd,omitempty"`
	LatestHint    string   `json:"latest_hint,omitempty"`
	ConfigPaths   []string `json:"config_paths,omitempty"`
	BackupPaths   []string `json:"backup_paths,omitempty"`
	InstallSteps  []string `json:"install_steps,omitempty"`
	HealthChecks  []string `json:"health_checks,omitempty"`
	RollbackSteps []string `json:"rollback_steps,omitempty"`
	SupportedOS   []string `json:"supported_os,omitempty"`
	RiskLevel     string   `json:"risk_level"`
	Dependencies  []string `json:"dependencies"`
	// InstallBin is the fixed destination for binary-style artifact installs.
	// Empty means package-style: verify download only (use SysUpgradePlan for apt/dnf).
	InstallBin string `json:"install_bin,omitempty"`
	// SystemdUnits are restarted after a successful binary install when non-empty.
	SystemdUnits []string `json:"systemd_units,omitempty"`
}

var Registry = map[string]*Module{
	"komari": {
		Name: "komari", DetectCmd: "command -v komari && komari version 2>/dev/null || true",
		ConfigPaths: []string{"/etc/komari"}, BackupPaths: []string{"/etc/komari"},
		InstallBin: "/usr/local/bin/komari", SystemdUnits: []string{"komari"},
		InstallSteps: []string{"install binary to /usr/local/bin/komari"}, HealthChecks: []string{"systemctl is-active komari || pgrep -x komari"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"komari-lite": {
		Name: "komari-lite", DetectCmd: "command -v komari-lite && komari-lite version 2>/dev/null || true",
		ConfigPaths: []string{"/etc/komari-lite"}, BackupPaths: []string{"/etc/komari-lite"},
		InstallBin: "/usr/local/bin/komari-lite", SystemdUnits: []string{"komari-lite"},
		InstallSteps: []string{"install binary to /usr/local/bin/komari-lite"}, HealthChecks: []string{"systemctl is-active komari-lite || pgrep -x komari-lite"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"nezha": {
		Name: "nezha", DetectCmd: "systemctl cat nezha-agent 2>/dev/null | head -n1 || true",
		ConfigPaths: []string{"/opt/nezha"}, BackupPaths: []string{"/opt/nezha"},
		InstallBin: "/opt/nezha/nezha-agent", SystemdUnits: []string{"nezha-agent"},
		InstallSteps: []string{"install binary to /opt/nezha/nezha-agent"}, HealthChecks: []string{"systemctl is-active nezha-agent"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "medium", SupportedOS: []string{"linux"},
	},
	"xray": {
		Name: "xray", DetectCmd: "xray version 2>/dev/null | head -n1 || true",
		ConfigPaths: []string{"/usr/local/etc/xray", "/etc/xray"}, BackupPaths: []string{"/usr/local/etc/xray", "/etc/xray"},
		InstallBin: "/usr/local/bin/xray", SystemdUnits: []string{"xray"},
		InstallSteps: []string{"install binary to /usr/local/bin/xray"}, HealthChecks: []string{"systemctl is-active xray", "pgrep -x xray"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high",
		Dependencies: []string{"certificates"}, SupportedOS: []string{"linux"},
	},
	"sing-box": {
		Name: "sing-box", DetectCmd: "sing-box version 2>/dev/null | head -n1 || true",
		ConfigPaths: []string{"/etc/sing-box"}, BackupPaths: []string{"/etc/sing-box"},
		InstallBin: "/usr/local/bin/sing-box", SystemdUnits: []string{"sing-box"},
		InstallSteps: []string{"install binary to /usr/local/bin/sing-box"}, HealthChecks: []string{"systemctl is-active sing-box"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"hysteria2": {
		Name: "hysteria2", DetectCmd: "hysteria version 2>/dev/null || true",
		ConfigPaths: []string{"/etc/hysteria"}, BackupPaths: []string{"/etc/hysteria"},
		InstallBin: "/usr/local/bin/hysteria", SystemdUnits: []string{"hysteria-server", "hysteria2"},
		InstallSteps: []string{"install binary to /usr/local/bin/hysteria"}, HealthChecks: []string{"systemctl is-active hysteria-server || systemctl is-active hysteria2"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high",
		SupportedOS: []string{"linux"},
	},
	"shadowsocks-rust": {
		Name: "shadowsocks-rust", DetectCmd: "ssserver --version 2>/dev/null || true",
		ConfigPaths: []string{"/etc/shadowsocks-rust"}, BackupPaths: []string{"/etc/shadowsocks-rust"},
		InstallBin: "/usr/local/bin/ssserver", SystemdUnits: []string{"shadowsocks-rust"},
		InstallSteps: []string{"install binary to /usr/local/bin/ssserver"}, HealthChecks: []string{"systemctl is-active shadowsocks-rust"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"anytls": {
		Name: "anytls", DetectCmd: "command -v anytls-server || true",
		ConfigPaths: []string{"/etc/anytls"}, BackupPaths: []string{"/etc/anytls"},
		InstallBin:   "/usr/local/bin/anytls-server",
		InstallSteps: []string{"install binary to /usr/local/bin/anytls-server"}, HealthChecks: []string{"pgrep -f anytls"},
		RollbackSteps: []string{"restore binary and config from BACKUP_DIR"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"nginx": {
		Name: "nginx", DetectCmd: "nginx -v 2>&1 || true",
		ConfigPaths: []string{"/etc/nginx"}, BackupPaths: []string{"/etc/nginx"},
		InstallSteps: []string{"# package module: verify artifact only; use sysupgrade for apt/dnf"}, HealthChecks: []string{"nginx -t", "systemctl is-active nginx"}, RiskLevel: "high",
		Dependencies: []string{"docker"}, SupportedOS: []string{"linux"},
	},
	"caddy": {
		Name: "caddy", DetectCmd: "caddy version 2>/dev/null || true",
		ConfigPaths: []string{"/etc/caddy"}, BackupPaths: []string{"/etc/caddy"},
		InstallSteps: []string{"# package module: verify artifact only; use sysupgrade for apt/dnf"}, HealthChecks: []string{"systemctl is-active caddy"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"docker": {
		Name: "docker", DetectCmd: "docker version --format '{{.Server.Version}}' 2>/dev/null || true",
		ConfigPaths: []string{"/etc/docker"}, BackupPaths: []string{"/etc/docker"},
		InstallSteps: []string{"# package module: verify artifact only; use sysupgrade for apt/dnf"}, HealthChecks: []string{"systemctl is-active docker", "docker info >/dev/null"}, RiskLevel: "high", SupportedOS: []string{"linux"},
	},
	"docker-compose": {
		Name: "docker-compose", DetectCmd: "docker compose version --short 2>/dev/null || true",
		ConfigPaths: []string{}, BackupPaths: []string{},
		InstallSteps: []string{"# package/plugin module: verify artifact only"}, HealthChecks: []string{"docker compose version"}, RiskLevel: "medium", Dependencies: []string{"docker"}, SupportedOS: []string{"linux"},
	},
}

// UpgradePlan builds a remote shell plan. version + sha256 are mandatory (no latest / curl|bash).
func UpgradePlan(name, version, sha256, downloadURL string) (string, error) {
	m, ok := Registry[name]
	if !ok {
		return "", fmt.Errorf("unknown module: %s", name)
	}
	if version == "" || version == "latest" {
		return "", fmt.Errorf("pinned version required")
	}
	if downloadURL == "" {
		return "", fmt.Errorf("download URL and sha256 required")
	}
	if err := validateSHA256(sha256); err != nil {
		return "", err
	}
	if err := validateInstallBin(m.InstallBin); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("rollback() {\n  echo '=== rollback ==='\n")
	for _, step := range m.RollbackSteps {
		b.WriteString("  echo " + strconvQuote(step) + "\n")
	}
	b.WriteString("  if [ -n \"${BACKUP_DIR:-}\" ] && [ -d \"$BACKUP_DIR\" ]; then\n")
	if m.InstallBin != "" {
		b.WriteString("    [ -e \"$BACKUP_DIR/.vpshub_bin\" ] && cp -a \"$BACKUP_DIR/.vpshub_bin\" " + strconvQuote(m.InstallBin) + " || true\n")
	}
	for _, p := range m.BackupPaths {
		key := archiveKey(p)
		parent := pathDir(p)
		fmt.Fprintf(&b, "    if [ -e \"$BACKUP_DIR\"/%s ]; then mkdir -p %s; rm -rf %s; cp -a \"$BACKUP_DIR\"/%s %s; fi\n",
			strconvQuote(key), strconvQuote(parent), strconvQuote(p), strconvQuote(key), strconvQuote(p))
	}
	b.WriteString("  fi\n")
	b.WriteString("}\ntrap rollback ERR\n")
	b.WriteString("echo '=== precheck ==='\n")
	b.WriteString("df -P / | awk 'NR==2{if($4+0<1048576) exit 1}'\n")
	b.WriteString("echo '=== detect ==='\n")
	if m.DetectCmd != "" {
		b.WriteString(m.DetectCmd + "\n")
	}
	b.WriteString("echo '=== backup ==='\n")
	b.WriteString("BACKUP_DIR=/var/backups/vpshub/$(date +%Y%m%d%H%M%S)\nmkdir -p \"$BACKUP_DIR\"\n")
	for _, p := range m.BackupPaths {
		key := archiveKey(p)
		fmt.Fprintf(&b, "[ -e %q ] && cp -a %q \"$BACKUP_DIR\"/%s || true\n", p, p, strconvQuote(key))
	}
	if m.InstallBin != "" {
		b.WriteString(fmt.Sprintf("[ -e %q ] && cp -a %q \"$BACKUP_DIR/.vpshub_bin\" || true\n", m.InstallBin, m.InstallBin))
	}
	b.WriteString("echo '=== download ==='\n")
	b.WriteString("TMP=$(mktemp)\n")
	b.WriteString(fmt.Sprintf("curl -fsSL %q -o \"$TMP\"\n", downloadURL))
	b.WriteString(fmt.Sprintf("echo '%s  %s' | sed \"s|  .*|  $TMP|\" | sha256sum -c -\n", sha256, "file"))
	b.WriteString("echo '=== install ==='\n")
	if m.InstallBin != "" {
		parent := pathDir(m.InstallBin)
		fmt.Fprintf(&b, "mkdir -p %q\n", parent)
		fmt.Fprintf(&b, "install -m 755 \"$TMP\" %q\n", m.InstallBin)
		b.WriteString("rm -f \"$TMP\"\n")
		for _, u := range m.SystemdUnits {
			if err := validateUnit(u); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "systemctl restart %s 2>/dev/null || true\n", u)
		}
	} else {
		b.WriteString("echo 'artifact verified at' \"$TMP\"\n")
		b.WriteString("echo 'package module: no binary install; use sysupgrade for package managers'\n")
		b.WriteString("rm -f \"$TMP\"\n")
		for _, step := range m.InstallSteps {
			b.WriteString("echo " + strconvQuote(step) + "\n")
		}
	}
	b.WriteString("echo '=== health ==='\n")
	for _, h := range m.HealthChecks {
		b.WriteString(h + "\n")
	}
	b.WriteString("trap - ERR\necho '=== done ==='\n")
	return b.String(), nil
}

func validateSHA256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("sha256 must be 64 hex characters")
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return fmt.Errorf("sha256 must be 64 hex characters")
		}
	}
	return nil
}

func validateInstallBin(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, ";&|`$<>'\"\\ \n\t") {
		return fmt.Errorf("invalid install path")
	}
	return nil
}

func validateUnit(u string) error {
	if u == "" || strings.ContainsAny(u, ";&|`$<>'\"\\/ \n\t") {
		return fmt.Errorf("invalid unit")
	}
	for _, r := range u {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid unit")
	}
	return nil
}

func pathDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func archiveKey(p string) string {
	return strings.ReplaceAll(strings.Trim(strings.TrimPrefix(p, "/"), "/"), "/", "-")
}

func strconvQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func ListModules() []*Module {
	out := make([]*Module, 0, len(Registry))
	for _, m := range Registry {
		out = append(out, m)
	}
	return out
}
