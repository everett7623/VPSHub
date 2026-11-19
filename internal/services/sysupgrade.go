package services

import (
	"fmt"
	"strings"
)

// SysUpgradePlan builds a non-interactive package upgrade script.
// scope is "all" or "security". dryRun keeps the script read-only.
// reboot is ignored when the caller already forced it off for production.
func SysUpgradePlan(pm, scope string, reboot, dryRun bool) (string, error) {
	switch pm {
	case "apt", "dnf", "yum", "apk", "pacman":
	default:
		return "", fmt.Errorf("unsupported package manager")
	}
	if scope == "" {
		scope = "all"
	}
	if scope != "all" && scope != "security" {
		return "", fmt.Errorf("scope must be all or security")
	}
	if scope == "security" && (pm == "apk" || pm == "pacman") {
		return "", fmt.Errorf("security scope is not available for %s", pm)
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("echo '=== precheck disk ==='\n")
	b.WriteString("avail=$(df -P / | awk 'NR==2{print $4}')\n")
	b.WriteString("[ \"${avail:-0}\" -ge 1048576 ] || { echo 'disk below 1GiB'; exit 1; }\n")
	b.WriteString("echo '=== precheck lock ==='\n")
	b.WriteString(lockCheck(pm))
	b.WriteString("echo '=== precheck ssh ==='\n")
	b.WriteString("ss -lnt 2>/dev/null | head -n 20 || netstat -lnt 2>/dev/null | head -n 20 || true\n")
	b.WriteString("echo '=== packages ==='\n")
	b.WriteString(packageCmd(pm, scope, dryRun))
	b.WriteString("echo '=== reboot required ==='\n")
	b.WriteString("if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi\n")
	if reboot && !dryRun {
		b.WriteString("if [ -f /var/run/reboot-required ]; then echo 'reboot scheduled in 1 minute'; nohup shutdown -r +1 >/dev/null 2>&1 & fi\n")
	} else {
		b.WriteString("echo 'reboot skipped'\n")
	}
	if !dryRun {
		b.WriteString("echo '=== health ==='\n")
		b.WriteString("systemctl is-system-running 2>/dev/null || true\n")
		b.WriteString("if command -v sshd >/dev/null 2>&1; then sshd -t; fi\n")
		b.WriteString("echo health_ok\n")
	}
	b.WriteString("echo '=== done ==='\n")
	return b.String(), nil
}

func lockCheck(pm string) string {
	switch pm {
	case "dnf", "yum":
		return "if [ -f /var/run/dnf.pid ] && kill -0 \"$(cat /var/run/dnf.pid)\" 2>/dev/null; then echo 'package manager locked'; exit 1; fi\n"
	case "apk":
		return "if [ -f /var/lock/apkdb.lock ]; then echo 'package manager locked'; exit 1; fi\n"
	case "pacman":
		return "if [ -f /var/lib/pacman/db.lck ]; then echo 'package manager locked'; exit 1; fi\n"
	default:
		return "if command -v fuser >/dev/null 2>&1 && fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then echo 'package manager locked'; exit 1; fi\n"
	}
}

func packageCmd(pm, scope string, dryRun bool) string {
	switch pm {
	case "dnf":
		if scope == "security" {
			if dryRun {
				return "dnf update --security --assumeno || true\n"
			}
			return "dnf -y update --security\n"
		}
		if dryRun {
			return "dnf update --assumeno || true\n"
		}
		return "dnf -y update\n"
	case "yum":
		flag := ""
		if scope == "security" {
			flag = " --security"
		}
		if dryRun {
			return "yum check-update" + flag + " || true\n"
		}
		return "yum -y update" + flag + "\n"
	case "apk":
		if dryRun {
			return "apk update && apk upgrade -s\n"
		}
		return "apk update && apk upgrade\n"
	case "pacman":
		if dryRun {
			return "pacman -Syu --print\n"
		}
		return "pacman -Syu --noconfirm\n"
	default:
		if scope == "security" {
			if dryRun {
				return "export DEBIAN_FRONTEND=noninteractive; apt-get update; unattended-upgrade --dry-run\n"
			}
			return "export DEBIAN_FRONTEND=noninteractive; apt-get update; command -v unattended-upgrade >/dev/null || { echo 'unattended-upgrade missing'; exit 1; }; unattended-upgrade\n"
		}
		if dryRun {
			return "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get -s upgrade\n"
		}
		return "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade\n"
	}
}

// DisablePasswordPlan backs up sshd_config, turns off password login, and reloads only if sshd -t passes.
func DisablePasswordPlan() string {
	return `set -euo pipefail
ts=$(date +%Y%m%d%H%M%S)
cp -a /etc/ssh/sshd_config "/etc/ssh/sshd_config.vpshub.${ts}"
if grep -qE '^[[:space:]]*#?[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config; then
  sed -i.bak "s/^[[:space:]]*#\\?[[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
else
  printf '\nPasswordAuthentication no\n' >> /etc/ssh/sshd_config
fi
if ! sshd -t; then
  cp -a "/etc/ssh/sshd_config.vpshub.${ts}" /etc/ssh/sshd_config
  echo 'sshd -t failed; config restored'
  exit 1
fi
if systemctl reload ssh 2>/dev/null; then
  echo reloaded ssh
elif systemctl reload sshd 2>/dev/null; then
  echo reloaded sshd
else
  cp -a "/etc/ssh/sshd_config.vpshub.${ts}" /etc/ssh/sshd_config
  echo 'reload failed; config restored'
  exit 1
fi
echo "password authentication disabled; backup /etc/ssh/sshd_config.vpshub.${ts}"
`
}
