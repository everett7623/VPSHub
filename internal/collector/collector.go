package collector

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
)

// ScanScript is a read-only shell that emits JSON on stdout.
const ScanScript = `#!/bin/sh
set -e
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g;s/"/\\"/g'; }
OS_ID=$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")
OS_VER=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
KERNEL=$(uname -r)
ARCH=$(uname -m)
HOSTNAME=$(hostname 2>/dev/null || echo unknown)
UPTIME=$(cat /proc/uptime 2>/dev/null | awk '{print $1}')
LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1","$2","$3}')
MEM_TOTAL=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
MEM_AVAIL=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
DISK=$(df -P / 2>/dev/null | awk 'NR==2{print $2","$3","$4","$5}')
NEED_REBOOT=false
[ -f /var/run/reboot-required ] && NEED_REBOOT=true
HAS_DOCKER=false
DOCKER_VER=""
command -v docker >/dev/null 2>&1 && HAS_DOCKER=true && DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "")
COMPOSE_VER=""
command -v docker >/dev/null 2>&1 && COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "")
PORTS=$(ss -lntuH 2>/dev/null | awk '{print $1","$5}' | head -n 80 | tr '\n' ';' || true)
SYSTEMD=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -n 100 | tr '\n' ';' || true)
CONTAINERS=""
if [ "$HAS_DOCKER" = true ]; then
  CONTAINERS=$(docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>/dev/null | head -n 80 | tr '\n' ';' || true)
fi
FAILED=$(systemctl --failed --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -n 20 | tr '\n' ';' || true)
REASONS=$(printf '%s' "$FAILED" | tr ';' '\n' | head -n 8 | while read -r u; do
  if [ -n "$u" ]; then
    r=$(systemctl show -p Result --value "$u" 2>/dev/null || echo unknown)
    printf '%s=%s;' "$u" "$r"
  fi
done || true)
# Read-only probes. apt-get -s and dnf/yum updateinfo do not install packages.
# apk and pacman have no separate security index here, so they stay at 0.
SEC_UPDATES=0
if command -v apt-get >/dev/null 2>&1; then
  SEC_UPDATES=$(apt-get -s upgrade 2>/dev/null | awk 'BEGIN{c=0} /^Inst / && /[Ss]ecurity/{c++} END{print c+0}' || true)
elif command -v dnf >/dev/null 2>&1; then
  SEC_UPDATES=$(dnf -q updateinfo list security 2>/dev/null | awk 'NF>=3 && $1 !~ /^Last/{c++} END{print c+0}' || true)
elif command -v yum >/dev/null 2>&1; then
  SEC_UPDATES=$(yum -q updateinfo list security 2>/dev/null | awk 'NF>=3 && $1 !~ /^Last/{c++} END{print c+0}' || true)
fi
case "$SEC_UPDATES" in
  ''|*[!0-9]*) SEC_UPDATES=0 ;;
esac
CERT_NOT_AFTER=0
if command -v openssl >/dev/null 2>&1; then
  for f in /etc/nginx/ssl/*.crt /etc/nginx/ssl/*.pem /etc/nginx/certs/*.crt /etc/nginx/certs/*.pem /etc/caddy/certs/*.crt /etc/caddy/certs/*.pem /etc/letsencrypt/live/*/cert.pem /etc/letsencrypt/live/*/fullchain.pem; do
    [ -f "$f" ] || continue
    case "$f" in
      *.key|*privkey*) continue ;;
    esac
    end=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)
    [ -n "$end" ] || continue
    epoch=$(date -u -d "$end" +%s 2>/dev/null || true)
    case "$epoch" in
      ''|*[!0-9]*) continue ;;
    esac
    if [ "$CERT_NOT_AFTER" -eq 0 ] || [ "$epoch" -lt "$CERT_NOT_AFTER" ]; then
      CERT_NOT_AFTER=$epoch
    fi
  done
fi
# Fixed whitelist of config files only (read-only sha256sum). No user paths.
CONFIG_SHA=""
if command -v sha256sum >/dev/null 2>&1; then
  for f in \
    /etc/nginx/nginx.conf \
    /etc/caddy/Caddyfile \
    /etc/docker/daemon.json \
    /etc/ssh/sshd_config \
    /etc/xray/config.json \
    /usr/local/etc/xray/config.json \
    /etc/sing-box/config.json \
    /etc/hysteria/config.yaml \
    /etc/hysteria/config.json \
    /etc/shadowsocks-rust/config.json \
    /etc/anytls/config.json \
    /etc/wireguard/wg0.conf \
    /etc/komari/config.toml \
    /etc/komari-lite/config.toml
  do
    [ -f "$f" ] && [ -r "$f" ] || continue
    h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    case "$h" in
      ''|*[!0-9a-fA-F]*) continue ;;
    esac
    CONFIG_SHA="${CONFIG_SHA}${f}=${h};"
  done
fi
printf '{'
printf '"hostname":"%s",' "$(json_escape "$HOSTNAME")"
printf '"os_id":"%s",' "$(json_escape "$OS_ID")"
printf '"os_version":"%s",' "$(json_escape "$OS_VER")"
printf '"kernel":"%s",' "$(json_escape "$KERNEL")"
printf '"arch":"%s",' "$(json_escape "$ARCH")"
printf '"uptime_sec":"%s",' "$(json_escape "$UPTIME")"
printf '"loadavg":"%s",' "$(json_escape "$LOAD")"
printf '"mem_total_kb":%s,' "${MEM_TOTAL:-0}"
printf '"mem_avail_kb":%s,' "${MEM_AVAIL:-0}"
printf '"disk":"%s",' "$(json_escape "$DISK")"
printf '"need_reboot":%s,' "$NEED_REBOOT"
printf '"docker":%s,' "$HAS_DOCKER"
printf '"docker_version":"%s",' "$(json_escape "$DOCKER_VER")"
printf '"compose_version":"%s",' "$(json_escape "$COMPOSE_VER")"
printf '"ports":"%s",' "$(json_escape "$PORTS")"
printf '"systemd_running":"%s",' "$(json_escape "$SYSTEMD")"
printf '"systemd_failed":"%s",' "$(json_escape "$FAILED")"
printf '"systemd_fail_reason":"%s",' "$(json_escape "$REASONS")"
printf '"security_updates":%s,' "${SEC_UPDATES:-0}"
printf '"cert_not_after":%s,' "${CERT_NOT_AFTER:-0}"
printf '"config_sha256":"%s",' "$(json_escape "$CONFIG_SHA")"
printf '"containers":"%s"' "$(json_escape "$CONTAINERS")"
printf '}\n'
`

type Result map[string]any

type Service struct {
	SSH  *sshx.Client
	DB   *store.DB
	Emit func(kind, severity string, vpsID *int64, message string)
}

func New(sshClient *sshx.Client, db *store.DB) *Service {
	return &Service{SSH: sshClient, DB: db}
}

func (s *Service) Scan(ctx context.Context, opts sshx.ConnectOpts, vpsID int64, fingerprints []Fingerprint) (Result, error) {
	out, stderr, _, err := s.SSH.Run(ctx, opts, "sh -s <<'VPSHUB_EOF'\n"+ScanScript+"\nVPSHUB_EOF")
	if err != nil {
		return nil, err
	}
	_ = stderr
	var res Result
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(res)
	_ = s.DB.SaveScanResult(vpsID, string(payload))
	_ = s.DB.TouchVPSScan(vpsID)
	s.applyFingerprints(vpsID, res, fingerprints)
	s.raiseScanAlerts(vpsID, res)
	return res, nil
}

func (s *Service) applyFingerprints(vpsID int64, res Result, fps []Fingerprint) {
	systemd, _ := res["systemd_running"].(string)
	containers, _ := res["containers"].(string)
	ports, _ := res["ports"].(string)
	dockerOn, _ := res["docker"].(bool)
	for _, fp := range fps {
		status := "unknown"
		version := ""
		matched := false
		for _, u := range fp.Units {
			if strings.Contains(systemd, u) {
				matched = true
				status = "running"
				break
			}
		}
		for _, p := range fp.Processes {
			if strings.Contains(systemd, p) || strings.Contains(containers, p) {
				matched = true
				if status == "unknown" {
					status = "installed"
				}
			}
		}
		for _, port := range fp.Ports {
			if strings.Contains(ports, ":"+port) {
				matched = true
				if status == "unknown" {
					status = "installed"
				}
			}
		}
		if fp.Name == "docker" && dockerOn {
			matched = true
			status = "running"
			if v, ok := res["docker_version"].(string); ok {
				version = v
			}
		}
		if matched {
			_ = s.DB.UpsertServiceInventory(vpsID, fp.Name, status, version, "")
		}
	}
}

type Fingerprint struct {
	Name      string   `yaml:"name" json:"name"`
	Units     []string `yaml:"units" json:"units"`
	Processes []string `yaml:"processes" json:"processes"`
	Ports     []string `yaml:"ports" json:"ports"`
}
