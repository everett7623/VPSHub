package docker

import (
	"fmt"
	"strings"
)

// Commands return structured remote commands (no user-string concatenation into shell beyond validated names).
func ListContainersCmd() string {
	return "docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'"
}

func ContainerLogsCmd(name string, lines int) (string, error) {
	if !safeName(name) {
		return "", fmt.Errorf("invalid container name")
	}
	if lines <= 0 || lines > 5000 {
		lines = 200
	}
	return fmt.Sprintf("docker logs --tail %d %s", lines, name), nil
}

func ContainerActionCmd(action, name string) (string, error) {
	switch action {
	case "start", "stop", "restart":
	default:
		return "", fmt.Errorf("invalid action")
	}
	if !safeName(name) {
		return "", fmt.Errorf("invalid container name")
	}
	return fmt.Sprintf("docker %s %s", action, name), nil
}

func StatsCmd() string {
	return "docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}'"
}

func ImagesCmd() string {
	return "docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}'"
}

// ActionCmd builds a docker or compose command. risk is medium or high.
// name is a container, volume, or absolute compose directory depending on action.
func ActionCmd(action, name string, dryRun bool) (cmd, risk string, err error) {
	switch action {
	case "start", "stop", "restart":
		cmd, err = ContainerActionCmd(action, name)
		return cmd, "medium", err
	case "rm":
		if !safeName(name) {
			return "", "", fmt.Errorf("invalid container name")
		}
		return "docker rm -f " + name, "high", nil
	case "volume_rm":
		if !safeName(name) {
			return "", "", fmt.Errorf("invalid volume name")
		}
		return "docker volume rm " + name, "high", nil
	case "image_prune":
		return "docker image prune -f", "high", nil
	case "compose_down":
		if !safePath(name) {
			return "", "", fmt.Errorf("invalid compose dir")
		}
		return fmt.Sprintf("cd %q && docker compose down", name), "high", nil
	case "compose_pull_up":
		cmd, err = ComposePullUpCmd(name, dryRun)
		if dryRun {
			return cmd, "medium", err
		}
		return cmd, "high", err
	default:
		return "", "", fmt.Errorf("invalid action")
	}
}

func Dangerous(action string) bool {
	switch action {
	case "rm", "volume_rm", "image_prune", "compose_down":
		return true
	default:
		return false
	}
}

// ComposePullUpCmd backs up the compose directory before pull/up.
// A dry run only prints the compose config.
func ComposePullUpCmd(dir string, dryRun bool) (string, error) {
	if !safePath(dir) {
		return "", fmt.Errorf("invalid compose dir")
	}
	if dryRun {
		return fmt.Sprintf("cd %q && docker compose config", dir), nil
	}
	return fmt.Sprintf(`set -euo pipefail
dir=%q
stamp=$(date +%%Y%%m%%d%%H%%M%%S)
mkdir -p /var/backups/vpshub/"$stamp"
tar -czf /var/backups/vpshub/"$stamp"/compose.tgz -C "$(dirname "$dir")" "$(basename "$dir")"
cd "$dir"
docker compose pull
docker compose up -d
echo "backup /var/backups/vpshub/$stamp/compose.tgz"
`, dir), nil
}

// AbnormalLines returns container rows whose status looks unhealthy.
func AbnormalLines(containers string) []string {
	var out []string
	for _, line := range strings.Split(containers, ";") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "exited") || strings.Contains(low, "unhealthy") || strings.Contains(low, "restarting") {
			out = append(out, line)
		}
	}
	return out
}

func safeName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func safePath(s string) bool {
	if s == "" || strings.Contains(s, "..") || strings.ContainsAny(s, ";&|`$") {
		return false
	}
	return strings.HasPrefix(s, "/")
}
