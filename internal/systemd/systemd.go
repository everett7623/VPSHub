package systemd

import (
	"fmt"
)

func ListUnitsCmd() string {
	return "systemctl list-units --type=service --all --no-pager --no-legend"
}

func UnitActionCmd(action, unit string) (string, error) {
	switch action {
	case "start", "stop", "restart", "reload", "enable", "disable", "status":
	default:
		return "", fmt.Errorf("invalid action")
	}
	if !safeUnit(unit) {
		return "", fmt.Errorf("invalid unit name")
	}
	return fmt.Sprintf("systemctl %s %s", action, unit), nil
}

func UnitLogsCmd(unit string, lines int) (string, error) {
	if !safeUnit(unit) {
		return "", fmt.Errorf("invalid unit name")
	}
	if lines <= 0 || lines > 5000 {
		lines = 200
	}
	return fmt.Sprintf("journalctl -u %s -n %d --no-pager", unit, lines), nil
}

func safeUnit(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	hasDot := false
	for _, r := range s {
		if r == '.' {
			hasDot = true
			break
		}
	}
	if !hasDot {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '@' {
			continue
		}
		return false
	}
	return true
}
