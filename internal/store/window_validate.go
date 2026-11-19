package store

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var hmRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// NormalizeMaintenanceWindows validates and canonicalizes the JSON array.
// Empty / "[]" means always allowed.
func NormalizeMaintenanceWindows(raw string) (string, error) {
	raw = trimSpace(raw)
	if raw == "" || raw == "[]" || raw == "null" {
		return "[]", nil
	}
	var wins []maintWindow
	if err := json.Unmarshal([]byte(raw), &wins); err != nil {
		return "", fmt.Errorf("maintenance_windows must be a JSON array")
	}
	for i, w := range wins {
		if !hmRE.MatchString(w.Start) || !hmRE.MatchString(w.End) {
			return "", fmt.Errorf("window %d: start/end must be HH:MM", i)
		}
		for _, d := range w.Weekdays {
			if d < 0 || d > 6 {
				return "", fmt.Errorf("window %d: weekday must be 0-6 (Sun-Sat)", i)
			}
		}
	}
	b, err := json.Marshal(wins)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
