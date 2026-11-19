package store

import (
	"encoding/json"
	"time"
)

type maintWindow struct {
	Weekdays []int  `json:"weekdays"`
	Start    string `json:"start"`
	End      string `json:"end"`
}

// MaintenanceStatus summarizes window state for UI.
type MaintenanceStatus struct {
	Unrestricted bool   `json:"unrestricted"`
	InWindow     bool   `json:"in_window"`
	Now          string `json:"now"`
	Weekday      int    `json:"weekday"`
	Raw          string `json:"windows_json"`
}

// WindowStatus returns whether high-risk work is currently allowed by windows.
func WindowStatus(raw string, now time.Time) MaintenanceStatus {
	raw = trimSpace(raw)
	st := MaintenanceStatus{
		Now: now.UTC().Format(time.RFC3339), Weekday: int(now.Weekday()), Raw: raw,
	}
	if raw == "" || raw == "[]" || raw == "null" {
		st.Unrestricted = true
		st.InWindow = true
		st.Raw = "[]"
		return st
	}
	st.InWindow = InMaintenanceWindow(raw, now)
	return st
}

// InMaintenanceWindow reports whether now is inside a configured window.
// Empty or "[]" means no restriction (always allowed).
func InMaintenanceWindow(raw string, now time.Time) bool {
	raw = trimSpace(raw)
	if raw == "" || raw == "[]" || raw == "null" {
		return true
	}
	var wins []maintWindow
	if err := json.Unmarshal([]byte(raw), &wins); err != nil || len(wins) == 0 {
		return true
	}
	wd := int(now.Weekday())
	hm := now.Format("15:04")
	for _, w := range wins {
		if w.Start == "" || w.End == "" {
			continue
		}
		dayOK := len(w.Weekdays) == 0
		for _, d := range w.Weekdays {
			if d == wd {
				dayOK = true
			}
		}
		if !dayOK {
			continue
		}
		if w.Start <= w.End {
			if hm >= w.Start && hm <= w.End {
				return true
			}
		} else if hm >= w.Start || hm <= w.End {
			return true
		}
	}
	return false
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\n' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
