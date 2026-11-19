package store

import (
	"testing"
	"time"
)

func TestAllowChange(t *testing.T) {
	cases := []struct {
		mode, risk string
		ok         bool
	}{
		{"", "low", true},
		{"normal_tasks", "medium", true},
		{"normal_tasks", "high", false},
		{"high_risk_allowed", "critical", true},
		{"readonly_monitor", "low", false},
		{"no_changes", "medium", false},
		{"readonly_monitor", "high", false},
	}
	for _, tc := range cases {
		err := AllowChange(tc.mode, tc.risk)
		if tc.ok && err != nil {
			t.Fatalf("%s/%s: want ok got %v", tc.mode, tc.risk, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s/%s: want block", tc.mode, tc.risk)
		}
	}
}

func TestInMaintenanceWindowEmpty(t *testing.T) {
	if !InMaintenanceWindow("[]", time.Now().UTC()) {
		t.Fatal("empty windows should allow")
	}
}

func TestInMaintenanceWindowOutside(t *testing.T) {
	raw := `[{"weekdays":[0],"start":"03:00","end":"04:00"}]`
	monday := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC) // Monday
	if InMaintenanceWindow(raw, monday) {
		t.Fatal("should be outside window")
	}
	sunday := time.Date(2023, 12, 31, 3, 30, 0, 0, time.UTC) // Sunday
	if !InMaintenanceWindow(raw, sunday) {
		t.Fatal("should be inside window")
	}
}
