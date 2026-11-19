package store

import "testing"

func TestNormalizeMaintenanceWindows(t *testing.T) {
	got, err := NormalizeMaintenanceWindows("")
	if err != nil || got != "[]" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = NormalizeMaintenanceWindows(`[{"weekdays":[0,6],"start":"03:00","end":"05:00"}]`)
	if err != nil || got == "" {
		t.Fatal(err)
	}
	if _, err := NormalizeMaintenanceWindows(`[{"weekdays":[9],"start":"03:00","end":"05:00"}]`); err == nil {
		t.Fatal("bad weekday")
	}
	if _, err := NormalizeMaintenanceWindows(`[{"weekdays":[0],"start":"3:00","end":"05:00"}]`); err == nil {
		t.Fatal("bad time")
	}
	if _, err := NormalizeMaintenanceWindows(`{`); err == nil {
		t.Fatal("bad json")
	}
}
