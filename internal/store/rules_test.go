package store

import "testing"

func TestDecideAlertRule(t *testing.T) {
	th := 95.0
	d := DecideAlertRule(nil, "disk_high")
	if !d.Allow || d.Threshold != nil {
		t.Fatalf("no rules: %+v", d)
	}
	d = DecideAlertRule([]AlertRule{{Kind: "disk_high", Enabled: false}}, "disk_high")
	if d.Allow {
		t.Fatal("disabled-only should deny")
	}
	d = DecideAlertRule([]AlertRule{
		{Kind: "disk_high", Enabled: true, Threshold: &th, NotifyChannels: `["telegram","smtp"]`},
	}, "disk_high")
	if !d.Allow || d.Threshold == nil || *d.Threshold != 95 || len(d.Channels) != 2 {
		t.Fatalf("%+v", d)
	}
}
