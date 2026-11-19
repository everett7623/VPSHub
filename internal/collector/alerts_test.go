package collector

import (
	"strings"
	"testing"
	"time"
)

func TestNotices(t *testing.T) {
	got := Notices(Result{
		"disk":           "100,95,5,91%",
		"mem_total_kb":   float64(1000),
		"mem_avail_kb":   float64(50),
		"systemd_failed": "nginx.service;",
		"containers":     "web|nginx|Up|;db|postgres|Exited (1)|",
	})
	kinds := map[string]bool{}
	for _, n := range got {
		kinds[n.Kind] = true
	}
	for _, k := range []string{"disk_high", "mem_low", "systemd_failed", "docker_unhealthy"} {
		if !kinds[k] {
			t.Fatalf("missing %s in %#v", k, got)
		}
	}
	if len(Notices(Result{"disk": "100,10,90,9%", "mem_total_kb": float64(1000), "mem_avail_kb": float64(500)})) != 0 {
		t.Fatal("healthy host should not alert")
	}
}

func TestSecurityAndCertThresholds(t *testing.T) {
	if CertExpiryWarnDays != 14 {
		t.Fatalf("cert window = %d", CertExpiryWarnDays)
	}
	if SecurityUpdatesMin != 1 {
		t.Fatalf("security minimum = %d", SecurityUpdatesMin)
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	soon := now.Add(time.Duration(CertExpiryWarnDays) * 24 * time.Hour).Unix()
	later := now.Add(time.Duration(CertExpiryWarnDays+1) * 24 * time.Hour).Unix()
	got := noticesAt(Result{"security_updates": float64(SecurityUpdatesMin), "cert_not_after": float64(soon)}, now)
	kinds := map[string]bool{}
	for _, n := range got {
		kinds[n.Kind] = true
	}
	if !kinds["security_updates"] || !kinds["cert_expiring"] {
		t.Fatalf("missing threshold alerts: %#v", got)
	}
	quiet := noticesAt(Result{"security_updates": float64(0), "cert_not_after": float64(later)}, now)
	if len(quiet) != 0 {
		t.Fatalf("below threshold should be quiet: %#v", quiet)
	}
	expired := noticesAt(Result{"cert_not_after": float64(now.Add(-24 * time.Hour).Unix())}, now)
	if len(expired) != 1 || expired[0].Kind != "cert_expiring" {
		t.Fatalf("expired cert: %#v", expired)
	}
}

func TestScanScriptProbesAreReadOnly(t *testing.T) {
	if !strings.Contains(ScanScript, `"security_updates"`) || !strings.Contains(ScanScript, `"cert_not_after"`) {
		t.Fatal("scan script missing alert fields")
	}
	if !strings.Contains(ScanScript, `"config_sha256"`) || !strings.Contains(ScanScript, "sha256sum") {
		t.Fatal("scan script missing config sha256 probe")
	}
	lower := strings.ToLower(ScanScript)
	for _, bad := range []string{"apt-get install", "apt install", "dnf install", "yum install", "apk add", "pacman -s", "curl", "wget"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("scan script must not install or fetch: %s", bad)
		}
	}
}
