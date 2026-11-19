package backup

import (
	"strings"
	"testing"
)

func TestConfigBackupPlanWhitelist(t *testing.T) {
	if ConfigBackupKeep != 5 {
		t.Fatalf("keep = %d", ConfigBackupKeep)
	}
	plan, err := ConfigBackupPlan(false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/etc/nginx", "/etc/caddy", "/etc/letsencrypt", "/etc/systemd/system",
		"/etc/docker", "/etc/wireguard", "/etc/komari", "/usr/local/etc/xray",
		"/etc/xray", "/opt/nezha", "/var/backups/vpshub",
	}
	for _, p := range want {
		if !strings.Contains(plan, p) {
			t.Fatalf("missing %s\n%s", p, plan)
		}
	}
	if !strings.Contains(plan, "usr-local-etc-xray.tgz") || !strings.Contains(plan, "etc-xray.tgz") {
		t.Fatalf("need unique xray archives: %s", plan)
	}
	if !strings.Contains(plan, "tar -czf") || !strings.Contains(plan, "-gt 5") {
		t.Fatalf("missing archive or retention: %s", plan)
	}
	if strings.Contains(plan, "curl") || strings.Contains(plan, "..") {
		t.Fatalf("unsafe plan: %s", plan)
	}
	dry, err := ConfigBackupPlan(true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dry, "tar ") || strings.Contains(dry, "rm ") {
		t.Fatalf("dry run must not archive: %s", dry)
	}
	for _, p := range ConfigBackupPaths {
		if !strings.Contains(dry, p) {
			t.Fatalf("dry run missing %s", p)
		}
	}
}

func TestConfigRestorePlanStamp(t *testing.T) {
	if _, err := ConfigRestorePlan("bad", false); err == nil {
		t.Fatal("bad stamp")
	}
	if _, err := ConfigRestorePlan("2024010112000", false); err == nil {
		t.Fatal("short stamp")
	}
	plan, err := ConfigRestorePlan("20240101120000", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "/var/backups/vpshub/20240101120000") {
		t.Fatalf("missing stamp dir: %s", plan)
	}
	if !strings.Contains(plan, "tar -xzf") || strings.Contains(plan, "curl") {
		t.Fatalf("bad restore plan: %s", plan)
	}
	for _, p := range []string{"/etc/nginx", "/etc/wireguard", "/opt/nezha"} {
		if !strings.Contains(plan, p) {
			t.Fatalf("missing %s", p)
		}
	}
	dry, err := ConfigRestorePlan("20240101120000", true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dry, "tar ") {
		t.Fatalf("dry run must not extract: %s", dry)
	}
	if !strings.Contains(dry, "would restore /etc/nginx") {
		t.Fatalf("dry run missing list: %s", dry)
	}
}

func TestArchiveBaseUnique(t *testing.T) {
	a := ArchiveBase("/usr/local/etc/xray")
	b := ArchiveBase("/etc/xray")
	if a == b || a == "" || b == "" {
		t.Fatalf("bases %q %q", a, b)
	}
}

func TestMergeConfigPaths(t *testing.T) {
	m := MergeConfigPaths([]string{"/etc/nginx/sites-enabled", "/tmp/evil", "/etc/nginx"})
	if !PathAllowed("/etc/nginx/sites-enabled") {
		t.Fatal("subpath should be allowed")
	}
	if PathAllowed("/tmp/evil") {
		t.Fatal("outside whitelist")
	}
	found := false
	for _, p := range m {
		if p == "/etc/nginx/sites-enabled" {
			found = true
		}
		if p == "/tmp/evil" {
			t.Fatal("evil path leaked")
		}
	}
	if !found {
		t.Fatalf("missing subpath: %v", m)
	}
	plan, err := ConfigBackupPlanWith([]string{"/etc/nginx/sites-enabled"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "/etc/nginx/sites-enabled") {
		t.Fatalf("dry plan missing extra: %s", plan)
	}
}
