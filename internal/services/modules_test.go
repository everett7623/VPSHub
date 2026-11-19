package services

import (
	"strings"
	"testing"
)

const testSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestUpgradePlanRejectsLatest(t *testing.T) {
	_, err := UpgradePlan("xray", "latest", testSHA, "https://example.com/x")
	if err == nil {
		t.Fatal("latest must be rejected")
	}
	_, err = UpgradePlan("xray", "1.8.0", testSHA, "https://example.com/x")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpgradePlanRejectsBadSHA(t *testing.T) {
	_, err := UpgradePlan("xray", "1.8.0", "deadbeef", "https://example.com/x")
	if err == nil {
		t.Fatal("short sha must be rejected")
	}
	_, err = UpgradePlan("xray", "1.8.0", testSHA[:63]+"g", "https://example.com/x")
	if err == nil {
		t.Fatal("non-hex sha must be rejected")
	}
}

func TestUpgradePlanBinaryInstall(t *testing.T) {
	plan, err := UpgradePlan("xray", "1.8.0", testSHA, "https://example.com/xray")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"install -m 755",
		"/usr/local/bin/xray",
		"systemctl restart xray",
		"sha256sum -c",
		"trap rollback ERR",
		"BACKUP_DIR",
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("missing %q\n%s", want, plan)
		}
	}
	if strings.Contains(plan, "curl | bash") || strings.Contains(plan, "apt-get install") {
		t.Fatalf("unsafe: %s", plan)
	}
}

func TestUpgradePlanPackageVerifyOnly(t *testing.T) {
	plan, err := UpgradePlan("nginx", "1.24.0", testSHA, "https://example.com/nginx.deb")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "install -m 755") || strings.Contains(plan, "apt-get") {
		t.Fatalf("package modules must not apt-install: %s", plan)
	}
	if !strings.Contains(plan, "artifact verified") || !strings.Contains(plan, "sysupgrade") {
		t.Fatalf("expected verify-only note: %s", plan)
	}
}

func TestUpgradePlanSingBoxAndNezha(t *testing.T) {
	for _, name := range []string{"sing-box", "hysteria2", "shadowsocks-rust", "anytls", "komari", "komari-lite", "nezha"} {
		m := Registry[name]
		if m.InstallBin == "" {
			t.Fatalf("%s should have InstallBin", name)
		}
		plan, err := UpgradePlan(name, "1.0.0", testSHA, "https://example.com/"+name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(plan, "install -m 755") || !strings.Contains(plan, m.InstallBin) {
			t.Fatalf("%s missing install: %s", name, plan)
		}
	}
}
