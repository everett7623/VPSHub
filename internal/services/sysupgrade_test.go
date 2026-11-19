package services

import "strings"
import "testing"

func TestSysUpgradePlan(t *testing.T) {
	plan, err := SysUpgradePlan("apt", "security", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "precheck disk") || !strings.Contains(plan, "unattended-upgrade --dry-run") {
		t.Fatalf("plan missing checks:\n%s", plan)
	}
	if strings.Contains(plan, "shutdown") {
		t.Fatal("dry run must not reboot")
	}
	if _, err := SysUpgradePlan("apk", "security", false, false); err == nil {
		t.Fatal("apk security scope must be rejected")
	}
	live, err := SysUpgradePlan("dnf", "all", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live, "dnf -y update") || !strings.Contains(live, "shutdown -r +1") {
		t.Fatalf("live plan:\n%s", live)
	}
	if !strings.Contains(live, "=== health ===") || !strings.Contains(live, "health_ok") || !strings.Contains(live, "sshd -t") {
		t.Fatalf("live plan missing health:\n%s", live)
	}
}

func TestDisablePasswordPlanRestoresOnFailure(t *testing.T) {
	plan := DisablePasswordPlan()
	if !strings.Contains(plan, "sshd_config.vpshub") || !strings.Contains(plan, "sshd -t") {
		t.Fatal(plan)
	}
}
