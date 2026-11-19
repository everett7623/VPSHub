package docker

import "testing"

func TestComposePullUpBacksUp(t *testing.T) {
	cmd, err := ComposePullUpCmd("/opt/app", false)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(cmd, "/var/backups/vpshub") || !contains(cmd, "docker compose pull") || !contains(cmd, "tar -czf") {
		t.Fatalf("missing backup or pull: %s", cmd)
	}
	dry, err := ComposePullUpCmd("/opt/app", true)
	if err != nil {
		t.Fatal(err)
	}
	if contains(dry, "docker compose pull") || contains(dry, "tar ") {
		t.Fatalf("dry run must not pull or archive: %s", dry)
	}
	if _, err := ComposePullUpCmd("/opt/../etc", false); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestDangerousActions(t *testing.T) {
	cmd, risk, err := ActionCmd("image_prune", "", false)
	if err != nil || risk != "high" || cmd != "docker image prune -f" {
		t.Fatalf("%s %s %v", cmd, risk, err)
	}
	if _, _, err := ActionCmd("rm", "bad name", false); err == nil {
		t.Fatal("space in name accepted")
	}
	if _, _, err := ActionCmd("compose_down", "relative", false); err == nil {
		t.Fatal("relative dir accepted")
	}
	cmd, risk, err = ActionCmd("restart", "web", false)
	if err != nil || risk != "medium" || cmd != "docker restart web" {
		t.Fatalf("%s %s %v", cmd, risk, err)
	}
}

func TestAbnormalLines(t *testing.T) {
	got := AbnormalLines("ok|nginx|Up 2 hours|;bad|redis|Exited (1)|;x|app|Restarting|")
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (func() bool { return indexOf(s, sub) >= 0 })())
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
