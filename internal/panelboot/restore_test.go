package panelboot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyRestoredDB(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vpshub.db"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vpshub.db.restored"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyRestoredDB(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "vpshub.db"))
	if err != nil || string(got) != "new" {
		t.Fatalf("db=%q err=%v", got, err)
	}
	bak, err := os.ReadFile(filepath.Join(dir, "vpshub.db.bak"))
	if err != nil || string(bak) != "old" {
		t.Fatalf("bak=%q err=%v", bak, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vpshub.db.restored")); !os.IsNotExist(err) {
		t.Fatal("restored sidecar should be gone")
	}
}
