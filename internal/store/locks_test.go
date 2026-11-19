package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClearAllLocks(t *testing.T) {
	dir := t.TempDir()
	root, _ := os.Getwd()
	mig := filepath.Join(root, "..", "..", "migrations")
	if _, err := os.Stat(mig); err != nil {
		mig = filepath.Join(root, "migrations")
	}
	t.Setenv("VPSHUB_MIGRATIONS", mig)
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	until := time.Now().Add(time.Hour)
	if err := db.SetLock("ip:1.1.1.1", until, "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetLock("user:admin", until, "test"); err != nil {
		t.Fatal(err)
	}
	locks, err := db.ListActiveLocks()
	if err != nil || len(locks) != 2 {
		t.Fatalf("want 2 locks, got %d err=%v", len(locks), err)
	}
	n, err := db.ClearAllLocks()
	if err != nil || n != 2 {
		t.Fatalf("cleared=%d err=%v", n, err)
	}
	locks, err = db.ListActiveLocks()
	if err != nil || len(locks) != 0 {
		t.Fatalf("want 0 locks after clear, got %d", len(locks))
	}
}
