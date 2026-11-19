package store

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPruneScanResultsKeepNewest(t *testing.T) {
	root, _ := os.Getwd()
	mig := filepath.Join(root, "..", "..", "migrations")
	if _, err := os.Stat(mig); err != nil {
		mig = filepath.Join(root, "migrations")
	}
	t.Setenv("VPSHUB_MIGRATIONS", mig)
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vpsID, err := db.CreateVPS(&VPS{Name: "m", Host: "127.0.0.1", SSHUser: "u", SSHPort: 22, Tags: "[]", MaintenanceWins: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if err := db.SaveScanResult(vpsID, `{"n":`+strconv.Itoa(i)+`}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.PruneScanResults(vpsID, 5); err != nil {
		t.Fatal(err)
	}
	scans, err := db.ListScans(vpsID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 5 {
		t.Fatalf("keep 5 got %d", len(scans))
	}
	if scans[0].Payload != `{"n":11}` || scans[4].Payload != `{"n":7}` {
		t.Fatalf("unexpected order: %v %v", scans[0].Payload, scans[4].Payload)
	}
}
