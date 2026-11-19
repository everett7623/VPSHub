package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListVPSProviderIDFilter(t *testing.T) {
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

	p1, err := db.CreateProvider(&Provider{Name: "ProvA"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := db.CreateProvider(&Provider{Name: "ProvB"})
	if err != nil {
		t.Fatal(err)
	}
	id1, err := db.CreateVPS(&VPS{
		Name: "a", Host: "10.0.0.1", SSHUser: "ops", OpMode: "normal_tasks",
		Tags: "[]", MaintenanceWins: "[]", Environment: "testing", ProviderID: &p1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateVPS(&VPS{
		Name: "b", Host: "10.0.0.2", SSHUser: "ops", OpMode: "normal_tasks",
		Tags: "[]", MaintenanceWins: "[]", Environment: "testing", ProviderID: &p2,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := db.ListVPS(VPSFilter{ProviderID: p1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != id1 {
		t.Fatalf("want 1 vps id=%d, got %#v", id1, got)
	}
	all, err := db.ListVPS(VPSFilter{})
	if err != nil || len(all) != 2 {
		t.Fatalf("all=%d err=%v", len(all), err)
	}
}
