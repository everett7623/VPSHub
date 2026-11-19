package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/evenfrank/vpshub/internal/crypto"
)

func TestMigrateAndAuditChain(t *testing.T) {
	dir := t.TempDir()
	// point migrations to repo migrations via env
	root, _ := os.Getwd()
	// when running from internal/store, migrations are ../..
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

	if err := db.AppendAudit(AuditInput{Actor: "a", Action: "login", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendAudit(AuditInput{Actor: "a", Action: "vps_create", TargetType: "vps", TargetID: "1"}); err != nil {
		t.Fatal(err)
	}
	actions, err := db.ListAuditActions()
	if err != nil || len(actions) < 2 {
		t.Fatalf("actions: %v %v", actions, err)
	}
	ok, err := db.VerifyAuditChain()
	if err != nil || !ok {
		t.Fatalf("chain: %v %v", ok, err)
	}

	id, err := db.CreateVPS(&VPS{Name: "t1", Host: "1.2.3.4", SSHUser: "root", OpMode: "normal_tasks", Tags: "[]", MaintenanceWins: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := crypto.NewSalt()
	kek := crypto.DeriveKEK("master-password-xyz", salt)
	ct, err := crypto.Encrypt(kek, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertCredential(id, "ssh_password", ct); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetCredential(id, "ssh_password")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.Decrypt(kek, got)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("cred roundtrip failed")
	}

	if err := db.SoftDeleteVPS(id); err != nil {
		t.Fatal(err)
	}
	del, err := db.ListDeletedVPS()
	if err != nil || len(del) != 1 || del[0].ID != id {
		t.Fatalf("deleted list: %v %v", del, err)
	}
	if err := db.RestoreVPS(id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetVPS(id); err != nil {
		t.Fatal(err)
	}

	filtered, err := db.ListAuditFiltered(AuditFilter{Action: "vps_create", Limit: 10})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("audit filter: %v %v", filtered, err)
	}
}
