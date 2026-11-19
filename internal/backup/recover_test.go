package backup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
)

func TestRecoverWithKey(t *testing.T) {
	dir := t.TempDir()
	root, _ := os.Getwd()
	mig := filepath.Join(root, "..", "..", "migrations")
	if _, err := os.Stat(mig); err != nil {
		mig = filepath.Join(root, "migrations")
	}
	t.Setenv("VPSHUB_MIGRATIONS", mig)
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	vault := crypto.NewVault(0)
	svc := New(db, dir, vault)

	vpsID, err := db.CreateVPS(&store.VPS{
		Name: "r1", Host: "10.0.0.1", SSHUser: "root", OpMode: "normal_tasks", Tags: "[]", MaintenanceWins: "[]",
	})
	if err != nil {
		t.Fatal(err)
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	kek := crypto.DeriveKEK("original-master-pw", salt)
	defer crypto.Wipe(kek)
	verifier, err := crypto.Encrypt(kek, []byte("vpshub-vault-ok"))
	if err != nil {
		t.Fatal(err)
	}
	rec, hash, recSalt, wrapped, err := crypto.NewRecoveryBundle(kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InitVaultMeta(&store.VaultMeta{
		Salt: salt, Verifier: verifier, RecoveryHash: hash,
		RecoverySalt: recSalt, RecoveryWrappedKEK: wrapped,
	}); err != nil {
		t.Fatal(err)
	}
	ct, err := crypto.Encrypt(kek, []byte("ssh-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertCredential(vpsID, "ssh_password", ct); err != nil {
		t.Fatal(err)
	}

	newRec, err := svc.RecoverWithKey(rec, "brand-new-master")
	if err != nil {
		t.Fatal(err)
	}
	if newRec == "" || newRec == rec {
		t.Fatal("expected new recovery key")
	}
	if vault.State() != crypto.VaultUnlocked {
		t.Fatalf("want unlocked, got %s", vault.State())
	}
	pt, err := vault.DecryptSecret(mustCred(t, db))
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(pt)
	if string(pt) != "ssh-secret" {
		t.Fatalf("cred %q", pt)
	}

	if _, err := svc.RecoverWithKey("bogus-key", "another-password"); err == nil {
		t.Fatal("bad recovery should fail")
	}
}

func mustCred(t *testing.T, db *store.DB) []byte {
	t.Helper()
	creds, err := db.AllCredentialBlobs()
	if err != nil || len(creds) != 1 {
		t.Fatalf("creds: %v %d", err, len(creds))
	}
	return creds[0].Ciphertext
}
