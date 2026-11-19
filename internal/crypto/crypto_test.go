package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("secret-pass", h) {
		t.Fatal("verify failed")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("wrong password should fail")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	salt, _ := NewSalt()
	kek := DeriveKEK("master", salt)
	pt := []byte("ssh-password-plaintext")
	ct, err := Encrypt(kek, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(kek, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("got %q want %q", got, pt)
	}
	wrong := DeriveKEK("wrong", salt)
	if _, err := Decrypt(wrong, ct); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestVaultLifecycle(t *testing.T) {
	v := NewVault(50 * time.Millisecond)
	salt, _ := NewSalt()
	if v.State() != VaultLocked {
		t.Fatal("expected locked")
	}
	v.Unlock("mp", salt)
	if v.State() != VaultUnlocked {
		t.Fatal("expected unlocked")
	}
	ct, err := v.EncryptSecret([]byte("cred"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := v.DecryptSecret(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "cred" {
		t.Fatal("mismatch")
	}
	v.Lock()
	if _, err := v.DecryptSecret(ct); err != ErrVaultLocked {
		t.Fatalf("want locked, got %v", err)
	}
	v.Unlock("mp", salt)
	time.Sleep(60 * time.Millisecond)
	if v.State() != VaultExpired {
		t.Fatalf("want expired, got %s", v.State())
	}
}

func TestHashChain(t *testing.T) {
	a := HashChain("", []byte("first"))
	b := HashChain(a, []byte("second"))
	if a == b || a == "" {
		t.Fatal("bad chain")
	}
}

func TestRecoveryWrap(t *testing.T) {
	salt, _ := NewSalt()
	kek := DeriveKEK("master-password-ok", salt)
	rec, hash, recSalt, wrapped, err := NewRecoveryBundle(kek)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRecoveryKey(hash, rec) {
		t.Fatal("verify recovery key")
	}
	if VerifyRecoveryKey(hash, "wrong") {
		t.Fatal("wrong key should fail")
	}
	got, err := UnwrapKEK(rec, recSalt, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(got)
	if !bytes.Equal(got, kek) {
		t.Fatal("unwrap mismatch")
	}
	if _, err := UnwrapKEK("not-the-key", recSalt, wrapped); err == nil {
		t.Fatal("bad recovery should fail")
	}
}
