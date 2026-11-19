package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/evenfrank/vpshub/internal/crypto"
)

func TestWriteBasicAuthKeepsListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "listen: \"127.0.0.1:23456\"\nbasic_auth_user: \"\"\nbasic_auth_hash: \"\"\nbase_path: \"/h/abc\"\n"
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.HashPassword("not-the-stored-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBasicAuth(path, "gate-user", hash); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:23456" || cfg.BasePath != "/h/abc" {
		t.Fatalf("config mutated: %+v", cfg)
	}
	if cfg.BasicAuthUser != "gate-user" || !crypto.VerifyPassword("not-the-stored-secret", cfg.BasicAuthHash) {
		t.Fatal("basic auth hash was not stored")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) == "" || containsPlain(string(raw), "not-the-stored-secret") {
		t.Fatal("plaintext password written to config")
	}
}

func containsPlain(s, needle string) bool {
	return len(needle) > 0 && len(s) >= len(needle) && (s == needle || len(s) > 0 && (contains(s, needle)))
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(find(s, sub)) > 0))
}

func find(s, sub string) string {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return s[i:]
		}
	}
	return ""
}
