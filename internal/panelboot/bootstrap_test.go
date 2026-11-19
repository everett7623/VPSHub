package panelboot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
)

func TestBootstrapOnce(t *testing.T) {
	root := t.TempDir()
	mig := filepath.Join("..", "..", "migrations")
	if _, err := os.Stat(mig); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VPSHUB_MIGRATIONS", mig)
	data := filepath.Join(root, "data")
	cfgPath := filepath.Join(root, "config.yaml")
	body := "listen: \"127.0.0.1:18080\"\ndata_dir: " + quote(data) + "\nbase_path: \"/h/testpath\"\nbasic_auth_user: \"\"\nbasic_auth_hash: \"\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Bootstrap(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.PanelPassword == "" || res.BasicPassword == "" || !strings.HasPrefix(res.TOTPURL, "otpauth://") {
		t.Fatalf("incomplete result: %+v", res)
	}
	raw, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(raw), res.BasicPassword) || strings.Contains(string(raw), res.PanelPassword) {
		t.Fatal("plaintext secret written to config")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.VerifyPassword(res.BasicPassword, cfg.BasicAuthHash) {
		t.Fatal("basic auth hash does not match")
	}
	db, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin, err := db.FirstAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if !admin.MustChangePassword || !admin.TOTPEnabled {
		t.Fatalf("admin flags: change=%v totp=%v", admin.MustChangePassword, admin.TOTPEnabled)
	}
	if !crypto.VerifyPassword(res.PanelPassword, admin.PasswordHash) {
		t.Fatal("panel password hash mismatch")
	}
	again, err := Bootstrap(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.PanelPassword != "" || again.BasicPassword != "" {
		t.Fatal("second bootstrap rotated secrets")
	}
	text := Format(again)
	if strings.Contains(text, "password=") {
		t.Fatal(text)
	}
}

func quote(s string) string {
	return "\"" + filepath.ToSlash(s) + "\""
}
