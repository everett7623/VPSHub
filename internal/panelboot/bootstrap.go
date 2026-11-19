package panelboot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evenfrank/vpshub/internal/auth"
	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
)

// Result is the one-time install secret bundle. Empty secret fields mean they were not generated.
type Result struct {
	Created       bool
	BasicUser     string
	BasicPassword string
	PanelUser     string
	PanelPassword string
	TOTPURL       string
	Listen        string
	BasePath      string
	Scheme        string
}

// Bootstrap creates the first admin and optional browser basic-auth hash.
// A second run does not rotate secrets.
func Bootstrap(cfgPath string) (Result, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return Result{}, err
	}
	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = secureData(cfg.DataDir) }()
	defer db.Close()

	res := Result{Listen: cfg.Listen, BasePath: cfg.BasePath, Scheme: "http"}
	if cfg.TLSEnabled() {
		res.Scheme = "https"
	}
	n, err := db.CountAdmins()
	if err != nil {
		return Result{}, err
	}
	if n > 0 {
		return res, nil
	}

	id, err := crypto.RandomID(5)
	if err != nil {
		return Result{}, err
	}
	panelUser := "op" + id
	panelPass, err := crypto.RandomPassword(24)
	if err != nil {
		return Result{}, err
	}
	totpURL, err := auth.New(db, cfg).ProvisionInitialAdmin(panelUser, panelPass)
	if err != nil {
		return Result{}, err
	}
	res.Created = true
	res.PanelUser = panelUser
	res.PanelPassword = panelPass
	res.TOTPURL = totpURL

	if !cfg.BasicAuthEnabled() {
		basicID, err := crypto.RandomID(5)
		if err != nil {
			return Result{}, err
		}
		basicUser := "gate" + basicID
		basicPass, err := crypto.RandomPassword(24)
		if err != nil {
			return Result{}, err
		}
		hash, err := crypto.HashPassword(basicPass)
		if err != nil {
			return Result{}, err
		}
		if err := config.WriteBasicAuth(cfgPath, basicUser, hash); err != nil {
			return Result{}, err
		}
		res.BasicUser = basicUser
		res.BasicPassword = basicPass
	}
	return res, nil
}

// ResetPassword sets a new random password for the first admin and requires a change.
func ResetPassword(cfgPath string) (username, password string, err error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return "", "", err
	}
	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return "", "", err
	}
	defer db.Close()
	admin, err := db.FirstAdmin()
	if err != nil {
		return "", "", fmt.Errorf("no admin: %w", err)
	}
	password, err = crypto.RandomPassword(24)
	if err != nil {
		return "", "", err
	}
	if err := auth.New(db, cfg).ResetPassword(admin.ID, password); err != nil {
		return "", "", err
	}
	return admin.Username, password, nil
}

// ApplyRestoredDB renames vpshub.db.restored over vpshub.db (with a .bak of the current DB).
// Call only when the panel process is stopped so the SQLite files are not open.
func ApplyRestoredDB(dataDir string) error {
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat("vpshub.db.restored"); err != nil {
		return fmt.Errorf("missing vpshub.db.restored — restore a backup from the panel first")
	}
	if _, err := root.Stat("vpshub.db"); err == nil {
		_ = root.Remove("vpshub.db.bak")
		if err := os.Rename(filepath.Join(dataDir, "vpshub.db"), filepath.Join(dataDir, "vpshub.db.bak")); err != nil {
			return fmt.Errorf("backup current db: %w", err)
		}
	}
	if err := os.Rename(filepath.Join(dataDir, "vpshub.db.restored"), filepath.Join(dataDir, "vpshub.db")); err != nil {
		return fmt.Errorf("apply restored db: %w", err)
	}
	fmt.Println("ok: vpshub.db replaced; previous file at vpshub.db.bak if it existed")
	fmt.Println("start the panel again (e.g. systemctl start vpshub)")
	return nil
}

// Format prints machine-readable fields. Secrets appear only when they were just created.
func Format(res Result) string {
	var b strings.Builder
	if res.Created {
		b.WriteString("created=1\n")
	} else {
		b.WriteString("created=0\n")
	}
	fmt.Fprintf(&b, "listen=%s\nbase_path=%s\nscheme=%s\n", res.Listen, res.BasePath, res.Scheme)
	if !res.Created {
		return b.String()
	}
	fmt.Fprintf(&b, "basic_user=%s\nbasic_password=%s\npanel_user=%s\npanel_password=%s\ntotp_url=%s\n",
		res.BasicUser, res.BasicPassword, res.PanelUser, res.PanelPassword, res.TOTPURL)
	return b.String()
}
