package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evenfrank/vpshub/internal/store"
)

func TestBuiltinDraftsStaySafe(t *testing.T) {
	banned := []string{"curl|bash", "curl | bash", "wget | sh", "chmod 777", "useradd", "nft ", "iptables -F", "ufw reset"}
	names := map[string]bool{}
	for _, sc := range builtins {
		names[sc.Name] = true
		if sc.Status != "draft" || sc.Source != "builtin" || sc.CreatedBy != "system" {
			t.Fatalf("%s not a system draft", sc.Name)
		}
		if hits := DangerousPatterns(sc.Content); len(hits) > 0 {
			t.Fatalf("%s dangerous: %v", sc.Name, hits)
		}
		lower := strings.ToLower(sc.Content)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Fatalf("%s contains %s", sc.Name, b)
			}
		}
	}
	for _, want := range []string{
		"disk-report", "reboot-required", "docker-ps", "failed-units", "listening-ports",
		"cert-files-present", "security-update-count", "uptime-load", "swap-report", "os-release", "ipv6-addresses", "echo-params",
		"fail2ban-status", "docker-disk", "timedate-sync",
	} {
		if !names[want] {
			t.Fatalf("missing builtin %s", want)
		}
	}
}

func TestOpsBuiltinsRiskSplit(t *testing.T) {
	published := map[string]bool{}
	draft := map[string]bool{}
	for _, sc := range opsBuiltins {
		if sc.Source != "builtin" || sc.CreatedBy != "system" {
			t.Fatalf("%s bad meta", sc.Name)
		}
		if hits := DangerousPatterns(sc.Content); len(hits) > 0 {
			t.Fatalf("%s dangerous: %v", sc.Name, hits)
		}
		switch sc.Status {
		case "published":
			published[sc.Name] = true
			if !sc.AllowBatch {
				t.Fatalf("%s published should allow batch", sc.Name)
			}
		case "draft":
			draft[sc.Name] = true
		default:
			t.Fatalf("%s unexpected status %s", sc.Name, sc.Status)
		}
	}
	for _, want := range []string{
		"security-baseline", "conn-summary", "process-top", "disk-inodes", "large-files-tmp",
		"docker-prune-dry", "apt-autoremove-dry", "sysctl-network-tune-check", "auth-log-tail",
	} {
		if !published[want] {
			t.Fatalf("missing published ops %s", want)
		}
	}
	for _, want := range []string{"docker-prune", "apt-autoremove", "journal-vacuum"} {
		if !draft[want] {
			t.Fatalf("missing draft mutating ops %s", want)
		}
	}
}

func TestSeedIdempotent(t *testing.T) {
	db := scriptDB(t)
	if err := Seed(db); err != nil {
		t.Fatal(err)
	}
	if err := Seed(db); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListScripts("")
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, sc := range list {
		count[sc.Name]++
		if sc.Source != "builtin" {
			continue
		}
		if sc.CreatedBy != "system" {
			t.Fatalf("seed mutated %s created_by=%s", sc.Name, sc.CreatedBy)
		}
		switch sc.Status {
		case "draft":
			if err := CanExecute(sc, false); err != ErrNotApproved {
				t.Fatalf("%s draft should not execute: %v", sc.Name, err)
			}
		case "published", "approved":
			if err := CanExecute(sc, false); err != nil {
				t.Fatalf("%s published should execute: %v", sc.Name, err)
			}
		default:
			t.Fatalf("unexpected status %s for %s", sc.Status, sc.Name)
		}
	}
	if count["listening-ports"] != 1 || count["uptime-load"] != 1 || count["os-release"] != 1 || count["disk-report"] != 1 {
		t.Fatalf("counts: %#v", count)
	}
	if count["security-baseline"] != 1 || count["docker-prune-dry"] != 1 {
		t.Fatalf("missing ops builtins: %#v", count)
	}
}

func scriptDB(t *testing.T) *store.DB {
	t.Helper()
	dir := t.TempDir()
	root, _ := os.Getwd()
	t.Setenv("VPSHUB_MIGRATIONS", filepath.Join(root, "..", "..", "migrations"))
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
