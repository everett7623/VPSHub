package sshx

import (
	"strings"
	"testing"
)

func TestJailPath(t *testing.T) {
	got, err := JailPath("/var/backups", "../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/var/backups/etc/passwd" {
		t.Fatalf("escaped or unexpected: %s", got)
	}
	got, err = JailPath("/var/backups", "/etc/passwd")
	if err != nil || got != "/var/backups/etc/passwd" {
		t.Fatalf("%s %v", got, err)
	}
	got, err = JailPath("/var/backups", "foo/../../../../etc/shadow")
	if err != nil || !strings.HasPrefix(got, "/var/backups/") {
		t.Fatalf("outside root: %s %v", got, err)
	}
	if _, err := JailPath("", "note.txt"); err == nil {
		t.Fatal("empty root accepted")
	}
	sib, err := JailPath("/var/backups", "../backups-evil/x")
	if err != nil || sib != "/var/backups/backups-evil/x" {
		t.Fatalf("sibling jail: %s %v", sib, err)
	}
	if _, err := RequireSFTPRoot("/", "note.txt"); err == nil {
		t.Fatal("filesystem root accepted")
	}
	if _, err := RequireSFTPRoot("", "note.txt"); err == nil {
		t.Fatal("missing root accepted")
	}
	if _, err := RequireSFTPRoot("/var/backups", "."); err == nil {
		t.Fatal("directory root accepted as a file")
	}
	full, err := RequireSFTPRoot("/srv/files", "app.conf")
	if err != nil || full != "/srv/files/app.conf" {
		t.Fatalf("%s %v", full, err)
	}
	if DistributeMaxHosts != 40 || MaxUploadBytes != 10<<20 {
		t.Fatalf("caps %d %d", DistributeMaxHosts, MaxUploadBytes)
	}
}
