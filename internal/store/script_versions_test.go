package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScriptVersionSnapshot(t *testing.T) {
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

	id, err := db.CreateScript(&Script{
		Name: "t", Version: "1.0.0", Content: "echo 1", SHA256: "abc", Status: "published",
		OSFilter: "[]", ParamsSchema: "[]", RiskLevel: "low",
	})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := db.GetScript(id)
	if err != nil {
		t.Fatal(err)
	}
	vid, err := db.SnapshotScriptVersion(sc, "publish", "admin")
	if err != nil || vid == 0 {
		t.Fatalf("snap: %v %d", err, vid)
	}
	list, err := db.ListScriptVersions(id)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	got, err := db.GetScriptVersion(id, vid)
	if err != nil || got.Content != "echo 1" || got.Note != "publish" {
		t.Fatalf("get: %+v %v", got, err)
	}
}
