package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverRunningTasks(t *testing.T) {
	dir := t.TempDir()
	root, _ := os.Getwd()
	t.Setenv("VPSHUB_MIGRATIONS", filepath.Join(root, "..", "..", "migrations"))
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	vpsID, err := db.CreateVPS(&VPS{Name: "r", Host: "10.0.0.9", SSHUser: "ops", OpMode: "normal_tasks"})
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{
		ID: "rec-1", Type: "shell", Status: "running", RiskLevel: "low",
		CanaryVPSIds: "[]", Payload: `{"command":"true"}`,
	}
	if err := db.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTaskItem(task.ID, vpsID); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListTaskItems(task.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("items: %v", err)
	}
	items[0].Status = "running"
	if err := db.UpdateTaskItem(items[0]); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}

	if err := db.RecoverRunningTasks(); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetTask(task.ID)
	if err != nil || got.Status != "pending" {
		t.Fatalf("task status: %+v %v", got, err)
	}
	items, _ = db.ListTaskItems(task.ID)
	if len(items) != 1 || items[0].Status != "pending" {
		t.Fatalf("items: %+v", items)
	}
}
