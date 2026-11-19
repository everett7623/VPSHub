package tasks

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/store"
)

func TestWaitingApprovalDoesNotExecute(t *testing.T) {
	db := taskDB(t)
	vpsID, err := db.CreateVPS(&store.VPS{Name: "a", Host: "10.0.0.8", SSHUser: "ops", OpMode: "high_risk_allowed"})
	if err != nil {
		t.Fatal(err)
	}
	task := &store.Task{
		ID: "wait-1", Type: "shell", Status: store.InitialTaskStatus("shell", "high", false), RiskLevel: "high",
		CanaryVPSIds: "[]", Payload: `{"command":"uname"}`, Concurrency: 1, TimeoutSec: 30,
	}
	if task.Status != "waiting_approval" {
		t.Fatal(task.Status)
	}
	if err := db.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTaskItem(task.ID, vpsID); err != nil {
		t.Fatal(err)
	}
	w := NewWorker(db, config.Default(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.poll(context.Background())
	got, err := db.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "waiting_approval" {
		t.Fatalf("waiting task executed: %s", got.Status)
	}
	items, err := db.ListTaskItems(task.ID)
	if err != nil || len(items) != 1 || items[0].Status != "pending" || items[0].LogText != "" {
		t.Fatalf("item ran: %+v %v", items, err)
	}
	pending, err := db.ListPendingTasks()
	if err != nil || len(pending) != 0 {
		t.Fatalf("listed as runnable: %+v %v", pending, err)
	}
}

func taskDB(t *testing.T) *store.DB {
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
