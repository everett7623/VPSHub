package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitialTaskStatus(t *testing.T) {
	if InitialTaskStatus("scan", "critical", false) != "pending" {
		t.Fatal("scan must stay immediate")
	}
	if InitialTaskStatus("shell", "low", false) != "pending" || InitialTaskStatus("shell", "medium", false) != "pending" {
		t.Fatal("low and medium must stay immediate")
	}
	if InitialTaskStatus("shell", "high", false) != "waiting_approval" || InitialTaskStatus("config_backup", "critical", false) != "waiting_approval" {
		t.Fatal("high and critical must wait")
	}
	if InitialTaskStatus("config_restore", "high", true) != "pending" {
		t.Fatal("dry-run must not wait for approval")
	}
}

func TestCheckApprovalKeepsGates(t *testing.T) {
	now := time.Date(2026, 10, 23, 15, 0, 0, 0, time.UTC)
	open := &VPS{OpMode: "high_risk_allowed", MaintenanceWins: "[]"}
	if err := CheckApproval(open, "shell", "high", nil, true, false, false, false, now); err != nil {
		t.Fatal(err)
	}
	normal := &VPS{OpMode: "normal_tasks", MaintenanceWins: "[]"}
	if err := CheckApproval(normal, "shell", "high", nil, true, false, false, false, now); err != ErrOpMode {
		t.Fatalf("high on normal_tasks: %v", err)
	}
	windowed := &VPS{OpMode: "high_risk_allowed", MaintenanceWins: `[{"weekdays":[0],"start":"03:00","end":"04:00"}]`}
	if err := CheckApproval(windowed, "shell", "critical", nil, true, false, false, false, now); err != ErrOutsideWindow {
		t.Fatalf("window: %v", err)
	}
	if err := CheckApproval(windowed, "shell", "critical", nil, true, false, false, true, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckApproval(open, "shell", "high", []string{"confirm_danger"}, true, false, false, false, now); err != ErrDangerConfirm {
		t.Fatalf("danger: %v", err)
	}
	if err := CheckApproval(open, "shell", "critical", []string{"confirm_disable_password"}, true, false, false, false, now); err == nil {
		t.Fatal("disable-password confirm missing")
	}
	if err := CheckApproval(open, "shell", "high", nil, false, true, true, true, now); err != ErrConfirmRequired {
		t.Fatal(err)
	}
}

func TestWaitingApprovalIsNotPending(t *testing.T) {
	db := approvalDB(t)
	vpsID, err := db.CreateVPS(&VPS{Name: "a", Host: "10.0.0.1", SSHUser: "ops", OpMode: "high_risk_allowed"})
	if err != nil {
		t.Fatal(err)
	}
	waiting := &Task{ID: "wait", Type: "shell", Status: "waiting_approval", RiskLevel: "high", CanaryVPSIds: "[]", Payload: `{"command":"true"}`}
	pending := &Task{ID: "go", Type: "shell", Status: "pending", RiskLevel: "low", CanaryVPSIds: "[]", Payload: `{"command":"true"}`}
	if err := db.CreateTask(waiting); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateTask(pending); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTaskItem(waiting.ID, vpsID); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListPendingTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "go" {
		t.Fatalf("pending list: %+v", list)
	}
	if err := db.RejectWaitingTask(waiting.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetTask(waiting.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "rejected" || got.FinishedAt == nil {
		t.Fatalf("rejected: %+v", got)
	}
	items, err := db.ListTaskItems(waiting.ID)
	if err != nil || len(items) != 1 || items[0].Status != "skipped" || items[0].Result != "rejected" {
		t.Fatalf("items: %+v %v", items, err)
	}
	list, _ = db.ListPendingTasks()
	if len(list) != 1 || list[0].ID != "go" {
		t.Fatal("rejected task became runnable")
	}
	if err := db.RejectWaitingTask(waiting.ID); err == nil {
		t.Fatal("second reject should fail")
	}
}

func approvalDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	root, _ := os.Getwd()
	mig := filepath.Join(root, "..", "..", "migrations")
	t.Setenv("VPSHUB_MIGRATIONS", mig)
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
