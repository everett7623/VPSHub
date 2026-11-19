package store

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrConfirmRequired = errors.New("confirm required")
	ErrDangerConfirm   = errors.New("confirm_danger required")
	ErrOutsideWindow   = errors.New("outside_maintenance_window")
)

// InitialTaskStatus keeps scans, dry-runs, and low/medium work immediate.
// Live high and critical tasks wait until an admin approves them.
func InitialTaskStatus(taskType, risk string, dryRun bool) string {
	if dryRun || taskType == "scan" || (risk != "high" && risk != "critical") {
		return "pending"
	}
	return "waiting_approval"
}

// CheckApproval re-checks op_mode, the maintenance window, and confirm flags
// before a waiting task is allowed to run.
func CheckApproval(v *VPS, taskType, risk string, requires []string, confirm, confirmDanger, confirmDisablePassword, confirmOutside bool, now time.Time) error {
	if !confirm {
		return ErrConfirmRequired
	}
	flags := map[string]bool{
		"confirm_danger":           confirmDanger,
		"confirm_disable_password": confirmDisablePassword,
	}
	for _, req := range requires {
		switch req {
		case "confirm_danger":
			if !confirmDanger {
				return ErrDangerConfirm
			}
		case "confirm_disable_password":
			if !confirmDisablePassword {
				return fmt.Errorf("confirm_disable_password required")
			}
		default:
			if !flags[req] {
				return fmt.Errorf("%s required", req)
			}
		}
	}
	if taskType != "scan" {
		if err := AllowChange(v.OpMode, risk); err != nil {
			return err
		}
	}
	if (risk == "high" || risk == "critical") && !InMaintenanceWindow(v.MaintenanceWins, now) && !confirmOutside {
		return ErrOutsideWindow
	}
	return nil
}

// RejectWaitingTask marks a task rejected and skips its items so they do not run.
func (db *DB) RejectWaitingTask(id string) error {
	t, err := db.GetTask(id)
	if err != nil {
		return err
	}
	if t.Status != "waiting_approval" {
		return fmt.Errorf("not waiting approval")
	}
	if err := db.UpdateTaskStatus(id, "rejected"); err != nil {
		return err
	}
	items, err := db.ListTaskItems(id)
	if err != nil {
		return err
	}
	fin := time.Now()
	for _, it := range items {
		it.Status = "skipped"
		it.Result = "rejected"
		it.FinishedAt = &fin
		if err := db.UpdateTaskItem(it); err != nil {
			return err
		}
	}
	return nil
}
