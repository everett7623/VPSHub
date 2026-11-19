package store

import "errors"

// ErrOpMode means the VPS operation mode rejects this change.
var ErrOpMode = errors.New("op_mode_blocks")

// AllowChange enforces the four operation modes.
// readonly_monitor and no_changes reject every change.
// high and critical risk require high_risk_allowed.
func AllowChange(opMode, risk string) error {
	if opMode == "" {
		opMode = "normal_tasks"
	}
	if opMode == "readonly_monitor" || opMode == "no_changes" {
		return ErrOpMode
	}
	if (risk == "high" || risk == "critical") && opMode != "high_risk_allowed" {
		return ErrOpMode
	}
	return nil
}
