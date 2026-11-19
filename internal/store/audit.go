package store

import (
	"encoding/json"
	"fmt"

	"github.com/evenfrank/vpshub/internal/crypto"
)

func (db *DB) lastAuditHash() (string, error) {
	var h string
	err := db.QueryRow(`SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&h)
	if err != nil {
		return "", nil // empty chain start
	}
	return h, nil
}

type AuditInput struct {
	Actor         string
	IP            string
	Action        string
	TargetType    string
	TargetID      string
	RiskLevel     string
	TaskID        string
	Result        string
	Detail        string
	FailureReason string
}

func (db *DB) AppendAudit(in AuditInput) error {
	if in.RiskLevel == "" {
		in.RiskLevel = "low"
	}
	if in.Result == "" {
		in.Result = "success"
	}
	prev, _ := db.lastAuditHash()
	payload, _ := json.Marshal(map[string]string{
		"actor": in.Actor, "ip": in.IP, "action": in.Action,
		"target_type": in.TargetType, "target_id": in.TargetID,
		"risk": in.RiskLevel, "result": in.Result, "detail": in.Detail,
		"failure": in.FailureReason, "task_id": in.TaskID, "prev": prev,
	})
	entryHash := crypto.HashChain(prev, payload)
	_, err := db.Exec(`INSERT INTO audit_logs(actor, ip, action, target_type, target_id, risk_level, task_id,
		result, detail, failure_reason, prev_hash, entry_hash)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		in.Actor, in.IP, in.Action, in.TargetType, in.TargetID, in.RiskLevel, nullStr(in.TaskID),
		in.Result, in.Detail, in.FailureReason, prev, entryHash)
	return err
}

type AuditFilter struct {
	Action string
	Actor  string
	Risk   string
	Result string
	Q      string
	Limit  int
	Offset int
}

func (db *DB) ListAudit(limit, offset int) ([]AuditEntry, error) {
	return db.ListAuditFiltered(AuditFilter{Limit: limit, Offset: offset})
}

func (db *DB) ListAuditActions() ([]string, error) {
	rows, err := db.Query(`SELECT DISTINCT action FROM audit_logs WHERE action != '' ORDER BY action ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (db *DB) ListAuditFiltered(f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	q := `SELECT id, COALESCE(actor,''), COALESCE(ip,''), action, COALESCE(target_type,''),
		COALESCE(target_id,''), risk_level, COALESCE(task_id,''), result, COALESCE(detail,''),
		COALESCE(failure_reason,''), prev_hash, entry_hash, created_at
		FROM audit_logs WHERE 1=1`
	var args []any
	if f.Action != "" {
		q += ` AND action=?`
		args = append(args, f.Action)
	}
	if f.Actor != "" {
		q += ` AND actor=?`
		args = append(args, f.Actor)
	}
	if f.Risk != "" {
		q += ` AND risk_level=?`
		args = append(args, f.Risk)
	}
	if f.Result != "" {
		q += ` AND result=?`
		args = append(args, f.Result)
	}
	if f.Q != "" {
		q += ` AND (action LIKE ? OR actor LIKE ? OR target_id LIKE ? OR COALESCE(detail,'') LIKE ?)`
		like := "%" + f.Q + "%"
		args = append(args, like, like, like, like)
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Actor, &e.IP, &e.Action, &e.TargetType, &e.TargetID, &e.RiskLevel,
			&e.TaskID, &e.Result, &e.Detail, &e.FailureReason, &e.PrevHash, &e.EntryHash, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) VerifyAuditChain() (bool, error) {
	rows, err := db.Query(`SELECT id, actor, ip, action, target_type, target_id, risk_level, task_id, result,
		detail, failure_reason, prev_hash, entry_hash FROM audit_logs ORDER BY id ASC`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var e AuditEntry
		var taskID, detail, fail, tt, tid, actor, ip *string
		if err := rows.Scan(&e.ID, &actor, &ip, &e.Action, &tt, &tid, &e.RiskLevel, &taskID,
			&e.Result, &detail, &fail, &e.PrevHash, &e.EntryHash); err != nil {
			return false, err
		}
		if actor != nil {
			e.Actor = *actor
		}
		if ip != nil {
			e.IP = *ip
		}
		if tt != nil {
			e.TargetType = *tt
		}
		if tid != nil {
			e.TargetID = *tid
		}
		if taskID != nil {
			e.TaskID = *taskID
		}
		if detail != nil {
			e.Detail = *detail
		}
		if fail != nil {
			e.FailureReason = *fail
		}
		if e.PrevHash != prev {
			return false, fmt.Errorf("chain break at id %d", e.ID)
		}
		payload, _ := json.Marshal(map[string]string{
			"actor": e.Actor, "ip": e.IP, "action": e.Action,
			"target_type": e.TargetType, "target_id": e.TargetID,
			"risk": e.RiskLevel, "result": e.Result, "detail": e.Detail,
			"failure": e.FailureReason, "task_id": e.TaskID, "prev": prev,
		})
		want := crypto.HashChain(prev, payload)
		if want != e.EntryHash {
			return false, fmt.Errorf("hash mismatch at id %d", e.ID)
		}
		prev = e.EntryHash
	}
	return true, rows.Err()
}
