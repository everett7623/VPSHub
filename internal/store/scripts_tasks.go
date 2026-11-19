package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (db *DB) CreateScript(s *Script) (int64, error) {
	res, err := db.Exec(`INSERT INTO scripts(name, category, version, os_filter, params_schema, content,
		rollback_content, healthcheck_content, sensitive, risk_level, allow_batch, allow_production,
		sha256, source, status, created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.Name, s.Category, s.Version, s.OSFilter, s.ParamsSchema, s.Content, s.RollbackContent,
		s.HealthcheckContent, boolInt(s.Sensitive), s.RiskLevel, boolInt(s.AllowBatch), boolInt(s.AllowProduction),
		s.SHA256, s.Source, s.Status, s.CreatedBy)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (db *DB) GetScript(id int64) (*Script, error) {
	s := &Script{}
	var sens, batch, prod int
	err := db.QueryRow(`SELECT id, name, COALESCE(category,''), version, COALESCE(os_filter,'[]'),
		COALESCE(params_schema,'[]'), content, COALESCE(rollback_content,''), COALESCE(healthcheck_content,''),
		sensitive, risk_level, allow_batch, allow_production, sha256, COALESCE(source,''), status,
		COALESCE(created_by,''), COALESCE(reviewed_by,''), created_at, updated_at FROM scripts WHERE id=?`, id).
		Scan(&s.ID, &s.Name, &s.Category, &s.Version, &s.OSFilter, &s.ParamsSchema, &s.Content,
			&s.RollbackContent, &s.HealthcheckContent, &sens, &s.RiskLevel, &batch, &prod, &s.SHA256,
			&s.Source, &s.Status, &s.CreatedBy, &s.ReviewedBy, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	s.Sensitive = sens == 1
	s.AllowBatch = batch == 1
	s.AllowProduction = prod == 1
	return s, err
}

func (db *DB) ListScripts(status string) ([]*Script, error) {
	return db.ListScriptsFiltered(status, "")
}

func (db *DB) ListScriptsFiltered(status, category string) ([]*Script, error) {
	q := `SELECT id, name, COALESCE(category,''), version, COALESCE(os_filter,'[]'), COALESCE(params_schema,'[]'),
		content, COALESCE(rollback_content,''), COALESCE(healthcheck_content,''), sensitive, risk_level,
		allow_batch, allow_production, sha256, COALESCE(source,''), status, COALESCE(created_by,''),
		COALESCE(reviewed_by,''), created_at, updated_at FROM scripts WHERE 1=1`
	var args []any
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	if category != "" {
		q += ` AND category=?`
		args = append(args, category)
	}
	q += ` ORDER BY id DESC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Script
	for rows.Next() {
		s := &Script{}
		var sens, batch, prod int
		if err := rows.Scan(&s.ID, &s.Name, &s.Category, &s.Version, &s.OSFilter, &s.ParamsSchema, &s.Content,
			&s.RollbackContent, &s.HealthcheckContent, &sens, &s.RiskLevel, &batch, &prod, &s.SHA256,
			&s.Source, &s.Status, &s.CreatedBy, &s.ReviewedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		s.Sensitive = sens == 1
		s.AllowBatch = batch == 1
		s.AllowProduction = prod == 1
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) UpdateScriptStatus(id int64, status, reviewer string) error {
	_, err := db.Exec(`UPDATE scripts SET status=?, reviewed_by=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		status, reviewer, id)
	return err
}

func (db *DB) UpdateScriptFlags(id int64, allowBatch, sensitive, allowProduction bool) error {
	_, err := db.Exec(`UPDATE scripts SET allow_batch=?, sensitive=?, allow_production=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		boolInt(allowBatch), boolInt(sensitive), boolInt(allowProduction), id)
	return err
}

// UpdateScriptBody replaces editable fields. Callers should bump SHA256 and usually reset status to draft.
func (db *DB) UpdateScriptBody(s *Script) error {
	res, err := db.Exec(`UPDATE scripts SET category=?, params_schema=?, content=?, rollback_content=?,
		healthcheck_content=?, sha256=?, status=?, risk_level=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		s.Category, s.ParamsSchema, s.Content, s.RollbackContent, s.HealthcheckContent, s.SHA256, s.Status, s.RiskLevel, s.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) BumpScriptVersion(id int64, version string) error {
	res, err := db.Exec(`UPDATE scripts SET version=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, version, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SnapshotScriptVersion stores an immutable copy of the current script body.
func (db *DB) SnapshotScriptVersion(s *Script, note, actor string) (int64, error) {
	res, err := db.Exec(`INSERT INTO script_versions(script_id, version, sha256, content, rollback_content,
		healthcheck_content, params_schema, risk_level, status_at_snapshot, note, created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		s.ID, s.Version, s.SHA256, s.Content, s.RollbackContent, s.HealthcheckContent,
		s.ParamsSchema, s.RiskLevel, s.Status, note, actor)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListScriptVersions(scriptID int64) ([]ScriptVersion, error) {
	rows, err := db.Query(`SELECT id, script_id, version, sha256, content, COALESCE(rollback_content,''),
		COALESCE(healthcheck_content,''), COALESCE(params_schema,'[]'), risk_level, status_at_snapshot,
		COALESCE(note,''), COALESCE(created_by,''), created_at
		FROM script_versions WHERE script_id=? ORDER BY id DESC`, scriptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptVersion
	for rows.Next() {
		var v ScriptVersion
		if err := rows.Scan(&v.ID, &v.ScriptID, &v.Version, &v.SHA256, &v.Content, &v.RollbackContent,
			&v.Healthcheck, &v.ParamsSchema, &v.RiskLevel, &v.StatusAtSnapshot, &v.Note, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (db *DB) GetScriptVersion(scriptID, versionID int64) (*ScriptVersion, error) {
	v := &ScriptVersion{}
	err := db.QueryRow(`SELECT id, script_id, version, sha256, content, COALESCE(rollback_content,''),
		COALESCE(healthcheck_content,''), COALESCE(params_schema,'[]'), risk_level, status_at_snapshot,
		COALESCE(note,''), COALESCE(created_by,''), created_at
		FROM script_versions WHERE id=? AND script_id=?`, versionID, scriptID).
		Scan(&v.ID, &v.ScriptID, &v.Version, &v.SHA256, &v.Content, &v.RollbackContent,
			&v.Healthcheck, &v.ParamsSchema, &v.RiskLevel, &v.StatusAtSnapshot, &v.Note, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

func (db *DB) CreateTask(t *Task) error {
	_, err := db.Exec(`INSERT INTO tasks(id, type, status, risk_level, dry_run, concurrency, timeout_sec,
		retry_max, canary_vps_ids, roll_batch, fail_threshold, payload, created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Type, t.Status, t.RiskLevel, boolInt(t.DryRun), t.Concurrency, t.TimeoutSec, t.RetryMax,
		t.CanaryVPSIds, t.RollBatch, t.FailThreshold, t.Payload, t.CreatedBy)
	return err
}

func (db *DB) CreateTaskItem(taskID string, vpsID int64) (int64, error) {
	res, err := db.Exec(`INSERT INTO task_items(task_id, vps_id, status) VALUES(?,?, 'pending')`, taskID, vpsID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) GetTask(id string) (*Task, error) {
	t := &Task{}
	var dry int
	var started, finished sql.NullTime
	err := db.QueryRow(`SELECT id, type, status, risk_level, dry_run, concurrency, timeout_sec, retry_max,
		COALESCE(canary_vps_ids,'[]'), roll_batch, fail_threshold, COALESCE(payload,''), COALESCE(created_by,''),
		created_at, started_at, finished_at FROM tasks WHERE id=?`, id).
		Scan(&t.ID, &t.Type, &t.Status, &t.RiskLevel, &dry, &t.Concurrency, &t.TimeoutSec, &t.RetryMax,
			&t.CanaryVPSIds, &t.RollBatch, &t.FailThreshold, &t.Payload, &t.CreatedBy, &t.CreatedAt, &started, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	t.DryRun = dry == 1
	if started.Valid {
		t.StartedAt = &started.Time
	}
	if finished.Valid {
		t.FinishedAt = &finished.Time
	}
	return t, err
}

func (db *DB) ListTasks(limit int) ([]*Task, error) {
	return db.ListTasksFiltered("", limit, 0)
}

func (db *DB) ListTasksFiltered(status string, limit, offset int) ([]*Task, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT id, type, status, risk_level, dry_run, concurrency, timeout_sec, retry_max,
		COALESCE(canary_vps_ids,'[]'), roll_batch, fail_threshold, COALESCE(payload,''), COALESCE(created_by,''),
		created_at, started_at, finished_at FROM tasks`
	var args []any
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t := &Task{}
		var dry int
		var started, finished sql.NullTime
		if err := rows.Scan(&t.ID, &t.Type, &t.Status, &t.RiskLevel, &dry, &t.Concurrency, &t.TimeoutSec, &t.RetryMax,
			&t.CanaryVPSIds, &t.RollBatch, &t.FailThreshold, &t.Payload, &t.CreatedBy, &t.CreatedAt, &started, &finished); err != nil {
			return nil, err
		}
		t.DryRun = dry == 1
		if started.Valid {
			t.StartedAt = &started.Time
		}
		if finished.Valid {
			t.FinishedAt = &finished.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) UpdateTaskStatus(id, status string) error {
	now := time.Now()
	switch status {
	case "running":
		_, err := db.Exec(`UPDATE tasks SET status=?, started_at=? WHERE id=?`, status, now, id)
		return err
	case "success", "failed", "cancelled", "timeout", "rejected":
		_, err := db.Exec(`UPDATE tasks SET status=?, finished_at=? WHERE id=?`, status, now, id)
		return err
	default:
		_, err := db.Exec(`UPDATE tasks SET status=? WHERE id=?`, status, id)
		return err
	}
}

func (db *DB) ListTaskItems(taskID string) ([]*TaskItem, error) {
	rows, err := db.Query(`SELECT id, task_id, vps_id, status, attempt, COALESCE(log_text,''),
		COALESCE(result,''), COALESCE(error,''), started_at, finished_at FROM task_items WHERE task_id=? ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TaskItem
	for rows.Next() {
		it := &TaskItem{}
		var started, finished sql.NullTime
		if err := rows.Scan(&it.ID, &it.TaskID, &it.VPSID, &it.Status, &it.Attempt, &it.LogText,
			&it.Result, &it.Error, &started, &finished); err != nil {
			return nil, err
		}
		if started.Valid {
			it.StartedAt = &started.Time
		}
		if finished.Valid {
			it.FinishedAt = &finished.Time
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (db *DB) UpdateTaskItem(it *TaskItem) error {
	_, err := db.Exec(`UPDATE task_items SET status=?, attempt=?, log_text=?, result=?, error=?,
		started_at=?, finished_at=? WHERE id=?`,
		it.Status, it.Attempt, it.LogText, it.Result, it.Error, it.StartedAt, it.FinishedAt, it.ID)
	return err
}

func (db *DB) AppendTaskItemLog(id int64, line string) error {
	_, err := db.Exec(`UPDATE task_items SET log_text = COALESCE(log_text,'') || ? WHERE id=?`, line+"\n", id)
	return err
}

func (db *DB) RecoverRunningTasks() error {
	_, err := db.Exec(`UPDATE tasks SET status='pending' WHERE status='running'`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE task_items SET status='pending' WHERE status='running'`)
	return err
}

func (db *DB) ListPendingTasks() ([]*Task, error) {
	rows, err := db.Query(`SELECT id, type, status, risk_level, dry_run, concurrency, timeout_sec, retry_max,
		COALESCE(canary_vps_ids,'[]'), roll_batch, fail_threshold, COALESCE(payload,''), COALESCE(created_by,''),
		created_at, started_at, finished_at FROM tasks WHERE status IN ('pending','running') ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t := &Task{}
		var dry int
		var started, finished sql.NullTime
		if err := rows.Scan(&t.ID, &t.Type, &t.Status, &t.RiskLevel, &dry, &t.Concurrency, &t.TimeoutSec, &t.RetryMax,
			&t.CanaryVPSIds, &t.RollBatch, &t.FailThreshold, &t.Payload, &t.CreatedBy, &t.CreatedAt, &started, &finished); err != nil {
			return nil, err
		}
		t.DryRun = dry == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// ScanResultsKeep is how many newest scan_results rows stay per VPS.
const ScanResultsKeep = 100

func (db *DB) SaveScanResult(vpsID int64, payload string) error {
	_, err := db.Exec(`INSERT INTO scan_results(vps_id, payload) VALUES(?,?)`, vpsID, payload)
	if err != nil {
		return err
	}
	return db.PruneScanResults(vpsID, ScanResultsKeep)
}

// PruneScanResults deletes older scan_results for one VPS, keeping the newest keep rows.
func (db *DB) PruneScanResults(vpsID int64, keep int) error {
	if keep <= 0 {
		keep = ScanResultsKeep
	}
	// Nested SELECT avoids SQLite "same table" DELETE/subquery restrictions.
	_, err := db.Exec(`DELETE FROM scan_results WHERE vps_id=? AND id NOT IN (
		SELECT id FROM (
			SELECT id FROM scan_results WHERE vps_id=? ORDER BY id DESC LIMIT ?
		)
	)`, vpsID, vpsID, keep)
	return err
}

func (db *DB) LatestScan(vpsID int64) (string, error) {
	var p string
	err := db.QueryRow(`SELECT payload FROM scan_results WHERE vps_id=? ORDER BY id DESC LIMIT 1`, vpsID).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return p, err
}

func (db *DB) UpsertServiceInventory(vpsID int64, serviceType, status, version, detail string) error {
	_, err := db.Exec(`INSERT INTO service_inventory(vps_id, service_type, status, version, detail, updated_at)
		VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(vps_id, service_type) DO UPDATE SET status=excluded.status, version=excluded.version,
		detail=excluded.detail, updated_at=CURRENT_TIMESTAMP`, vpsID, serviceType, status, version, detail)
	return err
}

func (db *DB) ListServiceInventory(vpsID int64) ([]ServiceInventory, error) {
	q := `SELECT id, vps_id, service_type, status, COALESCE(version,''), COALESCE(detail,''), updated_at FROM service_inventory`
	var args []any
	if vpsID > 0 {
		q += ` WHERE vps_id=?`
		args = append(args, vpsID)
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceInventory
	for rows.Next() {
		var s ServiceInventory
		if err := rows.Scan(&s.ID, &s.VPSID, &s.ServiceType, &s.Status, &s.Version, &s.Detail, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) SaveSnapshot(vpsID int64, taskID, phase, payload string) error {
	_, err := db.Exec(`INSERT INTO change_snapshots(vps_id, task_id, phase, payload) VALUES(?,?,?,?)`,
		vpsID, nullStr(taskID), phase, payload)
	return err
}

func (db *DB) CreateAlert(kind, severity string, vpsID *int64, message string) error {
	return db.CreateAlertTarget(kind, severity, "vps", vpsID, message)
}

func (db *DB) CreateAlertTarget(kind, severity, targetKind string, targetID *int64, message string) error {
	if targetKind == "" {
		targetKind = "vps"
	}
	_, err := db.Exec(`INSERT INTO alert_events(kind, severity, vps_id, target_kind, message) VALUES(?,?,?,?,?)`,
		kind, severity, targetID, targetKind, message)
	return err
}

func (db *DB) ListAlerts(limit int) ([]AlertEvent, error) {
	return db.ListAlertsFiltered(AlertListFilter{Limit: limit})
}

type AlertListFilter struct {
	UnackedOnly bool
	Limit       int
}

func (db *DB) ListAlertsFiltered(f AlertListFilter) ([]AlertEvent, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	q := `SELECT id, kind, severity, vps_id, COALESCE(target_kind,'vps'), message, acknowledged, created_at
		FROM alert_events WHERE 1=1`
	var args []any
	if f.UnackedOnly {
		q += ` AND acknowledged=0`
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertEvent
	for rows.Next() {
		var a AlertEvent
		var vpsID sql.NullInt64
		var ack int
		if err := rows.Scan(&a.ID, &a.Kind, &a.Severity, &vpsID, &a.TargetKind, &a.Message, &ack, &a.CreatedAt); err != nil {
			return nil, err
		}
		if vpsID.Valid {
			id := vpsID.Int64
			a.VPSID = &id
		}
		a.Acknowledged = ack == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

func (db *DB) HasRecentAlert(vpsID int64, kind string, within time.Duration) (bool, error) {
	return db.HasRecentAlertTarget(vpsID, "vps", kind, within)
}

func (db *DB) HasRecentAlertTarget(targetID int64, targetKind, kind string, within time.Duration) (bool, error) {
	if targetKind == "" {
		targetKind = "vps"
	}
	hours := int(within.Hours())
	if hours < 1 {
		hours = 1
	}
	ago := fmt.Sprintf("-%d hours", hours)
	var n int
	var err error
	if targetID > 0 {
		err = db.QueryRow(`SELECT COUNT(1) FROM alert_events WHERE kind=? AND vps_id=? AND COALESCE(target_kind,'vps')=? AND created_at > datetime('now', ?)`,
			kind, targetID, targetKind, ago).Scan(&n)
	} else {
		err = db.QueryRow(`SELECT COUNT(1) FROM alert_events WHERE kind=? AND vps_id IS NULL AND COALESCE(target_kind,'vps')=? AND created_at > datetime('now', ?)`,
			kind, targetKind, ago).Scan(&n)
	}
	return n > 0, err
}

func (db *DB) AckAlert(id int64) error {
	res, err := db.Exec(`UPDATE alert_events SET acknowledged=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) AckAllAlerts() (int64, error) {
	res, err := db.Exec(`UPDATE alert_events SET acknowledged=1 WHERE COALESCE(acknowledged,0)=0`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (db *DB) ScriptNameExists(name string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM scripts WHERE name=?`, name).Scan(&n)
	return n > 0, err
}

func (db *DB) GetBackup(id int64) (*Backup, error) {
	var b Backup
	var vpsID sql.NullInt64
	var enc int
	err := db.QueryRow(`SELECT id, kind, vps_id, name, storage, path, COALESCE(sha256,''), encrypted, created_at FROM backups WHERE id=?`, id).
		Scan(&b.ID, &b.Kind, &vpsID, &b.Name, &b.Storage, &b.Path, &b.SHA256, &enc, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if vpsID.Valid {
		id := vpsID.Int64
		b.VPSID = &id
	}
	b.Encrypted = enc == 1
	return &b, nil
}

func (db *DB) DeleteBackup(id int64) error {
	_, err := db.Exec(`DELETE FROM backups WHERE id=?`, id)
	return err
}

func (db *DB) CreateBackup(b *Backup) (int64, error) {
	res, err := db.Exec(`INSERT INTO backups(kind, vps_id, name, storage, path, sha256, encrypted) VALUES(?,?,?,?,?,?,?)`,
		b.Kind, b.VPSID, b.Name, b.Storage, b.Path, b.SHA256, boolInt(b.Encrypted))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListBackups() ([]Backup, error) {
	rows, err := db.Query(`SELECT id, kind, vps_id, name, storage, path, COALESCE(sha256,''), encrypted, created_at FROM backups ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		var b Backup
		var vpsID sql.NullInt64
		var enc int
		if err := rows.Scan(&b.ID, &b.Kind, &vpsID, &b.Name, &b.Storage, &b.Path, &b.SHA256, &enc, &b.CreatedAt); err != nil {
			return nil, err
		}
		if vpsID.Valid {
			id := vpsID.Int64
			b.VPSID = &id
		}
		b.Encrypted = enc == 1
		out = append(out, b)
	}
	return out, rows.Err()
}

func (db *DB) CreateAPIToken(name, tokenHash, scopes string, expires *time.Time) (int64, error) {
	res, err := db.Exec(`INSERT INTO api_tokens(name, token_hash, scopes, expires_at) VALUES(?,?,?,?)`,
		name, tokenHash, scopes, expires)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) GetAPITokenByHash(hash string) (*APIToken, error) {
	t := &APIToken{}
	var exp, rev sql.NullTime
	err := db.QueryRow(`SELECT id, name, token_hash, COALESCE(scopes,'[]'), expires_at, revoked_at, created_at
		FROM api_tokens WHERE token_hash=?`, hash).
		Scan(&t.ID, &t.Name, &t.TokenHash, &t.Scopes, &exp, &rev, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if exp.Valid {
		t.ExpiresAt = &exp.Time
	}
	if rev.Valid {
		t.RevokedAt = &rev.Time
	}
	return t, err
}

func (db *DB) ListAPITokens() ([]APIToken, error) {
	rows, err := db.Query(`SELECT id, name, token_hash, COALESCE(scopes,'[]'), expires_at, revoked_at, created_at FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var exp, rev sql.NullTime
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenHash, &t.Scopes, &exp, &rev, &t.CreatedAt); err != nil {
			return nil, err
		}
		if exp.Valid {
			t.ExpiresAt = &exp.Time
		}
		if rev.Valid {
			t.RevokedAt = &rev.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) RevokeAPIToken(id int64) error {
	_, err := db.Exec(`UPDATE api_tokens SET revoked_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	return err
}
