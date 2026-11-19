package store

import (
	"database/sql"
	"time"
)

type ServiceTemplate struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	ServiceType  string `json:"service_type"`
	ConfigPaths  string `json:"config_paths"`
	Healthcheck  string `json:"healthcheck"`
	Dependencies string `json:"dependencies"`
	RiskLevel    string `json:"risk_level"`
	Meta         string `json:"meta"`
	UsageCount   int    `json:"usage_count,omitempty"`
}

type TemplateVPSRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type ScanRecord struct {
	ID        int64     `json:"id"`
	VPSID     int64     `json:"vps_id"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

type ChangeSnapshot struct {
	ID        int64     `json:"id"`
	VPSID     int64     `json:"vps_id"`
	TaskID    string    `json:"task_id,omitempty"`
	Phase     string    `json:"phase"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

func (db *DB) ListTemplates() ([]ServiceTemplate, error) {
	rows, err := db.Query(`SELECT t.id, t.name, t.service_type, COALESCE(t.config_paths,'[]'), COALESCE(t.healthcheck,''),
		COALESCE(t.dependencies,'[]'), t.risk_level, COALESCE(t.meta,'{}'),
		(SELECT COUNT(DISTINCT e.vps_id) FROM vps_expectations e
			JOIN vps v ON v.id=e.vps_id AND v.deleted_at IS NULL
			WHERE e.template_id=t.id)
		FROM service_templates t ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceTemplate
	for rows.Next() {
		var t ServiceTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.ServiceType, &t.ConfigPaths, &t.Healthcheck, &t.Dependencies, &t.RiskLevel, &t.Meta, &t.UsageCount); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) ListTemplateVPS(templateID int64) ([]TemplateVPSRef, error) {
	rows, err := db.Query(`SELECT v.id, v.name FROM vps v
		JOIN vps_expectations e ON e.vps_id=v.id
		WHERE e.template_id=? AND v.deleted_at IS NULL ORDER BY v.name`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TemplateVPSRef
	for rows.Next() {
		var r TemplateVPSRef
		if err := rows.Scan(&r.ID, &r.Name); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) CreateTemplate(t *ServiceTemplate) (int64, error) {
	if t.ConfigPaths == "" {
		t.ConfigPaths = "[]"
	}
	if t.Dependencies == "" {
		t.Dependencies = "[]"
	}
	if t.RiskLevel == "" {
		t.RiskLevel = "medium"
	}
	if t.Meta == "" {
		t.Meta = "{}"
	}
	res, err := db.Exec(`INSERT INTO service_templates(name, service_type, config_paths, healthcheck, dependencies, risk_level, meta)
		VALUES(?,?,?,?,?,?,?)`, t.Name, t.ServiceType, t.ConfigPaths, t.Healthcheck, t.Dependencies, t.RiskLevel, t.Meta)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) UpdateTemplate(t *ServiceTemplate) error {
	if t.ConfigPaths == "" {
		t.ConfigPaths = "[]"
	}
	if t.Dependencies == "" {
		t.Dependencies = "[]"
	}
	if t.RiskLevel == "" {
		t.RiskLevel = "medium"
	}
	res, err := db.Exec(`UPDATE service_templates SET name=?, service_type=?, config_paths=?, healthcheck=?,
		dependencies=?, risk_level=? WHERE id=?`,
		t.Name, t.ServiceType, t.ConfigPaths, t.Healthcheck, t.Dependencies, t.RiskLevel, t.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) DeleteTemplate(id int64) error {
	res, err := db.Exec(`DELETE FROM service_templates WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) SetExpectations(vpsID int64, templateIDs []int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM vps_expectations WHERE vps_id=?`, vpsID); err != nil {
		return err
	}
	for _, id := range templateIDs {
		if _, err := tx.Exec(`INSERT INTO vps_expectations(vps_id, template_id) VALUES(?,?)`, vpsID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListExpectationTemplates(vpsID int64) ([]ServiceTemplate, error) {
	rows, err := db.Query(`SELECT t.id, t.name, t.service_type, COALESCE(t.config_paths,'[]'), COALESCE(t.healthcheck,''),
		COALESCE(t.dependencies,'[]'), t.risk_level, COALESCE(t.meta,'{}')
		FROM service_templates t
		JOIN vps_expectations e ON e.template_id = t.id
		WHERE e.vps_id=? ORDER BY t.name`, vpsID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceTemplate
	for rows.Next() {
		var t ServiceTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.ServiceType, &t.ConfigPaths, &t.Healthcheck, &t.Dependencies, &t.RiskLevel, &t.Meta); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) ListScans(vpsID int64, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 2
	}
	rows, err := db.Query(`SELECT id, vps_id, payload, created_at FROM scan_results WHERE vps_id=? ORDER BY id DESC LIMIT ?`, vpsID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

func (db *DB) ListSnapshots(vpsID int64, limit int) ([]ChangeSnapshot, error) {
	if limit <= 0 {
		limit = 4
	}
	rows, err := db.Query(`SELECT id, vps_id, COALESCE(task_id,''), phase, payload, created_at
		FROM change_snapshots WHERE vps_id=? ORDER BY id DESC LIMIT ?`, vpsID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeSnapshot
	for rows.Next() {
		var s ChangeSnapshot
		if err := rows.Scan(&s.ID, &s.VPSID, &s.TaskID, &s.Phase, &s.Payload, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanRecords(rows *sql.Rows) ([]ScanRecord, error) {
	var out []ScanRecord
	for rows.Next() {
		var s ScanRecord
		if err := rows.Scan(&s.ID, &s.VPSID, &s.Payload, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
