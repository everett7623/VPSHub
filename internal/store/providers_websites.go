package store

import (
	"database/sql"
	"errors"
	"time"
)

type Provider struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Website         string    `json:"website,omitempty"`
	Contact         string    `json:"contact,omitempty"`
	PrivateNotesEnc []byte    `json:"-"`
	HasPrivateNotes bool      `json:"has_private_notes"`
	Notes           string    `json:"notes,omitempty"`
	ServerCount     int       `json:"server_count,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Website struct {
	ID                 int64      `json:"id"`
	Name               string     `json:"name"`
	Domain             string     `json:"domain"`
	SiteType           string     `json:"site_type"`
	VPSID              *int64     `json:"vps_id,omitempty"`
	VPSName            string     `json:"vps_name,omitempty"`
	PanelType          string     `json:"panel_type"`
	PanelURL           string     `json:"panel_url,omitempty"`
	PanelUsername      string     `json:"panel_username,omitempty"`
	PanelPasswordEnc   []byte     `json:"-"`
	HasPanelPassword   bool       `json:"has_panel_password"`
	ExpiryDate         *string    `json:"expiry_date,omitempty"`
	Status             string     `json:"status"`
	HTTPProbeEnabled   bool       `json:"http_probe_enabled"`
	HTTPProbeURL       string     `json:"http_probe_url,omitempty"`
	HTTPProbeHealthy   *bool      `json:"http_probe_healthy,omitempty"`
	HTTPProbeLastAt    *time.Time `json:"http_probe_last_at,omitempty"`
	HTTPProbeLastError string     `json:"http_probe_last_error,omitempty"`
	Notes              string     `json:"notes,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type AlertRule struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`
	Enabled        bool      `json:"enabled"`
	Threshold      *float64  `json:"threshold,omitempty"`
	DaysBefore     int       `json:"days_before"`
	NotifyChannels string    `json:"notify_channels"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type DashboardStats struct {
	TotalVPS             int `json:"total_vps"`
	OnlineCount          int `json:"online_count"`
	OfflineCount         int `json:"offline_count"`
	ExpiringCount        int `json:"expiring_count"`
	OverdueCount         int `json:"overdue_count"`
	VPSExpiringCount     int `json:"vps_expiring_count"`
	WebsiteExpiringCount int `json:"website_expiring_count"`
	VPSOverdueCount      int `json:"vps_overdue_count"`
	WebsiteOverdueCount  int `json:"website_overdue_count"`
	TotalWebsites        int `json:"total_websites"`
	RecentAlerts         int `json:"recent_alerts"`
	ProbeUnhealthy       int `json:"probe_unhealthy"`
	TotalProviders       int `json:"total_providers"`
	WaitingApproval      int `json:"waiting_approval"`
	HostKeyPendingCount  int `json:"host_key_pending_count"`
	StaleScanCount       int `json:"stale_scan_count"`
}

type ExpiringItem struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"` // vps | website
	Name        string `json:"name"`
	ExpiryDate  string `json:"expiry_date"`
	DaysLeft    int    `json:"days_left"`
	AutoRenewal bool   `json:"auto_renewal,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

func (db *DB) CreateProvider(p *Provider) (int64, error) {
	res, err := db.Exec(`INSERT INTO providers(name, website, contact, private_notes_enc, notes) VALUES(?,?,?,?,?)`,
		p.Name, nullStr(p.Website), nullStr(p.Contact), p.PrivateNotesEnc, nullStr(p.Notes))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListProviders() ([]Provider, error) {
	rows, err := db.Query(`SELECT p.id, p.name, COALESCE(p.website,''), COALESCE(p.contact,''), p.private_notes_enc,
		COALESCE(p.notes,''), p.created_at, p.updated_at,
		(SELECT COUNT(1) FROM vps v WHERE v.provider_id=p.id AND v.deleted_at IS NULL)
		FROM providers p ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		var enc []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Website, &p.Contact, &enc, &p.Notes, &p.CreatedAt, &p.UpdatedAt, &p.ServerCount); err != nil {
			return nil, err
		}
		p.PrivateNotesEnc = enc
		p.HasPrivateNotes = len(enc) > 0
		out = append(out, p)
	}
	return out, rows.Err()
}

func (db *DB) GetProvider(id int64) (*Provider, error) {
	p := &Provider{}
	var enc []byte
	err := db.QueryRow(`SELECT id, name, COALESCE(website,''), COALESCE(contact,''), private_notes_enc,
		COALESCE(notes,''), created_at, updated_at FROM providers WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Website, &p.Contact, &enc, &p.Notes, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	p.PrivateNotesEnc = enc
	p.HasPrivateNotes = len(enc) > 0
	return p, err
}

func (db *DB) UpdateProvider(p *Provider) error {
	_, err := db.Exec(`UPDATE providers SET name=?, website=?, contact=?, private_notes_enc=?, notes=?,
		updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		p.Name, nullStr(p.Website), nullStr(p.Contact), p.PrivateNotesEnc, nullStr(p.Notes), p.ID)
	return err
}

func (db *DB) DeleteProvider(id int64) error {
	_, err := db.Exec(`DELETE FROM providers WHERE id=?`, id)
	return err
}

func (db *DB) CreateWebsite(w *Website) (int64, error) {
	res, err := db.Exec(`INSERT INTO websites(name, domain, site_type, vps_id, panel_type, panel_url, panel_username,
		panel_password_enc, expiry_date, status, http_probe_enabled, http_probe_url, notes)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		w.Name, w.Domain, w.SiteType, w.VPSID, w.PanelType, nullStr(w.PanelURL), nullStr(w.PanelUsername),
		w.PanelPasswordEnc, w.ExpiryDate, w.Status, boolInt(w.HTTPProbeEnabled), nullStr(w.HTTPProbeURL), nullStr(w.Notes))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListWebsites() ([]Website, error) {
	rows, err := db.Query(`SELECT w.id, w.name, w.domain, COALESCE(w.site_type,'other'), w.vps_id, COALESCE(v.name,''),
		COALESCE(w.panel_type,'none'), COALESCE(w.panel_url,''), COALESCE(w.panel_username,''), w.panel_password_enc,
		w.expiry_date, w.status, w.http_probe_enabled, COALESCE(w.http_probe_url,''), w.http_probe_healthy, w.http_probe_last_at,
		COALESCE(w.http_probe_last_error,''), COALESCE(w.notes,''), w.created_at, w.updated_at
		FROM websites w LEFT JOIN vps v ON v.id=w.vps_id ORDER BY w.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Website
	for rows.Next() {
		w, err := scanWebsite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

func scanWebsite(row interface{ Scan(...any) error }) (*Website, error) {
	w := &Website{}
	var vpsID sql.NullInt64
	var exp sql.NullString
	var healthy sql.NullInt64
	var lastAt sql.NullTime
	var enc []byte
	var probeEn int
	err := row.Scan(&w.ID, &w.Name, &w.Domain, &w.SiteType, &vpsID, &w.VPSName, &w.PanelType, &w.PanelURL,
		&w.PanelUsername, &enc, &exp, &w.Status, &probeEn, &w.HTTPProbeURL, &healthy, &lastAt, &w.HTTPProbeLastError, &w.Notes,
		&w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if vpsID.Valid {
		id := vpsID.Int64
		w.VPSID = &id
	}
	if exp.Valid {
		s := exp.String
		w.ExpiryDate = &s
	}
	w.PanelPasswordEnc = enc
	w.HasPanelPassword = len(enc) > 0
	w.HTTPProbeEnabled = probeEn == 1
	if healthy.Valid {
		b := healthy.Int64 == 1
		w.HTTPProbeHealthy = &b
	}
	if lastAt.Valid {
		t := lastAt.Time
		w.HTTPProbeLastAt = &t
	}
	return w, nil
}

func (db *DB) GetWebsite(id int64) (*Website, error) {
	row := db.QueryRow(`SELECT w.id, w.name, w.domain, COALESCE(w.site_type,'other'), w.vps_id, COALESCE(v.name,''),
		COALESCE(w.panel_type,'none'), COALESCE(w.panel_url,''), COALESCE(w.panel_username,''), w.panel_password_enc,
		w.expiry_date, w.status, w.http_probe_enabled, COALESCE(w.http_probe_url,''), w.http_probe_healthy, w.http_probe_last_at,
		COALESCE(w.http_probe_last_error,''), COALESCE(w.notes,''), w.created_at, w.updated_at
		FROM websites w LEFT JOIN vps v ON v.id=w.vps_id WHERE w.id=?`, id)
	w, err := scanWebsite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return w, err
}

func (db *DB) UpdateWebsite(w *Website) error {
	_, err := db.Exec(`UPDATE websites SET name=?, domain=?, site_type=?, vps_id=?, panel_type=?, panel_url=?,
		panel_username=?, panel_password_enc=?, expiry_date=?, status=?, http_probe_enabled=?, http_probe_url=?, notes=?,
		updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		w.Name, w.Domain, w.SiteType, w.VPSID, w.PanelType, nullStr(w.PanelURL), nullStr(w.PanelUsername),
		w.PanelPasswordEnc, w.ExpiryDate, w.Status, boolInt(w.HTTPProbeEnabled), nullStr(w.HTTPProbeURL), nullStr(w.Notes), w.ID)
	return err
}

func (db *DB) DeleteWebsite(id int64) error {
	_, err := db.Exec(`DELETE FROM websites WHERE id=?`, id)
	return err
}

func (db *DB) UpdateWebsiteProbe(id int64, healthy bool, errMsg string) error {
	h := 0
	if healthy {
		h = 1
	}
	_, err := db.Exec(`UPDATE websites SET http_probe_healthy=?, http_probe_last_at=CURRENT_TIMESTAMP,
		http_probe_last_error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, h, errMsg, id)
	return err
}

func (db *DB) ListProbeWebsites() ([]Website, error) {
	rows, err := db.Query(`SELECT w.id, w.name, w.domain, COALESCE(w.site_type,'other'), w.vps_id, COALESCE(v.name,''),
		COALESCE(w.panel_type,'none'), COALESCE(w.panel_url,''), COALESCE(w.panel_username,''), w.panel_password_enc,
		w.expiry_date, w.status, w.http_probe_enabled, COALESCE(w.http_probe_url,''), w.http_probe_healthy, w.http_probe_last_at,
		COALESCE(w.http_probe_last_error,''), COALESCE(w.notes,''), w.created_at, w.updated_at
		FROM websites w LEFT JOIN vps v ON v.id=w.vps_id WHERE w.http_probe_enabled=1 AND w.status='active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Website
	for rows.Next() {
		w, err := scanWebsite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

func (db *DB) UpdateVPSProbe(id int64, healthy bool, errMsg string) error {
	h := 0
	if healthy {
		h = 1
	}
	_, err := db.Exec(`UPDATE vps SET http_probe_healthy=?, http_probe_last_at=CURRENT_TIMESTAMP,
		http_probe_last_error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, h, errMsg, id)
	return err
}

func (db *DB) UpdateVPSTCP(id int64, reachable bool) error {
	r := 0
	if reachable {
		r = 1
	}
	_, err := db.Exec(`UPDATE vps SET tcp_reachable=?, tcp_checked_at=CURRENT_TIMESTAMP WHERE id=?`, r, id)
	return err
}

func (db *DB) ListProbeVPS() ([]*VPS, error) {
	rows, err := db.Query(`SELECT id, name, host, ssh_port, COALESCE(http_probe_url,'') FROM vps
		WHERE deleted_at IS NULL AND http_probe_enabled=1`)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []*VPS
	for rows.Next() {
		v := &VPS{}
		if err := rows.Scan(&v.ID, &v.Name, &v.Host, &v.SSHPort, &v.HTTPProbeURL); err != nil {
			return nil, err
		}
		v.HTTPProbeEnabled = true
		out = append(out, v)
	}
	return out, rows.Err()
}

func (db *DB) CreateAlertRule(r *AlertRule) (int64, error) {
	res, err := db.Exec(`INSERT INTO alert_rules(name, kind, enabled, threshold, days_before, notify_channels)
		VALUES(?,?,?,?,?,?)`, r.Name, r.Kind, boolInt(r.Enabled), r.Threshold, r.DaysBefore, r.NotifyChannels)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListAlertRules() ([]AlertRule, error) {
	rows, err := db.Query(`SELECT id, name, kind, enabled, threshold, days_before, COALESCE(notify_channels,'[]'),
		created_at, updated_at FROM alert_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var en int
		var th sql.NullFloat64
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &en, &th, &r.DaysBefore, &r.NotifyChannels, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		if th.Valid {
			v := th.Float64
			r.Threshold = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) UpdateAlertRule(r *AlertRule) error {
	_, err := db.Exec(`UPDATE alert_rules SET name=?, kind=?, enabled=?, threshold=?, days_before=?,
		notify_channels=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		r.Name, r.Kind, boolInt(r.Enabled), r.Threshold, r.DaysBefore, r.NotifyChannels, r.ID)
	return err
}

func (db *DB) DeleteAlertRule(id int64) error {
	_, err := db.Exec(`DELETE FROM alert_rules WHERE id=?`, id)
	return err
}

func (db *DB) DashboardStats() (*DashboardStats, error) {
	s := &DashboardStats{}
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL`).Scan(&s.TotalVPS)
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL AND status='online'`).Scan(&s.OnlineCount)
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL AND status='offline'`).Scan(&s.OfflineCount)
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL AND expires_at IS NOT NULL
		AND expires_at <= date('now','+30 days') AND expires_at >= date('now')`).Scan(&s.VPSExpiringCount)
	_ = db.QueryRow(`SELECT COUNT(1) FROM websites WHERE expiry_date IS NOT NULL AND status='active'
		AND expiry_date <= date('now','+30 days') AND expiry_date >= date('now')`).Scan(&s.WebsiteExpiringCount)
	s.ExpiringCount = s.VPSExpiringCount + s.WebsiteExpiringCount
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at < date('now')`).Scan(&s.VPSOverdueCount)
	_ = db.QueryRow(`SELECT COUNT(1) FROM websites WHERE expiry_date IS NOT NULL AND status='active' AND expiry_date < date('now')`).Scan(&s.WebsiteOverdueCount)
	s.OverdueCount = s.VPSOverdueCount + s.WebsiteOverdueCount
	_ = db.QueryRow(`SELECT COUNT(1) FROM websites`).Scan(&s.TotalWebsites)
	_ = db.QueryRow(`SELECT COUNT(1) FROM alert_events WHERE acknowledged=0 AND created_at > datetime('now','-7 days')`).Scan(&s.RecentAlerts)
	_ = db.QueryRow(`SELECT COUNT(1) FROM websites WHERE http_probe_enabled=1 AND http_probe_healthy=0`).Scan(&s.ProbeUnhealthy)
	_ = db.QueryRow(`SELECT COUNT(1) FROM providers`).Scan(&s.TotalProviders)
	_ = db.QueryRow(`SELECT COUNT(1) FROM tasks WHERE status='waiting_approval'`).Scan(&s.WaitingApproval)
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL AND host_key_pending IS NOT NULL AND host_key_pending != ''`).Scan(&s.HostKeyPendingCount)
	_ = db.QueryRow(`SELECT COUNT(1) FROM vps WHERE deleted_at IS NULL AND (last_scan_at IS NULL OR last_scan_at < datetime('now','-7 days'))`).Scan(&s.StaleScanCount)
	return s, nil
}

func (db *DB) ListExpiring(days int) ([]ExpiringItem, error) {
	if days <= 0 {
		days = 30
	}
	var out []ExpiringItem
	rows, err := db.Query(`SELECT id, name, expires_at, COALESCE(auto_renewal,0),
		CAST(julianday(expires_at) - julianday(date('now')) AS INTEGER)
		FROM vps WHERE deleted_at IS NULL AND expires_at IS NOT NULL
		AND expires_at <= date('now', ?) ORDER BY expires_at ASC LIMIT 20`, "+"+itoa(days)+" days")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it ExpiringItem
			var auto int
			var exp string
			if err := rows.Scan(&it.ID, &it.Name, &exp, &auto, &it.DaysLeft); err != nil {
				return nil, err
			}
			it.Kind = "vps"
			it.ExpiryDate = exp
			it.AutoRenewal = auto == 1
			out = append(out, it)
		}
	}
	rows2, err := db.Query(`SELECT id, name, domain, expiry_date,
		CAST(julianday(expiry_date) - julianday(date('now')) AS INTEGER)
		FROM websites WHERE status='active' AND expiry_date IS NOT NULL
		AND expiry_date <= date('now', ?) ORDER BY expiry_date ASC LIMIT 20`, "+"+itoa(days)+" days")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var it ExpiringItem
			var domain, exp string
			if err := rows2.Scan(&it.ID, &it.Name, &domain, &exp, &it.DaysLeft); err != nil {
				return nil, err
			}
			it.Kind = "website"
			it.ExpiryDate = exp
			it.Detail = domain
			out = append(out, it)
		}
	}
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (db *DB) AdvanceAutoRenewals() (int, error) {
	res, err := db.Exec(`UPDATE vps SET expires_at = date(expires_at,
		CASE renewal_cycle
			WHEN 'quarterly' THEN '+3 months'
			WHEN 'yearly' THEN '+1 year'
			WHEN '2year' THEN '+2 years'
			WHEN '3year' THEN '+3 years'
			ELSE '+1 month'
		END), updated_at=CURRENT_TIMESTAMP
		WHERE deleted_at IS NULL AND auto_renewal=1 AND expires_at IS NOT NULL AND expires_at < date('now')`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) CreateViewToken(token string, adminID int64, ip string, expires time.Time) error {
	_, err := db.Exec(`INSERT INTO view_tokens(token, admin_id, ip, expires_at) VALUES(?,?,?,?)`, token, adminID, ip, expires)
	return err
}

// ConsumeViewToken validates a view token within its TTL (reusable until expiry).
// The name is historical; tokens are session-scoped for 2 minutes, not single-use.
func (db *DB) ConsumeViewToken(token, ip string, adminID int64) (bool, error) {
	var id int64
	err := db.QueryRow(`SELECT id FROM view_tokens WHERE token=? AND used=0 AND admin_id=? AND ip=? AND expires_at > CURRENT_TIMESTAMP`,
		token, adminID, ip).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return id > 0, nil
}

func (db *DB) ClearViewTokens() error {
	_, err := db.Exec(`DELETE FROM view_tokens`)
	return err
}

func (db *DB) ClearAllCredentialCiphertexts() error {
	_, err := db.Exec(`DELETE FROM credentials`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE websites SET panel_password_enc=NULL`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE vps SET panel_password_enc=NULL`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE providers SET private_notes_enc=NULL`)
	return err
}
