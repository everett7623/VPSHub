package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func scanVPS(row interface {
	Scan(dest ...any) error
}) (*VPS, error) {
	v := &VPS{}
	var jump, providerID sql.NullInt64
	var ipv4, ipv6, provider, providerName, region, expires, groupName, notes, hkfp, hkpend sql.NullString
	var serverType, panelType, panelURL, panelUser, purchase, renewal, currency, probeURL, probeErr, bandwidth, sftpRoot, socks sql.NullString
	var cost, purchasePrice, cpu, ram, disk sql.NullFloat64
	var autoRenew, probeEn, probeHealthy, tcpOK sql.NullInt64
	var lastConn, lastScan, probeAt, tcpAt, deleted sql.NullTime
	err := row.Scan(
		&v.ID, &v.Name, &v.Host, &ipv4, &ipv6, &v.SSHPort, &v.SSHUser, &v.AuthMethod, &jump,
		&provider, &providerID, &providerName, &region, &expires, &cost, &groupName, &v.Tags, &v.Environment, &v.OpMode, &notes,
		&hkfp, &hkpend, &v.Status, &lastConn, &lastScan, &v.MaintenanceWins,
		&serverType, &panelType, &panelURL, &panelUser, &purchase, &renewal, &autoRenew, &currency, &purchasePrice,
		&probeEn, &probeURL, &probeHealthy, &probeAt, &probeErr, &tcpOK, &tcpAt, &bandwidth, &cpu, &ram, &disk, &sftpRoot, &socks,
		&deleted, &v.CreatedAt, &v.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	v.IPv4, v.IPv6 = ipv4.String, ipv6.String
	v.Provider, v.ProviderName, v.Region = provider.String, providerName.String, region.String
	if expires.Valid {
		s := expires.String
		v.ExpiresAt = &s
	}
	if cost.Valid {
		c := cost.Float64
		v.MonthlyCost = &c
	}
	v.GroupName, v.Notes = groupName.String, notes.String
	v.HostKeyFP, v.HostKeyPending = hkfp.String, hkpend.String
	if jump.Valid {
		j := jump.Int64
		v.JumpHostID = &j
	}
	if providerID.Valid {
		id := providerID.Int64
		v.ProviderID = &id
	}
	if lastConn.Valid {
		t := lastConn.Time
		v.LastConnectAt = &t
	}
	if lastScan.Valid {
		t := lastScan.Time
		v.LastScanAt = &t
	}
	v.ServerType = serverType.String
	v.PanelType = panelType.String
	v.PanelURL = panelURL.String
	v.PanelUsername = panelUser.String
	if purchase.Valid {
		s := purchase.String
		v.PurchaseDate = &s
	}
	v.RenewalCycle = renewal.String
	v.AutoRenewal = autoRenew.Int64 == 1
	v.Currency = currency.String
	if purchasePrice.Valid {
		p := purchasePrice.Float64
		v.PurchasePrice = &p
	}
	v.HTTPProbeEnabled = probeEn.Int64 == 1
	v.HTTPProbeURL = probeURL.String
	if probeHealthy.Valid {
		b := probeHealthy.Int64 == 1
		v.HTTPProbeHealthy = &b
	}
	if probeAt.Valid {
		t := probeAt.Time
		v.HTTPProbeLastAt = &t
	}
	v.HTTPProbeError = probeErr.String
	if tcpOK.Valid {
		b := tcpOK.Int64 == 1
		v.TCPReachable = &b
	}
	if tcpAt.Valid {
		t := tcpAt.Time
		v.TCPCheckedAt = &t
	}
	v.Bandwidth = bandwidth.String
	if cpu.Valid {
		n := cpu.Float64
		v.CPUCores = &n
	}
	if ram.Valid {
		n := ram.Float64
		v.RAMGB = &n
	}
	if disk.Valid {
		n := disk.Float64
		v.DiskGB = &n
	}
	v.SFTPRoot = sftpRoot.String
	v.SocksProxy = socks.String
	if deleted.Valid {
		t := deleted.Time
		v.DeletedAt = &t
	}
	return v, nil
}

const vpsCols = `id, name, host, ipv4, ipv6, ssh_port, ssh_user, auth_method, jump_host_id,
	provider, provider_id, (SELECT name FROM providers WHERE id=vps.provider_id), region, expires_at, monthly_cost, group_name, COALESCE(tags,'[]'), environment, op_mode, notes,
	host_key_fp, host_key_pending, status, last_connect_at, last_scan_at, COALESCE(maintenance_windows,'[]'),
	COALESCE(server_type,'vps'), COALESCE(panel_type,'none'), panel_url, panel_username,
	purchase_date, COALESCE(renewal_cycle,'monthly'), COALESCE(auto_renewal,0), COALESCE(currency,'USD'), purchase_price,
	COALESCE(http_probe_enabled,0), http_probe_url, http_probe_healthy, http_probe_last_at, http_probe_last_error,
	tcp_reachable, tcp_checked_at, bandwidth, cpu_cores, ram_gb, disk_gb, COALESCE(sftp_root,''), COALESCE(socks_proxy,''),
	deleted_at, created_at, updated_at`

func (db *DB) CreateVPS(v *VPS) (int64, error) {
	if v.Tags == "" {
		v.Tags = "[]"
	}
	if v.MaintenanceWins == "" {
		v.MaintenanceWins = "[]"
	}
	if v.SSHPort == 0 {
		v.SSHPort = 22
	}
	if v.AuthMethod == "" {
		v.AuthMethod = "password"
	}
	if v.Environment == "" {
		v.Environment = "production"
	}
	if v.OpMode == "" {
		v.OpMode = "normal_tasks"
	}
	if v.Status == "" {
		v.Status = "unknown"
	}
	if v.ServerType == "" {
		v.ServerType = "vps"
	}
	if v.RenewalCycle == "" {
		v.RenewalCycle = "monthly"
	}
	if v.Currency == "" {
		v.Currency = "USD"
	}
	auto := 0
	if v.AutoRenewal {
		auto = 1
	}
	probe := 0
	if v.HTTPProbeEnabled {
		probe = 1
	}
	res, err := db.Exec(`INSERT INTO vps(name, host, ipv4, ipv6, ssh_port, ssh_user, auth_method, jump_host_id,
		provider, provider_id, region, expires_at, monthly_cost, group_name, tags, environment, op_mode, notes,
		host_key_fp, status, maintenance_windows,
		server_type, panel_type, panel_url, panel_username, purchase_date, renewal_cycle, auto_renewal, currency, purchase_price,
		http_probe_enabled, http_probe_url, bandwidth, cpu_cores, ram_gb, disk_gb, sftp_root, socks_proxy)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.Name, v.Host, nullStr(v.IPv4), nullStr(v.IPv6), v.SSHPort, v.SSHUser, v.AuthMethod, v.JumpHostID,
		nullStr(v.Provider), v.ProviderID, nullStr(v.Region), v.ExpiresAt, v.MonthlyCost, nullStr(v.GroupName), v.Tags,
		v.Environment, v.OpMode, nullStr(v.Notes), nullStr(v.HostKeyFP), v.Status, v.MaintenanceWins,
		v.ServerType, nullStr(v.PanelType), nullStr(v.PanelURL), nullStr(v.PanelUsername), v.PurchaseDate, v.RenewalCycle, auto, v.Currency, v.PurchasePrice,
		probe, nullStr(v.HTTPProbeURL), nullStr(v.Bandwidth), v.CPUCores, v.RAMGB, v.DiskGB, nullStr(v.SFTPRoot), nullStr(v.SocksProxy))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (db *DB) GetVPS(id int64) (*VPS, error) {
	row := db.QueryRow(`SELECT `+vpsCols+` FROM vps WHERE id=? AND deleted_at IS NULL`, id)
	v, err := scanVPS(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

func (db *DB) GetVPSIncludeDeleted(id int64) (*VPS, error) {
	row := db.QueryRow(`SELECT `+vpsCols+` FROM vps WHERE id=?`, id)
	v, err := scanVPS(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

type VPSFilter struct {
	Q           string
	Group       string
	Environment string
	Tag         string
	Status      string
	ProviderID  int64
	IncludeDel  bool
}

func (db *DB) ListVPS(f VPSFilter) ([]*VPS, error) {
	var where []string
	var args []any
	if !f.IncludeDel {
		where = append(where, "deleted_at IS NULL")
	}
	if f.Q != "" {
		where = append(where, "(name LIKE ? OR host LIKE ? OR provider LIKE ? OR notes LIKE ?)")
		q := "%" + f.Q + "%"
		args = append(args, q, q, q, q)
	}
	if f.Group != "" {
		where = append(where, "group_name=?")
		args = append(args, f.Group)
	}
	if f.Environment != "" {
		where = append(where, "environment=?")
		args = append(args, f.Environment)
	}
	if f.Status != "" {
		where = append(where, "status=?")
		args = append(args, f.Status)
	}
	if f.Tag != "" {
		where = append(where, "tags LIKE ?")
		args = append(args, "%\""+f.Tag+"\"%")
	}
	if f.ProviderID > 0 {
		where = append(where, "provider_id=?")
		args = append(args, f.ProviderID)
	}
	sqlStr := `SELECT ` + vpsCols + ` FROM vps`
	if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	sqlStr += " ORDER BY name ASC"
	rows, err := db.Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*VPS
	for rows.Next() {
		v, err := scanVPS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (db *DB) UpdateVPS(v *VPS) error {
	auto := 0
	if v.AutoRenewal {
		auto = 1
	}
	probe := 0
	if v.HTTPProbeEnabled {
		probe = 1
	}
	_, err := db.Exec(`UPDATE vps SET name=?, host=?, ipv4=?, ipv6=?, ssh_port=?, ssh_user=?, auth_method=?,
		jump_host_id=?, provider=?, provider_id=?, region=?, expires_at=?, monthly_cost=?, group_name=?, tags=?,
		environment=?, op_mode=?, notes=?, host_key_fp=?, host_key_pending=?, status=?,
		maintenance_windows=?, server_type=?, panel_type=?, panel_url=?, panel_username=?,
		purchase_date=?, renewal_cycle=?, auto_renewal=?, currency=?, purchase_price=?,
		http_probe_enabled=?, http_probe_url=?, bandwidth=?, cpu_cores=?, ram_gb=?, disk_gb=?, sftp_root=?, socks_proxy=?,
		updated_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at IS NULL`,
		v.Name, v.Host, nullStr(v.IPv4), nullStr(v.IPv6), v.SSHPort, v.SSHUser, v.AuthMethod, v.JumpHostID,
		nullStr(v.Provider), v.ProviderID, nullStr(v.Region), v.ExpiresAt, v.MonthlyCost, nullStr(v.GroupName), v.Tags,
		v.Environment, v.OpMode, nullStr(v.Notes), nullStr(v.HostKeyFP), nullStr(v.HostKeyPending),
		v.Status, v.MaintenanceWins, nullStr(v.ServerType), nullStr(v.PanelType), nullStr(v.PanelURL), nullStr(v.PanelUsername),
		v.PurchaseDate, nullStr(v.RenewalCycle), auto, nullStr(v.Currency), v.PurchasePrice,
		probe, nullStr(v.HTTPProbeURL), nullStr(v.Bandwidth), v.CPUCores, v.RAMGB, v.DiskGB, nullStr(v.SFTPRoot), nullStr(v.SocksProxy), v.ID)
	return err
}

func (db *DB) SoftDeleteVPS(id int64) error {
	res, err := db.Exec(`UPDATE vps SET deleted_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) RestoreVPS(id int64) error {
	res, err := db.Exec(`UPDATE vps SET deleted_at=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at IS NOT NULL`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeVPS permanently deletes a soft-deleted VPS (credentials cascade via FK).
func (db *DB) PurgeVPS(id int64) error {
	res, err := db.Exec(`DELETE FROM vps WHERE id=? AND deleted_at IS NOT NULL`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeDeletedVPS permanently deletes soft-deleted rows. empty ids + all=true deletes every trashed VPS.
func (db *DB) PurgeDeletedVPS(ids []int64, all bool) (int64, error) {
	if all {
		res, err := db.Exec(`DELETE FROM vps WHERE deleted_at IS NOT NULL`)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	var n int64
	for _, id := range ids {
		if err := db.PurgeVPS(id); err == nil {
			n++
		}
	}
	return n, nil
}

func (db *DB) ListDeletedVPS() ([]*VPS, error) {
	rows, err := db.Query(`SELECT ` + vpsCols + ` FROM vps WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*VPS
	for rows.Next() {
		v, err := scanVPS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (db *DB) UpdateVPSHostKey(id int64, fp, pending string) error {
	_, err := db.Exec(`UPDATE vps SET host_key_fp=?, host_key_pending=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		nullStr(fp), nullStr(pending), id)
	return err
}

func (db *DB) TouchVPSConnect(id int64, status string) error {
	_, err := db.Exec(`UPDATE vps SET last_connect_at=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		time.Now(), status, id)
	return err
}

func (db *DB) TouchVPSScan(id int64) error {
	_, err := db.Exec(`UPDATE vps SET last_scan_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, time.Now(), id)
	return err
}

func (db *DB) UpsertCredential(vpsID int64, kind string, ciphertext []byte) error {
	_, err := db.Exec(`INSERT INTO credentials(vps_id, kind, ciphertext) VALUES(?,?,?)
		ON CONFLICT(vps_id, kind) DO UPDATE SET ciphertext=excluded.ciphertext, updated_at=CURRENT_TIMESTAMP`,
		vpsID, kind, ciphertext)
	return err
}

func (db *DB) GetCredential(vpsID int64, kind string) ([]byte, error) {
	var ct []byte
	err := db.QueryRow(`SELECT ciphertext FROM credentials WHERE vps_id=? AND kind=?`, vpsID, kind).Scan(&ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ct, err
}

func (db *DB) DeleteCredential(vpsID int64, kind string) error {
	_, err := db.Exec(`DELETE FROM credentials WHERE vps_id=? AND kind=?`, vpsID, kind)
	return err
}

func (db *DB) ListCredentials(vpsID int64) ([]Credential, error) {
	rows, err := db.Query(`SELECT id, vps_id, kind, ciphertext FROM credentials WHERE vps_id=?`, vpsID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.VPSID, &c.Kind, &c.Ciphertext); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) AllCredentialBlobs() ([]Credential, error) {
	rows, err := db.Query(`SELECT id, vps_id, kind, ciphertext FROM credentials`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.VPSID, &c.Kind, &c.Ciphertext); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) UpdateCredentialBlob(id int64, ct []byte) error {
	_, err := db.Exec(`UPDATE credentials SET ciphertext=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, ct, id)
	return err
}

func (db *DB) BatchUpdateVPS(ids []int64, fields map[string]any) error {
	if len(ids) == 0 {
		return nil
	}
	allowed := map[string]bool{
		"group_name": true, "environment": true, "op_mode": true, "provider": true, "provider_id": true, "region": true, "tags": true,
	}
	var sets []string
	var args []any
	for k, v := range fields {
		if !allowed[k] {
			return fmt.Errorf("field not allowed: %s", k)
		}
		if k == "op_mode" {
			switch fmt.Sprint(v) {
			case "readonly_monitor", "normal_tasks", "high_risk_allowed", "no_changes":
			default:
				return fmt.Errorf("invalid op_mode")
			}
		}
		if k == "environment" {
			switch fmt.Sprint(v) {
			case "production", "testing":
			default:
				return fmt.Errorf("invalid environment")
			}
		}
		if k == "provider_id" {
			switch n := v.(type) {
			case float64:
				v = int64(n)
			case int:
				v = int64(n)
			case int64:
			case string:
				parsed, err := strconv.ParseInt(n, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid provider_id")
				}
				v = parsed
			default:
				return fmt.Errorf("invalid provider_id")
			}
		}
		sets = append(sets, k+"=?")
		args = append(args, v)
	}
	if len(sets) == 0 {
		return nil
	}
	placeholders := make([]string, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	q := fmt.Sprintf(`UPDATE vps SET %s, updated_at=CURRENT_TIMESTAMP WHERE id IN (%s) AND deleted_at IS NULL`,
		strings.Join(sets, ","), strings.Join(placeholders, ","))
	_, err := db.Exec(q, args...)
	return err
}
