package store

import (
	"database/sql"
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

func (db *DB) CountAdmins() (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM admins`).Scan(&n)
	return n, err
}

func (db *DB) CreateAdmin(username, passwordHash string) (int64, error) {
	res, err := db.Exec(`INSERT INTO admins(username, password_hash, must_change_password) VALUES(?,?,1)`,
		username, passwordHash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) GetAdminByUsername(username string) (*Admin, error) {
	a := &Admin{}
	var totpEnabled, mustChange int
	var totpEnc []byte
	err := db.QueryRow(`SELECT id, username, password_hash, totp_secret_enc, totp_enabled, must_change_password,
		COALESCE(webauthn_credentials,'[]'), created_at, updated_at FROM admins WHERE username=?`, username).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &totpEnc, &totpEnabled, &mustChange, &a.WebAuthnCreds, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.TOTPSecretEnc = totpEnc
	a.TOTPEnabled = totpEnabled == 1
	a.MustChangePassword = mustChange == 1
	return a, nil
}

func (db *DB) FirstAdmin() (*Admin, error) {
	var id int64
	err := db.QueryRow(`SELECT id FROM admins ORDER BY id ASC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return db.GetAdminByID(id)
}

func (db *DB) GetAdminByID(id int64) (*Admin, error) {
	a := &Admin{}
	var totpEnabled, mustChange int
	var totpEnc []byte
	err := db.QueryRow(`SELECT id, username, password_hash, totp_secret_enc, totp_enabled, must_change_password,
		COALESCE(webauthn_credentials,'[]'), created_at, updated_at FROM admins WHERE id=?`, id).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &totpEnc, &totpEnabled, &mustChange, &a.WebAuthnCreds, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.TOTPSecretEnc = totpEnc
	a.TOTPEnabled = totpEnabled == 1
	a.MustChangePassword = mustChange == 1
	return a, nil
}

func (db *DB) UpdateAdminPassword(id int64, hash string, mustChange bool) error {
	mc := 0
	if mustChange {
		mc = 1
	}
	_, err := db.Exec(`UPDATE admins SET password_hash=?, must_change_password=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		hash, mc, id)
	return err
}

func (db *DB) SetAdminTOTP(id int64, secretEnc []byte, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := db.Exec(`UPDATE admins SET totp_secret_enc=?, totp_enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		secretEnc, en, id)
	return err
}

func (db *DB) CreateSession(s *Session) error {
	_, err := db.Exec(`INSERT INTO sessions(id, admin_id, ip, user_agent, expires_at) VALUES(?,?,?,?,?)`,
		s.ID, s.AdminID, s.IP, s.UserAgent, s.ExpiresAt)
	return err
}

func (db *DB) GetSession(id string) (*Session, error) {
	s := &Session{}
	err := db.QueryRow(`SELECT id, admin_id, COALESCE(ip,''), COALESCE(user_agent,''), expires_at, created_at FROM sessions WHERE id=?`, id).
		Scan(&s.ID, &s.AdminID, &s.IP, &s.UserAgent, &s.ExpiresAt, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

func (db *DB) DeleteSession(id string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (db *DB) DeleteSessionsByAdmin(adminID int64) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE admin_id=?`, adminID)
	return err
}

func (db *DB) DeleteExpiredSessions() error {
	_, err := db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	return err
}

func (db *DB) ListSessionsByAdmin(adminID int64) ([]Session, error) {
	_ = db.DeleteExpiredSessions()
	rows, err := db.Query(`SELECT id, admin_id, COALESCE(ip,''), COALESCE(user_agent,''), expires_at, created_at
		FROM sessions WHERE admin_id=? ORDER BY created_at DESC`, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.AdminID, &s.IP, &s.UserAgent, &s.ExpiresAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) RecordLoginAttempt(username, ip string, success bool) error {
	s := 0
	if success {
		s = 1
	}
	_, err := db.Exec(`INSERT INTO login_attempts(username, ip, success) VALUES(?,?,?)`, username, ip, s)
	return err
}

func (db *DB) CountRecentFails(username, ip string, since time.Time) (userFails, ipFails int, err error) {
	err = db.QueryRow(`SELECT COUNT(1) FROM login_attempts WHERE username=? AND success=0 AND created_at>=?`, username, since).Scan(&userFails)
	if err != nil {
		return
	}
	err = db.QueryRow(`SELECT COUNT(1) FROM login_attempts WHERE ip=? AND success=0 AND created_at>=?`, ip, since).Scan(&ipFails)
	return
}

func (db *DB) SetLock(key string, until time.Time, reason string) error {
	_, err := db.Exec(`INSERT INTO account_locks(key, until, reason) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET until=excluded.until, reason=excluded.reason`, key, until, reason)
	return err
}

func (db *DB) IsLocked(key string) (bool, string, error) {
	var until time.Time
	var reason sql.NullString
	err := db.QueryRow(`SELECT until, reason FROM account_locks WHERE key=?`, key).Scan(&until, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if time.Now().Before(until) {
		return true, reason.String, nil
	}
	_, _ = db.Exec(`DELETE FROM account_locks WHERE key=?`, key)
	return false, "", nil
}

type AccountLock struct {
	Key    string    `json:"key"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason,omitempty"`
}

type LoginAttemptRow struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	IP        string    `json:"ip"`
	Success   bool      `json:"success"`
	CreatedAt time.Time `json:"created_at"`
}

func (db *DB) ListActiveLocks() ([]AccountLock, error) {
	rows, err := db.Query(`SELECT key, until, COALESCE(reason,'') FROM account_locks WHERE until > ? ORDER BY until DESC`, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountLock
	for rows.Next() {
		var l AccountLock
		if err := rows.Scan(&l.Key, &l.Until, &l.Reason); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (db *DB) ClearAllLocks() (int, error) {
	locks, err := db.ListActiveLocks()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range locks {
		if err := db.ClearLock(l.Key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (db *DB) ClearLock(key string) error {
	_, err := db.Exec(`DELETE FROM account_locks WHERE key=?`, key)
	return err
}

func (db *DB) ListRecentLoginAttempts(limit int) ([]LoginAttemptRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.Query(`SELECT id, username, ip, success, created_at FROM login_attempts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginAttemptRow
	for rows.Next() {
		var r LoginAttemptRow
		var ok int
		if err := rows.Scan(&r.ID, &r.Username, &r.IP, &ok, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Success = ok == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) GetSetting(key string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// VaultMeta is the single-row vault KEK material (never stores plaintext KEK).
type VaultMeta struct {
	Salt               []byte
	Verifier           []byte
	RecoveryHash       string
	RecoverySalt       []byte
	RecoveryWrappedKEK []byte
}

func (db *DB) GetVaultMeta() (*VaultMeta, error) {
	m := &VaultMeta{}
	var rh sql.NullString
	var recSalt, wrapped []byte
	err := db.QueryRow(`SELECT salt, verifier, recovery_key_hash, recovery_salt, recovery_wrapped_kek
		FROM vault_meta WHERE id=1`).Scan(&m.Salt, &m.Verifier, &rh, &recSalt, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m.RecoveryHash = rh.String
	m.RecoverySalt = recSalt
	m.RecoveryWrappedKEK = wrapped
	return m, nil
}

func (db *DB) InitVaultMeta(m *VaultMeta) error {
	_, err := db.Exec(`INSERT INTO vault_meta(id, salt, verifier, recovery_key_hash, recovery_salt, recovery_wrapped_kek)
		VALUES(1,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET salt=excluded.salt, verifier=excluded.verifier,
		recovery_key_hash=excluded.recovery_key_hash, recovery_salt=excluded.recovery_salt,
		recovery_wrapped_kek=excluded.recovery_wrapped_kek, updated_at=CURRENT_TIMESTAMP`,
		m.Salt, m.Verifier, m.RecoveryHash, m.RecoverySalt, m.RecoveryWrappedKEK)
	return err
}

func (db *DB) UpdateVaultVerifier(verifier []byte, salt []byte) error {
	_, err := db.Exec(`UPDATE vault_meta SET verifier=?, salt=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`, verifier, salt)
	return err
}
