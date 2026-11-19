package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidCreds   = errors.New("invalid credentials")
	ErrLocked         = errors.New("account or IP locked")
	ErrTOTPRequired   = errors.New("totp required")
	ErrTOTPInvalid    = errors.New("invalid totp")
	ErrMustChangePass = errors.New("must change password")
	ErrIPNotAllowed   = errors.New("ip not allowed")
)

type Service struct {
	DB  *store.DB
	Cfg *config.Config
	// OnLockout is called when a user or IP lock is applied (no passwords).
	OnLockout func(username, ip, scope string)
	// OnLoginFail is called after a failed password or TOTP attempt (no secrets).
	OnLoginFail func(username, ip, reason string)
}

func New(db *store.DB, cfg *config.Config) *Service {
	return &Service{DB: db, Cfg: cfg}
}

func (s *Service) NeedsSetup() (bool, error) {
	n, err := s.DB.CountAdmins()
	return n == 0, err
}

func (s *Service) Setup(username, password string) (*store.Admin, string, error) {
	needs, err := s.NeedsSetup()
	if err != nil {
		return nil, "", err
	}
	if !needs {
		return nil, "", errors.New("already initialized")
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, "", err
	}
	id, err := s.DB.CreateAdmin(username, hash)
	if err != nil {
		return nil, "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "VPSHub",
		AccountName: username,
	})
	if err != nil {
		return nil, "", err
	}
	// Store TOTP secret temporarily unencrypted until vault is set; encode as plaintext marker for first unlock.
	// Phase 1: store base64 of secret in totp_secret_enc without vault (bootstrap). Re-encrypt optional later.
	enc := []byte(key.Secret())
	if err := s.DB.SetAdminTOTP(id, enc, false); err != nil {
		return nil, "", err
	}
	admin, err := s.DB.GetAdminByID(id)
	return admin, key.URL(), err
}

// ProvisionInitialAdmin creates the single admin, turns TOTP on, and requires a password change.
func (s *Service) ProvisionInitialAdmin(username, password string) (string, error) {
	admin, totpURL, err := s.Setup(username, password)
	if err != nil {
		return "", err
	}
	if err := s.DB.SetAdminTOTP(admin.ID, admin.TOTPSecretEnc, true); err != nil {
		return "", err
	}
	return totpURL, nil
}

// ResetPassword replaces the admin password and forces a change on next login.
func (s *Service) ResetPassword(adminID int64, password string) error {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.DB.UpdateAdminPassword(adminID, hash, true); err != nil {
		return err
	}
	return s.DB.DeleteSessionsByAdmin(adminID)
}

func (s *Service) checkWhitelist(ip string) error {
	if len(s.Cfg.IPWhitelist) == 0 {
		return nil
	}
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	for _, w := range s.Cfg.IPWhitelist {
		if w == host || w == "*" {
			return nil
		}
		if strings.Contains(w, "/") {
			_, cidr, err := net.ParseCIDR(w)
			if err == nil && cidr.Contains(net.ParseIP(host)) {
				return nil
			}
		}
	}
	return ErrIPNotAllowed
}

func (s *Service) Login(username, password, totpCode, ip, ua string) (sessionID string, admin *store.Admin, err error) {
	if err := s.checkWhitelist(ip); err != nil {
		return "", nil, err
	}
	_ = s.DB.DeleteExpiredSessions()

	locked, _, _ := s.DB.IsLocked("user:" + username)
	if locked {
		_ = s.DB.RecordLoginAttempt(username, ip, false)
		return "", nil, ErrLocked
	}
	locked, _, _ = s.DB.IsLocked("ip:" + stripPort(ip))
	if locked {
		_ = s.DB.RecordLoginAttempt(username, ip, false)
		return "", nil, ErrLocked
	}

	admin, err = s.DB.GetAdminByUsername(username)
	if err != nil {
		_ = s.DB.RecordLoginAttempt(username, ip, false)
		s.maybeLock(username, ip)
		return "", nil, ErrInvalidCreds
	}
	if !crypto.VerifyPassword(password, admin.PasswordHash) {
		_ = s.DB.RecordLoginAttempt(username, ip, false)
		s.maybeLock(username, ip)
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: username, IP: ip, Action: "login_failed", RiskLevel: "medium", Result: "failed",
			FailureReason: "bad_password",
		})
		if s.OnLoginFail != nil {
			s.OnLoginFail(username, stripPort(ip), "bad_password")
		}
		return "", nil, ErrInvalidCreds
	}

	if admin.TOTPEnabled {
		if totpCode == "" {
			return "", nil, ErrTOTPRequired
		}
		secret := string(admin.TOTPSecretEnc)
		if !totp.Validate(totpCode, secret) {
			_ = s.DB.RecordLoginAttempt(username, ip, false)
			s.maybeLock(username, ip)
			_ = s.DB.AppendAudit(store.AuditInput{
				Actor: username, IP: ip, Action: "login_failed", RiskLevel: "medium", Result: "failed",
				FailureReason: "bad_totp",
			})
			if s.OnLoginFail != nil {
				s.OnLoginFail(username, stripPort(ip), "bad_totp")
			}
			return "", nil, ErrTOTPInvalid
		}
	} else if len(admin.TOTPSecretEnc) > 0 && totpCode != "" {
		// First enable: verify and enable
		secret := string(admin.TOTPSecretEnc)
		if !totp.Validate(totpCode, secret) {
			_ = s.DB.AppendAudit(store.AuditInput{
				Actor: username, IP: ip, Action: "login_failed", RiskLevel: "medium", Result: "failed",
				FailureReason: "bad_totp",
			})
			if s.OnLoginFail != nil {
				s.OnLoginFail(username, stripPort(ip), "bad_totp")
			}
			return "", nil, ErrTOTPInvalid
		}
		_ = s.DB.SetAdminTOTP(admin.ID, admin.TOTPSecretEnc, true)
		admin.TOTPEnabled = true
	} else if len(admin.TOTPSecretEnc) > 0 && !admin.TOTPEnabled {
		// Force TOTP enrollment before issuing session — return special error with setup needed
		return "", admin, ErrTOTPRequired
	}

	sid, err := crypto.RandomToken(32)
	if err != nil {
		return "", nil, err
	}
	sess := &store.Session{
		ID:        sid,
		AdminID:   admin.ID,
		IP:        ip,
		UserAgent: ua,
		ExpiresAt: time.Now().Add(s.Cfg.SessionTTL),
	}
	if err := s.DB.CreateSession(sess); err != nil {
		return "", nil, err
	}
	_ = s.DB.RecordLoginAttempt(username, ip, true)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: username, IP: ip, Action: "login", RiskLevel: "low", Result: "success",
	})
	return sid, admin, nil
}

func (s *Service) maybeLock(username, ip string) {
	since := time.Now().Add(-time.Duration(s.Cfg.LoginLockMin) * time.Minute)
	uf, ipf, _ := s.DB.CountRecentFails(username, stripPort(ip), since)
	until := time.Now().Add(time.Duration(s.Cfg.LoginLockMin) * time.Minute)
	if uf >= s.Cfg.LoginMaxFails {
		_ = s.DB.SetLock("user:"+username, until, "too many failures")
		if s.OnLockout != nil {
			s.OnLockout(username, stripPort(ip), "user")
		}
	}
	if ipf >= s.Cfg.LoginMaxFails*2 {
		_ = s.DB.SetLock("ip:"+stripPort(ip), until, "too many failures")
		if s.OnLockout != nil {
			s.OnLockout(username, stripPort(ip), "ip")
		}
	}
}

func stripPort(ip string) string {
	if h, _, err := net.SplitHostPort(ip); err == nil {
		return h
	}
	return ip
}

func (s *Service) Logout(sessionID string) error {
	return s.DB.DeleteSession(sessionID)
}

func (s *Service) LogoutAll(adminID int64) error {
	return s.DB.DeleteSessionsByAdmin(adminID)
}

func (s *Service) SessionAdmin(sessionID string) (*store.Admin, error) {
	sess, err := s.DB.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DB.DeleteSession(sessionID)
		return nil, store.ErrNotFound
	}
	return s.DB.GetAdminByID(sess.AdminID)
}

func (s *Service) ChangePassword(adminID int64, oldPass, newPass string) error {
	admin, err := s.DB.GetAdminByID(adminID)
	if err != nil {
		return err
	}
	if !crypto.VerifyPassword(oldPass, admin.PasswordHash) {
		return ErrInvalidCreds
	}
	hash, err := crypto.HashPassword(newPass)
	if err != nil {
		return err
	}
	return s.DB.UpdateAdminPassword(adminID, hash, false)
}

func (s *Service) TOTPProvisioningURL(admin *store.Admin) string {
	secret := string(admin.TOTPSecretEnc)
	return fmt.Sprintf("otpauth://totp/VPSHub:%s?secret=%s&issuer=VPSHub", admin.Username, secret)
}

func (s *Service) EnableTOTP(adminID int64, code string) error {
	admin, err := s.DB.GetAdminByID(adminID)
	if err != nil {
		return err
	}
	secret := string(admin.TOTPSecretEnc)
	if !totp.Validate(code, secret) {
		return ErrTOTPInvalid
	}
	return s.DB.SetAdminTOTP(adminID, admin.TOTPSecretEnc, true)
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
