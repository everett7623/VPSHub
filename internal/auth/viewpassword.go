package auth

import (
	"errors"
	"time"

	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const viewPasswordSetting = "view_password_hash"
const viewFailSetting = "view_password_fails:"

var (
	ErrViewPasswordRequired = errors.New("view password required")
	ErrViewPasswordInvalid  = errors.New("invalid view password")
	ErrViewTokenInvalid     = errors.New("invalid or expired view token")
)

// SetupViewPassword stores bcrypt hash. Force reset clears saved secrets (server-panel pattern).
func (s *Service) SetupViewPassword(password string, force bool, confirmPhrase string) error {
	existing, _ := s.DB.GetSetting(viewPasswordSetting)
	if existing != "" && !force {
		return errors.New("view password already set")
	}
	if existing != "" && force {
		if confirmPhrase != "DELETE_SAVED_PASSWORDS" {
			return errors.New("confirm phrase required: DELETE_SAVED_PASSWORDS")
		}
		if err := s.DB.ClearAllCredentialCiphertexts(); err != nil {
			return err
		}
		_ = s.DB.ClearViewTokens()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	return s.DB.SetSetting(viewPasswordSetting, string(hash))
}

func (s *Service) ViewPasswordConfigured() bool {
	v, err := s.DB.GetSetting(viewPasswordSetting)
	return err == nil && v != ""
}

func (s *Service) ChangeViewPassword(oldPass, newPass string) error {
	hash, err := s.DB.GetSetting(viewPasswordSetting)
	if err != nil {
		return ErrViewPasswordRequired
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPass)) != nil {
		return ErrViewPasswordInvalid
	}
	nh, err := bcrypt.GenerateFromPassword([]byte(newPass), 12)
	if err != nil {
		return err
	}
	_ = s.DB.ClearViewTokens()
	return s.DB.SetSetting(viewPasswordSetting, string(nh))
}

// UnlockViewPassword verifies password and returns a short-lived token bound to admin+IP (2 min, reusable until expiry).
func (s *Service) UnlockViewPassword(adminID int64, ip, password string) (string, error) {
	hash, err := s.DB.GetSetting(viewPasswordSetting)
	if err != nil || hash == "" {
		return "", ErrViewPasswordRequired
	}
	failKey := viewFailSetting + ip
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		// track fails — after 5 wipe secrets (server-panel stop-loss)
		n := 0
		if v, e := s.DB.GetSetting(failKey); e == nil {
			for _, c := range v {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
		}
		n++
		_ = s.DB.SetSetting(failKey, itoa(n))
		if n >= 5 {
			_ = s.DB.ClearAllCredentialCiphertexts()
			_ = s.DB.ClearViewTokens()
			_ = s.DB.SetSetting(failKey, "0")
			_ = s.DB.AppendAudit(store.AuditInput{
				Actor: "system", IP: ip, Action: "view_password_wipe", RiskLevel: "critical",
				Detail: "5 failed view-password attempts; credentials cleared",
			})
		}
		return "", ErrViewPasswordInvalid
	}
	_ = s.DB.SetSetting(failKey, "0")
	tok, err := crypto.RandomToken(24)
	if err != nil {
		return "", err
	}
	if err := s.DB.CreateViewToken(tok, adminID, ip, time.Now().Add(2*time.Minute)); err != nil {
		return "", err
	}
	return tok, nil
}

func (s *Service) ConsumeViewToken(adminID int64, ip, token string) error {
	ok, err := s.DB.ConsumeViewToken(token, ip, adminID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrViewTokenInvalid
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
