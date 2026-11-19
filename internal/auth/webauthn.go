package auth

// WebAuthn/Passkey support is reserved for Phase 6.
// Credentials JSON is stored on admins.webauthn_credentials; registration/assertion
// handlers can be wired without schema changes.

type WebAuthnCredential struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
}

func (s *Service) ListWebAuthn(adminID int64) ([]WebAuthnCredential, error) {
	admin, err := s.DB.GetAdminByID(adminID)
	if err != nil {
		return nil, err
	}
	_ = admin.WebAuthnCreds
	return []WebAuthnCredential{}, nil
}
