package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
)

type Service struct {
	DB      *store.DB
	DataDir string
	Vault   *crypto.Vault
}

func New(db *store.DB, dataDir string, vault *crypto.Vault) *Service {
	return &Service{DB: db, DataDir: dataDir, Vault: vault}
}

type PanelBackupMeta struct {
	CreatedAt string `json:"created_at"`
	Version   int    `json:"version"`
}

// CreatePanelBackup copies SQLite DB and encrypts with current vault KEK into data/backups.
func (s *Service) CreatePanelBackup() (*store.Backup, error) {
	if s.Vault.State() != crypto.VaultUnlocked {
		return nil, crypto.ErrVaultLocked
	}
	dir := filepath.Join(s.DataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("panel-%s.vbak", time.Now().UTC().Format("20060102-150405"))
	dataRoot, err := os.OpenRoot(s.DataDir)
	if err != nil {
		return nil, err
	}
	defer dataRoot.Close()
	raw, err := dataRoot.ReadFile("vpshub.db")
	if err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(PanelBackupMeta{CreatedAt: time.Now().UTC().Format(time.RFC3339), Version: 1})
	bundle := append(meta, 0)
	bundle = append(bundle, raw...)
	enc, err := s.Vault.EncryptSecret(bundle)
	if err != nil {
		return nil, err
	}
	bakRoot, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer bakRoot.Close()
	if err := bakRoot.WriteFile(name, enc, 0o600); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	sum := sha256.Sum256(enc)
	b := &store.Backup{
		Kind: "panel", Name: name, Storage: "local", Path: path,
		SHA256: hex.EncodeToString(sum[:]), Encrypted: true,
	}
	id, err := s.DB.CreateBackup(b)
	if err != nil {
		return nil, err
	}
	b.ID = id
	s.prunePanel(7)
	return b, nil
}

// prunePanel keeps the newest panel backups and removes the rest from disk and the catalog.
func (s *Service) prunePanel(keep int) {
	if keep < 1 {
		keep = 1
	}
	list, err := s.DB.ListBackups()
	if err != nil {
		return
	}
	n := 0
	root := filepath.Join(s.DataDir, "backups")
	for _, b := range list {
		if b.Kind != "panel" {
			continue
		}
		n++
		if n <= keep {
			continue
		}
		if rel, err := underBackups(root, b.Path); err == nil {
			_ = os.Remove(filepath.Join(root, rel))
		}
		_ = s.DB.DeleteBackup(b.ID)
	}
}

func underBackups(root, path string) (string, error) {
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(root, clean)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", fmt.Errorf("backup path must be under %s", root)
	}
	return rel, nil
}

// OpenLocal returns the encrypted backup file. The caller closes it.
func (s *Service) OpenLocal(id int64) (*os.File, *store.Backup, error) {
	b, err := s.DB.GetBackup(id)
	if err != nil {
		return nil, nil, err
	}
	rootDir := filepath.Join(s.DataDir, "backups")
	rel, err := underBackups(rootDir, b.Path)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return nil, nil, err
	}
	return f, b, nil
}

// DeleteLocal removes the backup file (if under data/backups) and the DB row.
func (s *Service) DeleteLocal(id int64) (*store.Backup, error) {
	b, err := s.DB.GetBackup(id)
	if err != nil {
		return nil, err
	}
	rootDir := filepath.Join(s.DataDir, "backups")
	if rel, err := underBackups(rootDir, b.Path); err == nil {
		_ = os.Remove(filepath.Join(rootDir, rel))
	}
	if err := s.DB.DeleteBackup(id); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Service) RestorePanelBackup(path string) error {
	if s.Vault.State() != crypto.VaultUnlocked {
		return crypto.ErrVaultLocked
	}
	rootDir := filepath.Join(s.DataDir, "backups")
	rel, err := underBackups(rootDir, path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	enc, err := root.ReadFile(rel)
	if err != nil {
		return err
	}
	pt, err := s.Vault.DecryptSecret(enc)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pt)
	// find null separator
	idx := -1
	for i, c := range pt {
		if c == 0 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("invalid backup format")
	}
	raw := pt[idx+1:]
	dataRoot, err := os.OpenRoot(s.DataDir)
	if err != nil {
		return err
	}
	defer dataRoot.Close()
	return dataRoot.WriteFile("vpshub.db.restored", raw, 0o600)
}

// RotateMasterPassword re-encrypts all credentials with a new password.
func (s *Service) RotateMasterPassword(oldPass, newPass string) (recoveryKey string, err error) {
	meta, err := s.DB.GetVaultMeta()
	if err != nil {
		return "", err
	}
	oldKEK := crypto.DeriveKEK(oldPass, meta.Salt)
	defer crypto.Wipe(oldKEK)
	if _, err := crypto.Decrypt(oldKEK, meta.Verifier); err != nil {
		return "", fmt.Errorf("old master password invalid")
	}
	return s.rekeyFromKEK(oldKEK, newPass)
}

// RecoverWithKey resets the master password using the offline recovery key.
// Requires a vault that was initialized/rotated after recovery wrap support.
func (s *Service) RecoverWithKey(recoveryKey, newPass string) (newRecoveryKey string, err error) {
	if len(newPass) < 12 {
		return "", fmt.Errorf("new master password must be at least 12 characters")
	}
	meta, err := s.DB.GetVaultMeta()
	if err != nil {
		return "", err
	}
	if !crypto.VerifyRecoveryKey(meta.RecoveryHash, recoveryKey) {
		return "", fmt.Errorf("invalid recovery key")
	}
	if len(meta.RecoverySalt) == 0 || len(meta.RecoveryWrappedKEK) == 0 {
		return "", fmt.Errorf("recovery wrap missing; unlock with master password and rotate once to enable recovery")
	}
	oldKEK, err := crypto.UnwrapKEK(recoveryKey, meta.RecoverySalt, meta.RecoveryWrappedKEK)
	if err != nil {
		return "", fmt.Errorf("invalid recovery key")
	}
	defer crypto.Wipe(oldKEK)
	return s.rekeyFromKEK(oldKEK, newPass)
}

func (s *Service) rekeyFromKEK(oldKEK []byte, newPass string) (recoveryKey string, err error) {
	newSalt, err := crypto.NewSalt()
	if err != nil {
		return "", err
	}
	newKEK := crypto.DeriveKEK(newPass, newSalt)
	defer crypto.Wipe(newKEK)

	creds, err := s.DB.AllCredentialBlobs()
	if err != nil {
		return "", err
	}
	for _, c := range creds {
		nct, err := crypto.Reencrypt(oldKEK, newKEK, c.Ciphertext)
		if err != nil {
			return "", err
		}
		if err := s.DB.UpdateCredentialBlob(c.ID, nct); err != nil {
			return "", err
		}
	}
	newVerifier, err := crypto.Encrypt(newKEK, []byte("vpshub-vault-ok"))
	if err != nil {
		return "", err
	}
	rec, hash, recSalt, wrapped, err := crypto.NewRecoveryBundle(newKEK)
	if err != nil {
		return "", err
	}
	if err := s.DB.InitVaultMeta(&store.VaultMeta{
		Salt: newSalt, Verifier: newVerifier, RecoveryHash: hash,
		RecoverySalt: recSalt, RecoveryWrappedKEK: wrapped,
	}); err != nil {
		return "", err
	}
	s.Vault.Lock()
	s.Vault.Unlock(newPass, newSalt)
	return rec, nil
}

