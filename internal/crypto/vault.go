package crypto

import (
	"errors"
	"sync"
	"time"
)

type VaultState string

const (
	VaultLocked   VaultState = "locked"
	VaultUnlocked VaultState = "unlocked"
	VaultExpired  VaultState = "expired"
)

var (
	ErrVaultLocked = errors.New("vault is locked")
)

// Vault holds the in-memory KEK. Never persisted.
type Vault struct {
	mu       sync.RWMutex
	kek      []byte
	state    VaultState
	unlocked time.Time
	lockTTL  time.Duration
}

func NewVault(lockTTL time.Duration) *Vault {
	return &Vault{
		state:   VaultLocked,
		lockTTL: lockTTL,
	}
}

func (v *Vault) State() VaultState {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expireIfNeeded()
	return v.state
}

func (v *Vault) expireIfNeeded() {
	if v.state == VaultUnlocked && v.lockTTL > 0 && time.Since(v.unlocked) > v.lockTTL {
		Wipe(v.kek)
		v.kek = nil
		v.state = VaultExpired
	}
}

// Unlock derives KEK from password+salt and stores it in memory.
func (v *Vault) Unlock(password string, salt []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.kek != nil {
		Wipe(v.kek)
	}
	v.kek = DeriveKEK(password, salt)
	v.state = VaultUnlocked
	v.unlocked = time.Now()
}

// Lock clears the KEK from memory.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	Wipe(v.kek)
	v.kek = nil
	v.state = VaultLocked
}

// Touch extends the unlock window.
func (v *Vault) Touch() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state == VaultUnlocked {
		v.unlocked = time.Now()
	}
}

// EncryptSecret encrypts plaintext if vault is unlocked.
func (v *Vault) EncryptSecret(plaintext []byte) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expireIfNeeded()
	if v.state != VaultUnlocked || v.kek == nil {
		return nil, ErrVaultLocked
	}
	v.unlocked = time.Now()
	return Encrypt(v.kek, plaintext)
}

// DecryptSecret decrypts blob if vault is unlocked.
func (v *Vault) DecryptSecret(blob []byte) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expireIfNeeded()
	if v.state != VaultUnlocked || v.kek == nil {
		return nil, ErrVaultLocked
	}
	v.unlocked = time.Now()
	return Decrypt(v.kek, blob)
}

// WithKEK runs fn with a copy of the KEK; caller must wipe when done via returned cleanup.
// Prefer EncryptSecret/DecryptSecret for normal use.
func (v *Vault) KEKCopy() ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expireIfNeeded()
	if v.state != VaultUnlocked || v.kek == nil {
		return nil, ErrVaultLocked
	}
	out := make([]byte, len(v.kek))
	copy(out, v.kek)
	v.unlocked = time.Now()
	return out, nil
}

// ReencryptAll re-encrypts blobs with a new password (key rotation helper).
func Reencrypt(oldKEK, newKEK, blob []byte) ([]byte, error) {
	pt, err := Decrypt(oldKEK, blob)
	if err != nil {
		return nil, err
	}
	defer Wipe(pt)
	return Encrypt(newKEK, pt)
}
