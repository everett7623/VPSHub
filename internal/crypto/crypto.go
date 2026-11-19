package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
	nonceLen     = 12
)

var (
	ErrDecryptFailed = errors.New("decryption failed")
	ErrInvalidKey    = errors.New("invalid key")
)

// DeriveKEK derives a key-encryption key from a master password and salt.
func DeriveKEK(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// NewSalt generates a random salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// RandomPassword returns a password of n characters from a non-ambiguous alphabet.
func RandomPassword(n int) (string, error) {
	if n < 16 {
		n = 16
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}

// RandomToken is defined below. RandomID returns hex of n bytes.
func RandomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashPassword hashes an admin password with Argon2id (encode: salt$hash base64).
func HashPassword(password string) (string, error) {
	salt, err := NewSalt()
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash), nil
}

// VerifyPassword checks a password against a stored Argon2id hash.
func VerifyPassword(password, encoded string) bool {
	var saltB64, hashB64 string
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '$' {
			saltB64 = encoded[:i]
			hashB64 = encoded[i+1:]
			break
		}
	}
	if saltB64 == "" || hashB64 == "" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if len(got) != len(want) {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}

// Encrypt encrypts plaintext with AES-256-GCM using kek. Returns nonce||ciphertext.
func Encrypt(kek, plaintext []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	return out, nil
}

// Decrypt decrypts nonce||ciphertext with AES-256-GCM.
func Decrypt(kek, blob []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, ErrInvalidKey
	}
	if len(blob) < nonceLen {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// Wipe overwrites a byte slice (best-effort; Go GC may retain copies).
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HashChain computes sha256(prev||payload) for audit log chaining.
func HashChain(prev string, payload []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(prev))
	_, _ = h.Write(payload)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// RandomToken returns a URL-safe random token of n bytes.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// VerifyRecoveryKey checks a recovery key against the stored hash (constant-time).
func VerifyRecoveryKey(storedHash, key string) bool {
	got := HashChain("", []byte(key))
	if len(got) != len(storedHash) || storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// WrapKEK encrypts the master KEK under a key derived from recoveryKey+salt.
func WrapKEK(recoveryKey string, salt, kek []byte) ([]byte, error) {
	wk := DeriveKEK(recoveryKey, salt)
	defer Wipe(wk)
	return Encrypt(wk, kek)
}

// UnwrapKEK decrypts a wrapped master KEK with the recovery key.
func UnwrapKEK(recoveryKey string, salt, wrapped []byte) ([]byte, error) {
	if len(salt) == 0 || len(wrapped) == 0 {
		return nil, ErrDecryptFailed
	}
	wk := DeriveKEK(recoveryKey, salt)
	defer Wipe(wk)
	return Decrypt(wk, wrapped)
}

// NewRecoveryBundle generates a recovery key and wraps kek under it.
// Returns plaintext recovery key (show once), its hash, salt, and wrapped kek.
func NewRecoveryBundle(kek []byte) (recoveryKey, hash string, salt, wrapped []byte, err error) {
	recoveryKey, err = RandomToken(32)
	if err != nil {
		return "", "", nil, nil, err
	}
	salt, err = NewSalt()
	if err != nil {
		return "", "", nil, nil, err
	}
	wrapped, err = WrapKEK(recoveryKey, salt, kek)
	if err != nil {
		return "", "", nil, nil, err
	}
	hash = HashChain("", []byte(recoveryKey))
	return recoveryKey, hash, salt, wrapped, nil
}
