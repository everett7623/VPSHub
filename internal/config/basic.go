package config

import (
	"os"
	"strconv"
	"strings"
)

// WriteBasicAuth sets the browser basic-auth username and Argon2id hash.
// The plaintext password is never written.
func WriteBasicAuth(path, user, hash string) error {
	b, err := os.ReadFile(path) // #nosec G304 -- panel config path from installer
	if err != nil {
		return err
	}
	text := setYAMLKey(string(b), "basic_auth_user", user)
	text = setYAMLKey(text, "basic_auth_hash", hash)
	mode := os.FileMode(0o640)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), mode); err != nil { // #nosec G703 -- adjacent .tmp under known config path
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, mode)
}

func setYAMLKey(text, key, value string) string {
	line := key + ": " + strconv.Quote(value)
	lines := strings.Split(text, "\n")
	found := false
	for i, raw := range lines {
		trim := strings.TrimSpace(raw)
		if trim == key+":" || strings.HasPrefix(trim, key+":") {
			lines[i] = line
			found = true
		}
	}
	if !found {
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
