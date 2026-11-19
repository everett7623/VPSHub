package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/evenfrank/vpshub/internal/store"
)

var ErrNotApproved = errors.New("script not approved for execution")

func ContentSHA256(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func CanExecute(s *store.Script, production bool) error {
	switch s.Status {
	case "approved", "published":
	default:
		return ErrNotApproved
	}
	if production && !s.AllowProduction {
		return errors.New("script not allowed on production")
	}
	return nil
}

// CanBatch rejects multi-host runs when the script has not opted into batching.
func CanBatch(s *store.Script, targetCount int) error {
	if targetCount <= 1 {
		return nil
	}
	if !s.AllowBatch {
		return errors.New("script does not allow batch execution")
	}
	return nil
}

// DangerousPatterns are heuristic warnings (not a substitute for review).
func DangerousPatterns(content string) []string {
	lower := strings.ToLower(content)
	var hits []string
	checks := []string{
		"rm -rf /", "mkfs", ":(){", "dd if=", "curl | bash", "curl|bash",
		"wget | sh", "chmod 777", "> /dev/sda", "iptables -F",
	}
	for _, c := range checks {
		if strings.Contains(lower, c) {
			hits = append(hits, c)
		}
	}
	return hits
}

// WrapWithEnv runs script content with env vars only (no string-concat of user args into shell).
func WrapWithEnv(content string, env map[string]string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -eu\n")
	for k, v := range env {
		// sanitize key
		key := strings.Map(func(r rune) rune {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
				return r
			}
			return -1
		}, k)
		if key == "" {
			continue
		}
		b.WriteString("export " + key + "=")
		b.WriteString(shellQuote(v))
		b.WriteString("\n")
	}
	b.WriteString(content)
	b.WriteString("\n")
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
