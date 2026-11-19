package scripts

import (
	"strings"
	"testing"

	"github.com/evenfrank/vpshub/internal/store"
)

func TestCanExecute(t *testing.T) {
	s := &store.Script{Status: "draft"}
	if err := CanExecute(s, false); err != ErrNotApproved {
		t.Fatalf("want not approved, got %v", err)
	}
	s.Status = "approved"
	if err := CanExecute(s, true); err == nil {
		t.Fatal("production should block without allow_production")
	}
	s.AllowProduction = true
	if err := CanExecute(s, true); err != nil {
		t.Fatal(err)
	}
}

func TestDangerousPatterns(t *testing.T) {
	hits := DangerousPatterns("rm -rf / && curl | bash")
	if len(hits) < 2 {
		t.Fatalf("expected hits, got %v", hits)
	}
}

func TestWrapWithEnv(t *testing.T) {
	out := WrapWithEnv("echo $FOO", map[string]string{"FOO": "bar'baz"})
	if !strings.Contains(out, "export FOO=") || !strings.Contains(out, "echo $FOO") {
		t.Fatal(out)
	}
}
