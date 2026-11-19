package api

import (
	"net/http"
	"testing"
)

func TestTokenScopeAllows(t *testing.T) {
	cases := []struct {
		scopes, method, path string
		ok                   bool
	}{
		{`[]`, http.MethodPost, "/api/vault/unlock", true},
		{`["*"]`, http.MethodDelete, "/api/tokens/1", true},
		{`["read"]`, http.MethodGet, "/api/vps", true},
		{`["read"]`, http.MethodPost, "/api/vps", false},
		{`["write"]`, http.MethodPost, "/api/tasks", true},
		{`["write"]`, http.MethodPost, "/api/vault/unlock", false},
		{`["admin"]`, http.MethodPost, "/api/vault/recover", true},
		{`["read"]`, http.MethodGet, "/api/sessions", false},
	}
	for _, tc := range cases {
		got := tokenScopeAllows(tc.scopes, tc.method, tc.path)
		if got != tc.ok {
			t.Fatalf("%s %s %s: got %v want %v", tc.scopes, tc.method, tc.path, got, tc.ok)
		}
	}
}
