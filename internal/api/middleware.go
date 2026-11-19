package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

const sessionCookie = "vpshub_session"

func (s *Server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, err := c.Cookie(sessionCookie)
		if err != nil || sid == "" {
			// Bearer API token
			authz := c.GetHeader("Authorization")
			if len(authz) > 7 && authz[:7] == "Bearer " {
				if s.authAPIToken(c, authz[7:]) {
					return
				}
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		admin, err := s.Auth.SessionAdmin(sid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("admin", admin)
		c.Set("session_id", sid)
		c.Next()
	}
}

func (s *Server) authAPIToken(c *gin.Context, raw string) bool {
	h := hashToken(raw)
	tok, err := s.DB.GetAPITokenByHash(h)
	if err != nil || tok.RevokedAt != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return true
	}
	if tok.ExpiresAt != nil && time.Now().After(*tok.ExpiresAt) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return true
	}
	if !tokenScopeAllows(tok.Scopes, c.Request.Method, c.Request.URL.Path) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token_scope_denied"})
		return true
	}
	c.Set("admin", &store.Admin{ID: 0, Username: "api:" + tok.Name})
	c.Set("api_token", tok)
	c.Next()
	return true
}

// tokenScopeAllows: empty or ["*"] = full; else read|write|admin.
func tokenScopeAllows(scopesJSON, method, path string) bool {
	var scopes []string
	_ = json.Unmarshal([]byte(scopesJSON), &scopes)
	if len(scopes) == 0 {
		return true
	}
	has := func(s string) bool {
		for _, x := range scopes {
			if x == s || x == "*" {
				return true
			}
		}
		return false
	}
	if has("*") {
		return true
	}
	adminPath := strings.Contains(path, "/vault") || strings.Contains(path, "/tokens") ||
		strings.Contains(path, "/sessions") || strings.Contains(path, "/password") ||
		strings.Contains(path, "/totp") || strings.Contains(path, "/view-password")
	if adminPath {
		return has("admin")
	}
	if method == http.MethodGet || method == http.MethodHead {
		return has("read") || has("write") || has("admin")
	}
	return has("write") || has("admin")
}

func (s *Server) requireVault() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Vault.State() != crypto.VaultUnlocked {
			c.AbortWithStatusJSON(http.StatusLocked, gin.H{"error": "vault_locked", "state": s.Vault.State()})
			return
		}
		s.Vault.Touch()
		c.Next()
	}
}

func (s *Server) currentAdmin(c *gin.Context) *store.Admin {
	v, _ := c.Get("admin")
	if v == nil {
		return nil
	}
	return v.(*store.Admin)
}

func (s *Server) setSessionCookie(c *gin.Context, sid string) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(sessionCookie, sid, int(s.Cfg.SessionTTL.Seconds()), "/", "", s.Cfg.SecureCookie, true)
}

func (s *Server) clearSessionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(sessionCookie, "", -1, "/", "", s.Cfg.SecureCookie, true)
}
