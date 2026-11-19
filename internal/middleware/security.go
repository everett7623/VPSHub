package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}

func generateCSRF() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CSRF validates double-submit cookie for mutating methods (server-panel pattern).
func CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			ensureCSRFCookie(c)
			c.Next()
			return
		}
		// Skip CSRF for API bearer tokens and setup/login bootstrap
		if strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		if path == "/api/login" || path == "/api/setup" || path == "/api/setup/status" {
			c.Next()
			return
		}
		header := c.GetHeader("X-CSRF-Token")
		cookie, err := c.Cookie("csrf_token")
		if err != nil || cookie == "" || header == "" || subtle.ConstantTimeCompare([]byte(header), []byte(cookie)) != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "csrf_mismatch"})
			return
		}
		c.Next()
	}
}

func ensureCSRFCookie(c *gin.Context) {
	if tok, err := c.Cookie("csrf_token"); err == nil && tok != "" {
		c.Header("X-CSRF-Token", tok)
		return
	}
	tok := generateCSRF()
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	// HttpOnly must be false so the SPA can mirror the value into X-CSRF-Token.
	http.SetCookie(c.Writer, &http.Cookie{ // #nosec G124 -- double-submit CSRF cookie is intentionally JS-readable
		Name: "csrf_token", Value: tok, MaxAge: 86400, Path: "/",
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	c.Header("X-CSRF-Token", tok)
}

// ClientIP prefers CF-Connecting-IP when peer looks like a proxy, else gin ClientIP.
func ClientIP(c *gin.Context, trustedProxies []string) string {
	remote := c.RemoteIP()
	if isTrustedProxy(remote, trustedProxies) {
		if cf := strings.TrimSpace(c.GetHeader("CF-Connecting-IP")); cf != "" {
			if net.ParseIP(cf) != nil {
				return cf
			}
		}
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return c.ClientIP()
}

func isTrustedProxy(ip string, list []string) bool {
	if len(list) == 0 {
		// trust loopback by default (local reverse proxy)
		parsed := net.ParseIP(ip)
		return parsed != nil && (parsed.IsLoopback() || parsed.IsPrivate())
	}
	for _, t := range list {
		if t == ip || t == "*" {
			return true
		}
		if strings.Contains(t, "/") {
			_, cidr, err := net.ParseCIDR(t)
			if err == nil && cidr.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

// BasePath restricts panel under optional random prefix (server-panel style).
func BasePath(prefix string) gin.HandlerFunc {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" || prefix == "/" {
		return func(c *gin.Context) { c.Next() }
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return func(c *gin.Context) {
		p := c.Request.URL.Path
		if p == "/healthz" {
			c.Next()
			return
		}
		if !strings.HasPrefix(p, prefix+"/") && p != prefix {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Request.URL.Path = strings.TrimPrefix(p, prefix)
		if c.Request.URL.Path == "" {
			c.Request.URL.Path = "/"
		}
		c.Next()
	}
}
