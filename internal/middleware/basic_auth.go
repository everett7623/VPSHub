package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/gin-gonic/gin"
)

// BasicAuth requires HTTP basic authentication when a username and Argon2id hash are set.
// Both the username digest and the password hash are checked on every request.
// The password is never logged.
func BasicAuth(user, hash string) gin.HandlerFunc {
	if user == "" || hash == "" {
		return func(c *gin.Context) { c.Next() }
	}
	wantUser := sha256.Sum256([]byte(user))
	return func(c *gin.Context) {
		gotUser, password, ok := c.Request.BasicAuth()
		sum := sha256.Sum256([]byte(gotUser))
		userOK := subtle.ConstantTimeCompare(wantUser[:], sum[:]) == 1
		passOK := crypto.VerifyPassword(password, hash)
		if !ok || !userOK || !passOK {
			c.Header("WWW-Authenticate", `Basic realm="VPSHub", charset="UTF-8"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}
