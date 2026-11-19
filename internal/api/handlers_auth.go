package api

import (
	"fmt"
	"net/http"

	"github.com/evenfrank/vpshub/internal/auth"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

func (s *Server) setupStatus(c *gin.Context) {
	needs, err := s.Auth.NeedsSetup()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, vaultErr := s.DB.GetVaultMeta()
	c.JSON(http.StatusOK, gin.H{
		"needs_setup": needs,
		"vault_init":  vaultErr == nil,
		"vault_state": s.Vault.State(),
	})
}

func (s *Server) setup(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	admin, totpURL, err := s.Auth.Setup(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"admin":    gin.H{"id": admin.ID, "username": admin.Username},
		"totp_url": totpURL,
		"message":  "Scan TOTP and enable before first login completes",
	})
}

func (s *Server) login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		TOTP     string `json:"totp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sid, admin, err := s.Auth.Login(req.Username, req.Password, req.TOTP, c.ClientIP(), c.Request.UserAgent())
	if err == auth.ErrTOTPRequired && admin != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":    "totp_required",
			"totp_url": s.Auth.TOTPProvisioningURL(admin),
		})
		return
	}
	if err != nil {
		code := http.StatusUnauthorized
		if err == auth.ErrLocked || err == auth.ErrIPNotAllowed {
			code = http.StatusForbidden
		}
		c.JSON(code, gin.H{"error": err.Error()})
		return
	}
	s.setSessionCookie(c, sid)
	c.JSON(http.StatusOK, gin.H{
		"username":             admin.Username,
		"must_change_password": admin.MustChangePassword,
		"totp_enabled":         admin.TOTPEnabled,
	})
}

func (s *Server) logout(c *gin.Context) {
	if sid, err := c.Cookie(sessionCookie); err == nil {
		_ = s.Auth.Logout(sid)
	}
	s.clearSessionCookie(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) me(c *gin.Context) {
	a := s.currentAdmin(c)
	c.JSON(http.StatusOK, gin.H{
		"id":                   a.ID,
		"username":             a.Username,
		"must_change_password": a.MustChangePassword,
		"totp_enabled":         a.TOTPEnabled,
		"vault":                s.Vault.State(),
	})
}

func (s *Server) changePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	if err := s.Auth.ChangePassword(a.ID, req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "change_password", RiskLevel: "high"})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) totpSetup(c *gin.Context) {
	a := s.currentAdmin(c)
	full, err := s.DB.GetAdminByID(a.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"totp_url": s.Auth.TOTPProvisioningURL(full), "enabled": full.TOTPEnabled})
}

func (s *Server) enableTOTP(c *gin.Context) {
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	if err := s.Auth.EnableTOTP(a.ID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) revokeAll(c *gin.Context) {
	a := s.currentAdmin(c)
	_ = s.Auth.LogoutAll(a.ID)
	s.clearSessionCookie(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "revoke_sessions", RiskLevel: "medium"})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) listLocks(c *gin.Context) {
	locks, err := s.DB.ListActiveLocks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	attempts, _ := s.DB.ListRecentLoginAttempts(40)
	c.JSON(http.StatusOK, gin.H{"locks": locks, "recent_attempts": attempts})
}

func (s *Server) clearLock(c *gin.Context) {
	var req struct {
		Key string `json:"key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key required"})
		return
	}
	if err := s.DB.ClearLock(req.Key); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "clear_lock", RiskLevel: "high", Detail: req.Key,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) clearAllLocks(c *gin.Context) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	n, err := s.DB.ClearAllLocks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "clear_all_locks", RiskLevel: "high",
		Detail: fmt.Sprintf("count=%d", n),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "cleared": n})
}

func (s *Server) listSessions(c *gin.Context) {
	a := s.currentAdmin(c)
	list, err := s.DB.ListSessionsByAdmin(a.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	cur, _ := c.Cookie(sessionCookie)
	out := make([]gin.H, 0, len(list))
	for _, sess := range list {
		out = append(out, gin.H{
			"id":         sess.ID,
			"ip":         sess.IP,
			"user_agent": sess.UserAgent,
			"expires_at": sess.ExpiresAt,
			"created_at": sess.CreatedAt,
			"current":    sess.ID == cur,
		})
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) revokeSession(c *gin.Context) {
	a := s.currentAdmin(c)
	sid := c.Param("id")
	sess, err := s.DB.GetSession(sid)
	if err != nil || sess.AdminID != a.ID {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	_ = s.DB.DeleteSession(sid)
	cur, _ := c.Cookie(sessionCookie)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "revoke_session", RiskLevel: "medium", Detail: sid[:min(8, len(sid))],
	})
	if sid == cur {
		s.clearSessionCookie(c)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "self": sid == cur})
}

func (s *Server) vaultStatus(c *gin.Context) {
	meta, err := s.DB.GetVaultMeta()
	recoveryReady := false
	if err == nil && meta != nil {
		recoveryReady = len(meta.RecoveryWrappedKEK) > 0 && len(meta.RecoverySalt) > 0
	}
	c.JSON(http.StatusOK, gin.H{
		"state": s.Vault.State(), "initialized": err == nil, "recovery_ready": recoveryReady,
	})
}

func (s *Server) vaultInit(c *gin.Context) {
	var req struct {
		MasterPassword string `json:"master_password" binding:"required,min=12"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := s.DB.GetVaultMeta(); err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vault already initialized"})
		return
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	kek := crypto.DeriveKEK(req.MasterPassword, salt)
	defer crypto.Wipe(kek)
	verifier, err := crypto.Encrypt(kek, []byte("vpshub-vault-ok"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rec, recHash, recSalt, wrapped, err := crypto.NewRecoveryBundle(kek)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.DB.InitVaultMeta(&store.VaultMeta{
		Salt: salt, Verifier: verifier, RecoveryHash: recHash,
		RecoverySalt: recSalt, RecoveryWrappedKEK: wrapped,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.Vault.Unlock(req.MasterPassword, salt)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "vault_init", RiskLevel: "critical"})
	c.JSON(http.StatusOK, gin.H{"ok": true, "recovery_key": rec, "state": s.Vault.State()})
}

func (s *Server) vaultUnlock(c *gin.Context) {
	var req struct {
		MasterPassword string `json:"master_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	meta, err := s.DB.GetVaultMeta()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vault not initialized"})
		return
	}
	kek := crypto.DeriveKEK(req.MasterPassword, meta.Salt)
	defer crypto.Wipe(kek)
	if _, err := crypto.Decrypt(kek, meta.Verifier); err != nil {
		a := s.currentAdmin(c)
		_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "vault_unlock", Result: "failed", RiskLevel: "high", FailureReason: "bad_password"})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid master password"})
		return
	}
	s.Vault.Unlock(req.MasterPassword, meta.Salt)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "vault_unlock", RiskLevel: "high"})
	c.JSON(http.StatusOK, gin.H{"state": s.Vault.State()})
}

func (s *Server) vaultLock(c *gin.Context) {
	s.Vault.Lock()
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "vault_lock", RiskLevel: "medium"})
	c.JSON(http.StatusOK, gin.H{"state": s.Vault.State()})
}

func (s *Server) vaultRotate(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=12"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rec, err := s.Backup.RotateMasterPassword(req.OldPassword, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "vault_rotate", RiskLevel: "critical"})
	c.JSON(http.StatusOK, gin.H{"ok": true, "recovery_key": rec})
}

func (s *Server) vaultRecover(c *gin.Context) {
	var req struct {
		RecoveryKey    string `json:"recovery_key" binding:"required"`
		NewPassword    string `json:"new_password" binding:"required,min=12"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ConfirmPassword != "" && req.ConfirmPassword != req.NewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password confirmation mismatch"})
		return
	}
	a := s.currentAdmin(c)
	rec, err := s.Backup.RecoverWithKey(req.RecoveryKey, req.NewPassword)
	if err != nil {
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "vault_recover", Result: "failed",
			RiskLevel: "critical", FailureReason: err.Error(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "vault_recover", RiskLevel: "critical"})
	c.JSON(http.StatusOK, gin.H{"ok": true, "recovery_key": rec, "state": s.Vault.State()})
}
