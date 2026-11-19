package api

import (
	"net/http"
	"strconv"

	"github.com/evenfrank/vpshub/internal/auth"
	"github.com/evenfrank/vpshub/internal/crypto"
	mw "github.com/evenfrank/vpshub/internal/middleware"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

func (s *Server) clientIP(c *gin.Context) string {
	return mw.ClientIP(c, s.Cfg.TrustedProxies)
}

func (s *Server) dashboard(c *gin.Context) {
	stats, err := s.DB.DashboardStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days <= 0 || days > 365 {
		days = 30
	}
	expiring, _ := s.DB.ListExpiring(days)
	c.JSON(http.StatusOK, gin.H{"stats": stats, "expiring": expiring, "days": days})
}

func (s *Server) listProviders(c *gin.Context) {
	list, err := s.DB.ListProviders()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) createProvider(c *gin.Context) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		Website      string `json:"website"`
		Contact      string `json:"contact"`
		Notes        string `json:"notes"`
		PrivateNotes string `json:"private_notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p := &store.Provider{Name: req.Name, Website: req.Website, Contact: req.Contact, Notes: req.Notes}
	if req.PrivateNotes != "" {
		if s.Vault.State() != crypto.VaultUnlocked {
			c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
			return
		}
		ct, err := s.Vault.EncryptSecret([]byte(req.PrivateNotes))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		p.PrivateNotesEnc = ct
	}
	id, err := s.DB.CreateProvider(p)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.ID = id
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: s.clientIP(c), Action: "provider_create", TargetType: "provider", TargetID: strconv.FormatInt(id, 10)})
	c.JSON(http.StatusOK, p)
}

func (s *Server) updateProvider(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	existing, err := s.DB.GetProvider(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Name         string `json:"name" binding:"required"`
		Website      string `json:"website"`
		Contact      string `json:"contact"`
		Notes        string `json:"notes"`
		PrivateNotes string `json:"private_notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing.Name, existing.Website, existing.Contact, existing.Notes = req.Name, req.Website, req.Contact, req.Notes
	if req.PrivateNotes != "" {
		if s.Vault.State() != crypto.VaultUnlocked {
			c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
			return
		}
		ct, err := s.Vault.EncryptSecret([]byte(req.PrivateNotes))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing.PrivateNotesEnc = ct
	}
	if err := s.DB.UpdateProvider(existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, existing)
}

func (s *Server) deleteProvider(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	_ = s.DB.DeleteProvider(id)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) revealProviderNotes(c *gin.Context) {
	if err := s.requireViewToken(c); err != nil {
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	p, err := s.DB.GetProvider(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if len(p.PrivateNotesEnc) == 0 {
		c.JSON(http.StatusOK, gin.H{"private_notes": ""})
		return
	}
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
	pt, err := s.Vault.DecryptSecret(p.PrivateNotesEnc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer crypto.Wipe(pt)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: s.clientIP(c), Action: "reveal_provider_notes", TargetType: "provider", TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical"})
	c.JSON(http.StatusOK, gin.H{"private_notes": string(pt)})
}

func (s *Server) listWebsites(c *gin.Context) {
	list, err := s.DB.ListWebsites()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) createWebsite(c *gin.Context) {
	var w store.Website
	if err := c.ShouldBindJSON(&w); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if w.Status == "" {
		w.Status = "active"
	}
	if w.SiteType == "" {
		w.SiteType = "other"
	}
	id, err := s.DB.CreateWebsite(&w)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	w.ID = id
	c.JSON(http.StatusOK, w)
}

func (s *Server) updateWebsite(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	existing, err := s.DB.GetWebsite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var w store.Website
	if err := c.ShouldBindJSON(&w); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	w.ID = id
	if len(w.PanelPasswordEnc) == 0 {
		w.PanelPasswordEnc = existing.PanelPasswordEnc
	}
	if err := s.DB.UpdateWebsite(&w); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, w)
}

func (s *Server) deleteWebsite(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	_ = s.DB.DeleteWebsite(id)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) setWebsitePanelPassword(c *gin.Context) {
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	w, err := s.DB.GetWebsite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ct, err := s.Vault.EncryptSecret([]byte(req.Password))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	w.PanelPasswordEnc = ct
	_ = s.DB.UpdateWebsite(w)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) revealWebsitePassword(c *gin.Context) {
	if err := s.requireViewToken(c); err != nil {
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	w, err := s.DB.GetWebsite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if len(w.PanelPasswordEnc) == 0 {
		c.JSON(http.StatusOK, gin.H{"password": ""})
		return
	}
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
	pt, err := s.Vault.DecryptSecret(w.PanelPasswordEnc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer crypto.Wipe(pt)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: s.clientIP(c), Action: "reveal_website_password", TargetType: "website", TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical"})
	c.JSON(http.StatusOK, gin.H{"password": string(pt)})
}

func (s *Server) revealVPSCredential(c *gin.Context) {
	if err := s.requireViewToken(c); err != nil {
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	kind := c.Param("kind")
	if kind == "" {
		kind = "ssh_password"
	}
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
	ct, err := s.DB.GetCredential(id, kind)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	pt, err := s.Vault.DecryptSecret(ct)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer crypto.Wipe(pt)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: s.clientIP(c), Action: "reveal_credential", TargetType: "vps", TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical", Detail: kind})
	c.JSON(http.StatusOK, gin.H{"kind": kind, "value": string(pt)})
}

func (s *Server) requireViewToken(c *gin.Context) error {
	tok := c.GetHeader("X-View-Token")
	if tok == "" {
		tok = c.Query("view_token")
	}
	a := s.currentAdmin(c)
	if err := s.Auth.ConsumeViewToken(a.ID, s.clientIP(c), tok); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return err
	}
	return nil
}

func (s *Server) viewPasswordStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"configured": s.Auth.ViewPasswordConfigured()})
}

func (s *Server) viewPasswordSetup(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required,min=8"`
		Confirm  string `json:"password_confirm"`
		Force    bool   `json:"force"`
		Phrase   string `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Confirm != "" && req.Confirm != req.Password {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password mismatch"})
		return
	}
	if err := s.Auth.SetupViewPassword(req.Password, req.Force, req.Phrase); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: s.clientIP(c), Action: "view_password_setup", RiskLevel: "critical"})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) viewPasswordUnlock(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	tok, err := s.Auth.UnlockViewPassword(a.ID, s.clientIP(c), req.Password)
	if err != nil {
		code := http.StatusUnauthorized
		if err == auth.ErrViewPasswordRequired {
			code = http.StatusBadRequest
		}
		c.JSON(code, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: s.clientIP(c), Action: "view_password_unlock", RiskLevel: "high"})
	c.JSON(http.StatusOK, gin.H{"view_token": tok, "expires_in_sec": 120})
}

func (s *Server) listAlertRules(c *gin.Context) {
	list, err := s.DB.ListAlertRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) createAlertRule(c *gin.Context) {
	var r store.AlertRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if r.NotifyChannels == "" {
		r.NotifyChannels = `["webhook","telegram","smtp"]`
	}
	if r.DaysBefore == 0 {
		r.DaysBefore = 14
	}
	r.Enabled = true
	id, err := s.DB.CreateAlertRule(&r)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	r.ID = id
	c.JSON(http.StatusOK, r)
}

func (s *Server) updateAlertRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var r store.AlertRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	r.ID = id
	if err := s.DB.UpdateAlertRule(&r); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, r)
}

func (s *Server) deleteAlertRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	_ = s.DB.DeleteAlertRule(id)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) smtpTest(c *gin.Context) {
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "smtp_test", RiskLevel: "low",
	})
	s.Alert.Emit("smtp_test", "info", nil, "VPSHub SMTP test message")
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "test dispatched if SMTP configured"})
}

func (s *Server) alertChannelTest(c *gin.Context) {
	channel := c.Param("channel")
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "alert_test", RiskLevel: "low", Detail: channel,
	})
	msg := "VPSHub " + channel + " test message"
	switch channel {
	case "smtp":
		s.Alert.Emit("smtp_test", "info", nil, msg)
	case "webhook":
		s.Alert.Emit("webhook_test", "info", nil, msg)
	case "telegram":
		s.Alert.Emit("telegram_test", "info", nil, msg)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel must be smtp|webhook|telegram"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "channel": channel})
}

func (s *Server) runProbesNow(c *gin.Context) {
	if s.Probe != nil {
		go s.Probe.RunOnce(c.Request.Context())
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
