package api

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/collector"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

func (s *Server) listVPS(c *gin.Context) {
	providerID, _ := strconv.ParseInt(c.Query("provider_id"), 10, 64)
	list, err := s.DB.ListVPS(store.VPSFilter{
		Q: c.Query("q"), Group: c.Query("group"), Environment: c.Query("environment"),
		Tag: c.Query("tag"), Status: c.Query("status"), ProviderID: providerID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if list == nil {
		list = []*store.VPS{}
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) getVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, v)
}

func (s *Server) createVPS(c *gin.Context) {
	var v store.VPS
	if err := c.ShouldBindJSON(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := normalizeSocks(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	mw, err := store.NormalizeMaintenanceWindows(v.MaintenanceWins)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v.MaintenanceWins = mw
	id, err := s.DB.CreateVPS(&v)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_create", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "medium",
	})
	v.ID = id
	c.JSON(http.StatusOK, v)
}

func (s *Server) updateVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	existing, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var v store.VPS
	if err := c.ShouldBindJSON(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v.ID = id
	if v.HostKeyFP == "" {
		v.HostKeyFP = existing.HostKeyFP
	}
	if v.HostKeyPending == "" {
		v.HostKeyPending = existing.HostKeyPending
	}
	if v.Status == "" {
		v.Status = existing.Status
	}
	if v.Tags == "" {
		v.Tags = existing.Tags
	}
	if v.MaintenanceWins == "" {
		v.MaintenanceWins = existing.MaintenanceWins
	}
	mw, merr := store.NormalizeMaintenanceWindows(v.MaintenanceWins)
	if merr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": merr.Error()})
		return
	}
	v.MaintenanceWins = mw
	if err := normalizeSocks(&v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.DB.UpdateVPS(&v); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_update", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "medium",
	})
	c.JSON(http.StatusOK, v)
}

func (s *Server) deleteVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := s.DB.SoftDeleteVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_delete", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) listDeletedVPS(c *gin.Context) {
	list, err := s.DB.ListDeletedVPS()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if list == nil {
		list = []*store.VPS{}
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) purgeVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	if err := s.DB.PurgeVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found or not soft-deleted"})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_purge", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) purgeVPSBatch(c *gin.Context) {
	var req struct {
		Confirm bool    `json:"confirm"`
		All     bool    `json:"all"`
		IDs     []int64 `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	if !req.All && len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids or all required"})
		return
	}
	n, err := s.DB.PurgeDeletedVPS(req.IDs, req.All)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_purge_batch", RiskLevel: "critical",
		Detail: fmt.Sprintf("purged=%d all=%v", n, req.All),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "purged": n})
}

func (s *Server) maintenanceStatus(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, store.WindowStatus(v.MaintenanceWins, time.Now()))
}

func (s *Server) restoreVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := s.DB.RestoreVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_restore", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "medium",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) setCredentials(c *gin.Context) {
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
		Passphrase string `json:"passphrase"`
		SudoPass   string `json:"sudo_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	save := func(kind, val string) error {
		if val == "" {
			return nil
		}
		ct, err := s.Vault.EncryptSecret([]byte(val))
		if err != nil {
			return err
		}
		return s.DB.UpsertCredential(id, kind, ct)
	}
	if err := save("ssh_password", req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := save("ssh_private_key", req.PrivateKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := save("key_passphrase", req.Passphrase); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := save("sudo_password", req.SudoPass); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "credential_update", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical", Detail: "kinds updated (no secrets logged)",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func normalizeSocks(v *store.VPS) error {
	p, err := sshx.ParseSocksProxy(v.SocksProxy)
	if err != nil {
		return err
	}
	v.SocksProxy = p
	return nil
}

func (s *Server) connectOpts(v *store.VPS) (sshx.ConnectOpts, error) {
	return s.connectOptsDepth(v, 0)
}

func (s *Server) connectOptsDepth(v *store.VPS, depth int) (sshx.ConnectOpts, error) {
	proxyAddr, err := sshx.ParseSocksProxy(v.SocksProxy)
	if err != nil {
		return sshx.ConnectOpts{}, err
	}
	opts := sshx.ConnectOpts{
		Host: v.Host, Port: v.SSHPort, User: v.SSHUser, KnownFP: v.HostKeyFP,
		SocksProxy: proxyAddr,
	}
	if pw, err := s.DB.GetCredential(v.ID, "ssh_password"); err == nil {
		pt, err := s.Vault.DecryptSecret(pw)
		if err != nil {
			return opts, err
		}
		opts.Password = string(pt)
		crypto.Wipe(pt)
	}
	if key, err := s.DB.GetCredential(v.ID, "ssh_private_key"); err == nil {
		pt, err := s.Vault.DecryptSecret(key)
		if err != nil {
			return opts, err
		}
		opts.PrivateKey = pt
	}
	if ph, err := s.DB.GetCredential(v.ID, "key_passphrase"); err == nil {
		pt, err := s.Vault.DecryptSecret(ph)
		if err != nil {
			return opts, err
		}
		opts.Passphrase = string(pt)
		crypto.Wipe(pt)
	}
	if opts.Password == "" && len(opts.PrivateKey) == 0 {
		return opts, errors.New("no credentials")
	}
	if depth == 0 && v.JumpHostID != nil {
		if *v.JumpHostID == v.ID {
			return opts, errors.New("jump host cannot be itself")
		}
		jump, err := s.DB.GetVPS(*v.JumpHostID)
		if err != nil {
			return opts, fmt.Errorf("jump host: %w", err)
		}
		jopts, err := s.connectOptsDepth(jump, depth+1)
		if err != nil {
			return opts, fmt.Errorf("jump host: %w", err)
		}
		opts.Jump = &sshx.JumpSpec{
			Host: jopts.Host, Port: jopts.Port, User: jopts.User,
			Password: jopts.Password, PrivateKey: jopts.PrivateKey,
			Passphrase: jopts.Passphrase, KnownFP: jopts.KnownFP,
			SocksProxy: jopts.SocksProxy,
		}
	}
	return opts, nil
}

func (s *Server) testConnection(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	opts, err := s.connectOpts(v)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	confirm := c.Query("confirm_hostkey") == "1"
	opts.PendingOK = confirm
	var pendingFP string
	opts.OnPending = func(fp string) {
		pendingFP = fp
		_ = s.DB.UpdateVPSHostKey(id, v.HostKeyFP, fp)
	}

	out, stderr, fp, err := s.SSH.Run(c.Request.Context(), opts, "echo ok && uname -a")
	a := s.currentAdmin(c)
	if errors.Is(err, sshx.ErrHostKeyUnknown) {
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "ssh_test", TargetType: "vps",
			TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", Result: "pending_hostkey", Detail: pendingFP,
		})
		c.JSON(http.StatusConflict, gin.H{"error": "host_key_pending", "fingerprint": pendingFP})
		return
	}
	if errors.Is(err, sshx.ErrHostKeyMismatch) {
		s.Alert.Emit("host_key_changed", "critical", &id, fmt.Sprintf("Host key changed for %s", v.Name))
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "ssh_test", TargetType: "vps",
			TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical", Result: "failed", FailureReason: "host_key_mismatch",
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "host_key_mismatch"})
		return
	}
	if err != nil {
		_ = s.DB.TouchVPSConnect(id, "offline")
		if recent, _ := s.DB.HasRecentAlert(id, "ssh_fail", 6*time.Hour); !recent {
			s.Alert.Emit("ssh_fail", "warning", &id, fmt.Sprintf("SSH failed for %s: %s", v.Name, err.Error()))
		}
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "ssh_test", TargetType: "vps",
			TargetID: strconv.FormatInt(id, 10), RiskLevel: "medium", Result: "failed", FailureReason: err.Error(),
		})
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "stderr": stderr})
		return
	}
	if v.HostKeyFP == "" && fp != "" {
		_ = s.DB.UpdateVPSHostKey(id, fp, "")
	}
	_ = s.DB.TouchVPSConnect(id, "online")
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "ssh_test", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "low", Result: "success",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "output": strings.TrimSpace(out), "fingerprint": fp})
}

func (s *Server) confirmHostKey(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if v.HostKeyPending == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no pending host key"})
		return
	}
	_ = s.DB.UpdateVPSHostKey(id, v.HostKeyPending, "")
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "hostkey_confirm", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", Detail: v.HostKeyPending,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "fingerprint": v.HostKeyPending})
}

func (s *Server) clearHostKey(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	if _, err := s.DB.GetVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := s.DB.UpdateVPSHostKey(id, "", ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "hostkey_clear", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) importVPSCSV(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file required"})
		return
	}
	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid csv"})
		return
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(row []string, key string) string {
		i, ok := idx[key]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	var created int
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user := get(row, "ssh_user")
		if user == "" {
			user = get(row, "user")
		}
		group := get(row, "group_name")
		if group == "" {
			group = get(row, "group")
		}
		tags := get(row, "tags")
		if tags == "" {
			tags = "[]"
		}
		v := &store.VPS{
			Name: get(row, "name"), Host: get(row, "host"), SSHUser: user,
			Provider: get(row, "provider"), Region: get(row, "region"), GroupName: group,
			Environment: get(row, "environment"), OpMode: get(row, "op_mode"), Notes: get(row, "notes"),
			Tags: tags, SocksProxy: get(row, "socks_proxy"), IPv4: get(row, "ipv4"), IPv6: get(row, "ipv6"),
			AuthMethod: get(row, "auth_method"), Currency: get(row, "currency"),
			RenewalCycle: get(row, "renewal_cycle"), ServerType: get(row, "server_type"),
			HTTPProbeURL: get(row, "http_probe_url"), Bandwidth: get(row, "bandwidth"),
			SFTPRoot: get(row, "sftp_root"), MaintenanceWins: get(row, "maintenance_windows"),
		}
		if v.Name == "" || v.Host == "" {
			continue
		}
		if v.SSHUser == "" {
			v.SSHUser = "root"
		}
		if v.Environment == "" {
			v.Environment = "production"
		}
		if v.OpMode == "" {
			v.OpMode = "normal_tasks"
		}
		port := get(row, "ssh_port")
		if port == "" {
			port = get(row, "port")
		}
		if port != "" {
			v.SSHPort, _ = strconv.Atoi(port)
		}
		if exp := get(row, "expires_at"); exp != "" {
			v.ExpiresAt = &exp
		}
		if pd := get(row, "purchase_date"); pd != "" {
			v.PurchaseDate = &pd
		}
		if c := get(row, "monthly_cost"); c != "" {
			if f, err := strconv.ParseFloat(c, 64); err == nil {
				v.MonthlyCost = &f
			}
		}
		if c := get(row, "purchase_price"); c != "" {
			if f, err := strconv.ParseFloat(c, 64); err == nil {
				v.PurchasePrice = &f
			}
		}
		if c := get(row, "cpu_cores"); c != "" {
			if f, err := strconv.ParseFloat(c, 64); err == nil {
				v.CPUCores = &f
			}
		}
		if c := get(row, "ram_gb"); c != "" {
			if f, err := strconv.ParseFloat(c, 64); err == nil {
				v.RAMGB = &f
			}
		}
		if c := get(row, "disk_gb"); c != "" {
			if f, err := strconv.ParseFloat(c, 64); err == nil {
				v.DiskGB = &f
			}
		}
		v.PanelType = get(row, "panel_type")
		v.PanelURL = get(row, "panel_url")
		if j := get(row, "jump_host_id"); j != "" {
			if id, err := strconv.ParseInt(j, 10, 64); err == nil {
				v.JumpHostID = &id
			}
		}
		ar := get(row, "auto_renewal")
		v.AutoRenewal = ar == "1" || strings.EqualFold(ar, "true") || strings.EqualFold(ar, "yes")
		pe := get(row, "http_probe_enabled")
		v.HTTPProbeEnabled = pe == "1" || strings.EqualFold(pe, "true") || strings.EqualFold(pe, "yes")
		if _, err := s.DB.CreateVPS(v); err == nil {
			created++
		}
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_csv_import", RiskLevel: "medium",
		Detail: fmt.Sprintf("created=%d", created),
	})
	c.JSON(http.StatusOK, gin.H{"created": created})
}

func (s *Server) batchVPS(c *gin.Context) {
	var req struct {
		IDs    []int64        `json:"ids" binding:"required"`
		Fields map[string]any `json:"fields" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.DB.BatchUpdateVPS(req.IDs, req.Fields); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_batch_update", TargetType: "vps",
		RiskLevel: "medium", Detail: fmt.Sprintf("count=%d", len(req.IDs)),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) scanVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	opts, err := s.connectOpts(v)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := s.Collector.Scan(c.Request.Context(), opts, id, s.Fingerprints)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	s.emitExpectationGaps(id, v.Name)
	c.JSON(http.StatusOK, res)
}

func (s *Server) emitExpectationGaps(vpsID int64, vpsName string) {
	if s.Alert == nil {
		return
	}
	assigned, err := s.DB.ListExpectationTemplates(vpsID)
	if err != nil || len(assigned) == 0 {
		return
	}
	inv, err := s.DB.ListServiceInventory(vpsID)
	if err != nil {
		return
	}
	status := map[string]string{}
	for _, row := range inv {
		status[row.ServiceType] = row.Status
	}
	var missing []string
	for _, t := range assigned {
		actual := status[t.ServiceType]
		if actual == "" {
			actual = "missing"
		}
		if actual != "running" {
			missing = append(missing, fmt.Sprintf("%s(%s)", t.Name, actual))
		}
	}
	if len(missing) == 0 {
		return
	}
	recent, _ := s.DB.HasRecentAlert(vpsID, "expectation_gap", 6*time.Hour)
	if recent {
		return
	}
	s.Alert.Emit("expectation_gap", "warning", &vpsID,
		fmt.Sprintf("%s expectation gaps: %s", vpsName, strings.Join(missing, ", ")))
}

func (s *Server) getScan(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	p, err := s.DB.LatestScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no scan"})
		return
	}
	var raw json.RawMessage = json.RawMessage(p)
	c.JSON(http.StatusOK, raw)
}

func (s *Server) vpsMetrics(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if _, err := s.DB.GetVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	scans, err := s.DB.ListScans(id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	pts := collector.MetricsFromScans(scans)
	if pts == nil {
		pts = []collector.MetricPoint{}
	}
	c.JSON(http.StatusOK, gin.H{"points": pts, "keep": store.ScanResultsKeep})
}

func (s *Server) serviceMatrix(c *gin.Context) {
	inv, err := s.DB.ListServiceInventory(0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, inv)
}

func (s *Server) listAudit(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, err := s.DB.ListAuditFiltered(store.AuditFilter{
		Action: c.Query("action"),
		Actor:  c.Query("actor"),
		Risk:   c.Query("risk"),
		Result: c.Query("result"),
		Q:      c.Query("q"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) listAuditActions(c *gin.Context) {
	list, err := s.DB.ListAuditActions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if list == nil {
		list = []string{}
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) exportAudit(c *gin.Context) {
	list, err := s.DB.ListAuditFiltered(store.AuditFilter{
		Action: c.Query("action"),
		Actor:  c.Query("actor"),
		Risk:   c.Query("risk"),
		Result: c.Query("result"),
		Q:      c.Query("q"),
		Limit:  2000,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="vpshub-audit.csv"`)
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{
		"id", "created_at", "actor", "ip", "action", "target_type", "target_id", "risk_level",
		"result", "detail", "task_id", "failure_reason", "prev_hash", "entry_hash",
	})
	for _, e := range list {
		_ = w.Write([]string{
			strconv.FormatInt(e.ID, 10),
			e.CreatedAt.UTC().Format(time.RFC3339),
			e.Actor, e.IP, e.Action, e.TargetType, e.TargetID, e.RiskLevel, e.Result, e.Detail,
			e.TaskID, e.FailureReason, e.PrevHash, e.EntryHash,
		})
	}
	w.Flush()
}

func (s *Server) convertToKey(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := store.AllowChange(v.OpMode, "critical"); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
		return
	}
	opts, err := s.connectOpts(v)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	priv, pub, err := sshx.GenerateEd25519Key("vpshub@" + v.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo %q >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", strings.TrimSpace(string(pub)))
	_, _, _, err = s.SSH.Run(c.Request.Context(), opts, cmd)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	// verify with new key
	keyOpts := opts
	keyOpts.Password = ""
	keyOpts.PrivateKey = priv
	_, _, _, err = s.SSH.Run(c.Request.Context(), keyOpts, "echo keyok")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "key verify failed: " + err.Error()})
		return
	}
	ct, err := s.Vault.EncryptSecret(priv)
	crypto.Wipe(priv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.UpsertCredential(id, "ssh_private_key", ct)
	_ = s.DB.DeleteCredential(id, "ssh_password")
	v.AuthMethod = "key"
	_ = s.DB.UpdateVPS(v)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "password_to_key", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
