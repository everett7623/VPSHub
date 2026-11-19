package api

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/scripts"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Same host only.
		return origin == "http://"+r.Host || origin == "https://"+r.Host
	},
}

func (s *Server) webssh(c *gin.Context) {
	if !s.Cfg.WebSSHEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "webssh disabled by default", "enabled": false})
		return
	}
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
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
	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	client, _, err := s.SSH.Dial(c.Request.Context(), opts)
	crypto.Wipe(opts.PrivateKey)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("ssh: "+err.Error()))
		return
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		return
	}
	defer session.Close()
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	_ = session.RequestPty("xterm", 40, 120, nil)
	if err := session.Shell(); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "webssh_open", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical",
	})
	var inN, outN int
	idle := time.NewTimer(15 * time.Minute)
	defer idle.Stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				outN += n
				_ = conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		<-idle.C
		_ = conn.Close()
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Minute))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(15 * time.Minute)
		inN += len(msg)
		_, _ = stdin.Write(msg)
	}
	<-done
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "webssh_close", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
		Detail: "bytes_in=" + strconv.Itoa(inN) + " bytes_out=" + strconv.Itoa(outN),
	})
}

// websshSnippet returns an approved script body for pasting into an open WebSSH session.
// Passwords are never included. WebSSH must be enabled; vault must be unlocked.
func (s *Server) websshSnippet(c *gin.Context) {
	if !s.Cfg.WebSSHEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "webssh disabled by default"})
		return
	}
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return
	}
	vpsID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(vpsID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		ScriptID int64 `json:"script_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ScriptID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "script_id required"})
		return
	}
	sc, err := s.DB.GetScript(req.ScriptID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "script not found"})
		return
	}
	if err := scripts.CanExecute(sc, v.Environment == "production"); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "webssh_snippet", TargetType: "vps",
		TargetID: strconv.FormatInt(vpsID, 10), RiskLevel: "high",
		Detail: "script_id=" + strconv.FormatInt(sc.ID, 10) + " name=" + sc.Name + " sha256=" + sc.SHA256,
	})
	c.JSON(http.StatusOK, gin.H{
		"name":    sc.Name,
		"sha256":  sc.SHA256,
		"content": sc.Content,
	})
}

func (s *Server) sftpRoot(v *store.VPS) (string, error) {
	if v.SFTPRoot != "" {
		return v.SFTPRoot, nil
	}
	if v.OpMode == "high_risk_allowed" {
		return "/", nil
	}
	return "", errSFTPRoot
}

var errSFTPRoot = errString("set sftp_root, or use op_mode high_risk_allowed to allow /")

type errString string

func (e errString) Error() string { return string(e) }

func (s *Server) sftpList(c *gin.Context) {
	if !s.Cfg.SFTPEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "sftp disabled", "enabled": false})
		return
	}
	sess, v, err := s.openSFTP(c)
	if err != nil {
		return
	}
	defer sess.Close()
	entries, err := sess.List(c.Query("path"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"root": v.SFTPRoot, "entries": entries})
}

func (s *Server) sftpDownload(c *gin.Context) {
	if !s.Cfg.SFTPEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "sftp disabled"})
		return
	}
	sess, _, err := s.openSFTP(c)
	if err != nil {
		return
	}
	defer sess.Close()
	c.Writer.Header().Set("Content-Type", "application/octet-stream")
	if err := sess.Download(c.Query("path"), c.Writer); err != nil {
		return
	}
}

func (s *Server) sftpUpload(c *gin.Context) {
	if !s.Cfg.SFTPEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "sftp disabled"})
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	hookIDStr := strings.TrimSpace(c.PostForm("hook_script_id"))
	deleteAfter := c.PostForm("delete_after_hook") == "true" || c.PostForm("delete_after_hook") == "1"
	confirm := c.PostForm("confirm") == "true" || c.PostForm("confirm") == "1"
	var hook *store.Script
	if hookIDStr != "" {
		hid, perr := strconv.ParseInt(hookIDStr, 10, 64)
		if perr != nil || hid <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hook_script_id"})
			return
		}
		hook, err = s.DB.GetScript(hid)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hook script not found"})
			return
		}
		if err := scripts.CanExecute(hook, v.Environment == "production"); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		risk := hook.RiskLevel
		if risk == "" {
			risk = "medium"
		}
		if (risk == "medium" || risk == "high" || risk == "critical") && !confirm {
			c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required for hook"})
			return
		}
		if err := store.AllowChange(v.OpMode, risk); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
			return
		}
	} else if deleteAfter {
		c.JSON(http.StatusBadRequest, gin.H{"error": "delete_after_hook requires hook_script_id"})
		return
	}
	hookRisk := "medium"
	if hook != nil {
		hookRisk = hook.RiskLevel
		if hookRisk == "" {
			hookRisk = "medium"
		}
	}
	sess, _, err := s.openSFTP(c)
	if err != nil {
		return
	}
	defer sess.Close()
	file, hdr, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file required"})
		return
	}
	defer file.Close()
	dest := c.PostForm("path")
	if dest == "" {
		dest = hdr.Filename
	}
	sum, err := sess.Upload(dest, file, hdr.Size)
	if err != nil && err != io.EOF {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "sftp_upload", TargetType: "vps",
		TargetID: c.Param("id"), RiskLevel: "medium", Detail: dest + " sha256=" + sum,
	})
	resp := gin.H{"ok": true, "sha256": sum, "path": dest}
	if hook == nil {
		c.JSON(http.StatusOK, resp)
		return
	}
	root, rerr := s.sftpRoot(v)
	if rerr != nil {
		resp["hook_error"] = rerr.Error()
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook", TargetType: "vps",
			TargetID: c.Param("id"), RiskLevel: hookRisk, Result: "failed",
			Detail: "hook_script_id=" + hookIDStr + " path=" + dest + " sha256=" + sum, FailureReason: rerr.Error(),
		})
		c.JSON(http.StatusOK, resp)
		return
	}
	full, jerr := sshx.JailPath(root, dest)
	if jerr != nil {
		// Never pass an unjailed path into the hook environment.
		resp["hook_error"] = jerr.Error()
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook", TargetType: "vps",
			TargetID: c.Param("id"), RiskLevel: hookRisk, Result: "failed",
			Detail: "hook_script_id=" + hookIDStr + " path=" + dest + " sha256=" + sum, FailureReason: jerr.Error(),
		})
		c.JSON(http.StatusOK, resp)
		return
	}
	opts, oerr := s.connectOpts(v)
	if oerr != nil {
		resp["hook_error"] = oerr.Error()
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook", TargetType: "vps",
			TargetID: c.Param("id"), RiskLevel: hookRisk, Result: "failed",
			Detail: "hook_script_id=" + hookIDStr + " path=" + dest + " sha256=" + sum, FailureReason: oerr.Error(),
		})
		c.JSON(http.StatusOK, resp)
		return
	}
	cmd := scripts.WrapWithEnv(hook.Content, map[string]string{
		"VPSHUB_SFTP_PATH":   full,
		"VPSHUB_SFTP_SHA256": sum,
	})
	out, stderr, _, herr := s.SSH.Run(c.Request.Context(), opts, cmd)
	crypto.Wipe(opts.PrivateKey)
	resp["hook_script_id"] = hook.ID
	if herr != nil {
		resp["hook_error"] = herr.Error()
		if stderr != "" {
			resp["hook_stderr"] = truncateRun(stderr, 2<<10)
		}
		_ = s.DB.AppendAudit(store.AuditInput{
			Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook", TargetType: "vps",
			TargetID: c.Param("id"), RiskLevel: hookRisk, Result: "failed",
			Detail: "hook_script_id=" + hookIDStr + " path=" + dest + " sha256=" + sum, FailureReason: herr.Error(),
		})
		// Upload stays committed; hook failure is reported without deleting the file.
		c.JSON(http.StatusOK, resp)
		return
	}
	resp["hook_ok"] = true
	if out != "" {
		resp["hook_output"] = truncateRun(out, 2<<10)
	}
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook", TargetType: "vps",
		TargetID: c.Param("id"), RiskLevel: hookRisk, Result: "success",
		Detail: "hook_script_id=" + hookIDStr + " path=" + dest + " sha256=" + sum,
	})
	if deleteAfter {
		if derr := sess.Remove(dest); derr != nil {
			resp["delete_error"] = derr.Error()
			_ = s.DB.AppendAudit(store.AuditInput{
				Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook_cleanup", TargetType: "vps",
				TargetID: c.Param("id"), RiskLevel: "medium", Result: "failed",
				Detail: "path=" + dest + " sha256=" + sum, FailureReason: derr.Error(),
			})
		} else {
			resp["deleted_after_hook"] = true
			_ = s.DB.AppendAudit(store.AuditInput{
				Actor: a.Username, IP: c.ClientIP(), Action: "sftp_hook_cleanup", TargetType: "vps",
				TargetID: c.Param("id"), RiskLevel: "medium", Result: "success",
				Detail: "path=" + dest + " sha256=" + sum,
			})
		}
	}
	c.JSON(http.StatusOK, resp)
}

func truncateRun(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (s *Server) sftpReadText(c *gin.Context) {
	if !s.Cfg.SFTPEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "sftp disabled"})
		return
	}
	sess, _, err := s.openSFTP(c)
	if err != nil {
		return
	}
	defer sess.Close()
	text, sum, err := sess.ReadText(c.Query("path"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"content": text, "sha256": sum})
}

func (s *Server) sftpWriteText(c *gin.Context) {
	if !s.Cfg.SFTPEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "sftp disabled"})
		return
	}
	var req struct {
		Path    string `json:"path" binding:"required"`
		Content string `json:"content"`
		Confirm bool   `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path and confirm required"})
		return
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := store.AllowChange(v.OpMode, "medium"); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
		return
	}
	sess, _, err := s.openSFTP(c)
	if err != nil {
		return
	}
	defer sess.Close()
	sum, err := sess.WriteText(req.Path, req.Content)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "sftp_write", TargetType: "vps",
		TargetID: c.Param("id"), RiskLevel: "medium", Detail: req.Path + " sha256=" + sum,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "sha256": sum})
}

func (s *Server) openSFTP(c *gin.Context) (*sshx.SFTPSession, *store.VPS, error) {
	if s.Vault.State() != crypto.VaultUnlocked {
		c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		return nil, nil, errSFTPRoot
	}
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return nil, nil, err
	}
	root, err := s.sftpRoot(v)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return nil, nil, err
	}
	sess, err := s.dialSFTP(c, v, root)
	if err != nil {
		if err == crypto.ErrVaultLocked {
			c.JSON(http.StatusLocked, gin.H{"error": "vault_locked"})
		} else {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		}
		return nil, nil, err
	}
	return sess, v, nil
}

func (s *Server) dialSFTP(c *gin.Context, v *store.VPS, root string) (*sshx.SFTPSession, error) {
	if s.Vault.State() != crypto.VaultUnlocked {
		return nil, crypto.ErrVaultLocked
	}
	opts, err := s.connectOpts(v)
	if err != nil {
		return nil, err
	}
	sess, err := sshx.OpenSFTP(c.Request.Context(), s.SSH, opts, root, sshx.MaxUploadBytes)
	crypto.Wipe(opts.PrivateKey)
	return sess, err
}

func (s *Server) sftpDistribute(c *gin.Context) {
	if !s.Cfg.SFTPEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "sftp disabled"})
		return
	}
	var req struct {
		SourceVPSID int64   `json:"source_vps_id"`
		SourcePath  string  `json:"source_path"`
		DestPath    string  `json:"dest_path"`
		VPSIds      []int64 `json:"vps_ids"`
		Confirm     bool    `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm || req.SourceVPSID == 0 || req.SourcePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	if req.DestPath == "" {
		req.DestPath = req.SourcePath
	}
	ids := uniqueIDs(req.VPSIds)
	if len(ids) == 0 || len(ids) > sshx.DistributeMaxHosts {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vps_ids required, at most 40"})
		return
	}
	src, err := s.DB.GetVPS(req.SourceVPSID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	if _, err := sshx.RequireSFTPRoot(src.SFTPRoot, req.SourcePath); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	targets := make([]*store.VPS, 0, len(ids))
	for _, id := range ids {
		v, err := s.DB.GetVPS(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "vps not found", "vps_id": id})
			return
		}
		if _, err := sshx.RequireSFTPRoot(v.SFTPRoot, req.DestPath); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "vps": v.Name})
			return
		}
		if err := store.AllowChange(v.OpMode, "medium"); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
			return
		}
		targets = append(targets, v)
	}
	sess, err := s.dialSFTP(c, src, src.SFTPRoot)
	if err != nil {
		status := http.StatusBadGateway
		if err == crypto.ErrVaultLocked {
			status = http.StatusLocked
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	buf, sum, err := sess.ReadFile(req.SourcePath)
	_ = sess.Close()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()
	if int64(len(buf)) > sshx.MaxUploadBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file too large"})
		return
	}
	type result struct {
		VPSID  int64  `json:"vps_id"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(targets))
	okN := 0
	for _, v := range targets {
		full, jerr := sshx.RequireSFTPRoot(v.SFTPRoot, req.DestPath)
		if jerr != nil {
			results = append(results, result{VPSID: v.ID, Error: jerr.Error()})
			continue
		}
		ds, err := s.dialSFTP(c, v, v.SFTPRoot)
		if err != nil {
			results = append(results, result{VPSID: v.ID, Path: full, Error: err.Error()})
			continue
		}
		_, err = ds.Upload(req.DestPath, bytes.NewReader(buf), int64(len(buf)))
		_ = ds.Close()
		if err != nil {
			results = append(results, result{VPSID: v.ID, Path: full, Error: err.Error()})
			continue
		}
		okN++
		results = append(results, result{VPSID: v.ID, Path: full, SHA256: sum})
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "sftp_distribute", TargetType: "vps",
		TargetID: strconv.FormatInt(src.ID, 10), RiskLevel: "medium",
		Detail: "src=" + req.SourcePath + " dest=" + req.DestPath + " sha256=" + sum + " ok=" + strconv.Itoa(okN) + " hosts=" + strconv.Itoa(len(targets)),
	})
	c.JSON(http.StatusOK, gin.H{"sha256": sum, "results": results})
}

func uniqueIDs(ids []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
