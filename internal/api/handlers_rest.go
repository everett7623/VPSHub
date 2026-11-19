package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/backup"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/scripts"
	"github.com/evenfrank/vpshub/internal/services"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func scriptIDFromPayload(payload any) int64 {
	m, ok := payload.(map[string]any)
	if !ok {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0
		}
		_ = json.Unmarshal(b, &m)
	}
	switch v := m["script_id"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

func (s *Server) listScripts(c *gin.Context) {
	list, err := s.DB.ListScriptsFiltered(c.Query("status"), c.Query("category"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) getScript(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	sc, err := s.DB.GetScript(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"script": sc, "dangerous": scripts.DangerousPatterns(sc.Content)})
}

func (s *Server) createScript(c *gin.Context) {
	var req store.Script
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	req.SHA256 = scripts.ContentSHA256(req.Content)
	req.Status = "draft"
	req.CreatedBy = a.Username
	if req.Version == "" {
		req.Version = "1.0.0"
	}
	if req.OSFilter == "" {
		req.OSFilter = "[]"
	}
	if req.ParamsSchema == "" {
		req.ParamsSchema = "[]"
	}
	id, err := s.DB.CreateScript(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	req.ID = id
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "script_create", TargetType: "script",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "medium",
	})
	c.JSON(http.StatusOK, gin.H{"script": req, "dangerous": scripts.DangerousPatterns(req.Content)})
}

func (s *Server) reviewScript(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Status string `json:"status" binding:"required"` // review|approved|published|disabled|archived
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	sc, err := s.DB.GetScript(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if req.Status == "published" {
		if hist, _ := s.DB.ListScriptVersions(id); len(hist) > 0 {
			for _, h := range hist {
				if h.Note == "publish" {
					next := bumpPatchVersion(sc.Version)
					if next != sc.Version {
						_ = s.DB.BumpScriptVersion(id, next)
						sc.Version = next
					}
					break
				}
			}
		}
		sc.Status = "published"
		_, _ = s.DB.SnapshotScriptVersion(sc, "publish", a.Username)
	}
	if err := s.DB.UpdateScriptStatus(id, req.Status, a.Username); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "script_review", TargetType: "script",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", Detail: req.Status,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "version": sc.Version})
}

func bumpPatchVersion(v string) string {
	var major, minor, patch int
	n, err := fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
	if err != nil || n != 3 {
		return v
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch+1)
}

func (s *Server) updateScriptFlags(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		AllowBatch      *bool `json:"allow_batch"`
		Sensitive       *bool `json:"sensitive"`
		AllowProduction *bool `json:"allow_production"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sc, err := s.DB.GetScript(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	batch, sens, prod := sc.AllowBatch, sc.Sensitive, sc.AllowProduction
	if req.AllowBatch != nil {
		batch = *req.AllowBatch
	}
	if req.Sensitive != nil {
		sens = *req.Sensitive
	}
	if req.AllowProduction != nil {
		prod = *req.AllowProduction
	}
	if err := s.DB.UpdateScriptFlags(id, batch, sens, prod); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "script_flags", TargetType: "script",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
		Detail: fmt.Sprintf("batch=%v sensitive=%v production=%v", batch, sens, prod),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "allow_batch": batch, "sensitive": sens, "allow_production": prod})
}

func (s *Server) updateScriptBody(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	sc, err := s.DB.GetScript(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Category           *string `json:"category"`
		Content            *string `json:"content"`
		RollbackContent    *string `json:"rollback_content"`
		HealthcheckContent *string `json:"healthcheck_content"`
		ParamsSchema       *string `json:"params_schema"`
		RiskLevel          *string `json:"risk_level"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	if sc.Status == "approved" || sc.Status == "published" {
		_, _ = s.DB.SnapshotScriptVersion(sc, "pre-edit", a.Username)
	}
	if req.Category != nil {
		sc.Category = *req.Category
	}
	if req.Content != nil {
		sc.Content = *req.Content
	}
	if req.RollbackContent != nil {
		sc.RollbackContent = *req.RollbackContent
	}
	if req.HealthcheckContent != nil {
		sc.HealthcheckContent = *req.HealthcheckContent
	}
	if req.ParamsSchema != nil {
		sc.ParamsSchema = *req.ParamsSchema
	}
	if req.RiskLevel != nil && *req.RiskLevel != "" {
		sc.RiskLevel = *req.RiskLevel
	}
	if sc.ParamsSchema == "" {
		sc.ParamsSchema = "[]"
	}
	sc.SHA256 = scripts.ContentSHA256(sc.Content)
	// Content/body edits always return the script to draft for re-review.
	sc.Status = "draft"
	if err := s.DB.UpdateScriptBody(sc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "script_update", TargetType: "script",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", Detail: "reset_to_draft",
	})
	c.JSON(http.StatusOK, gin.H{"script": sc, "dangerous": scripts.DangerousPatterns(sc.Content)})
}

func (s *Server) listScriptVersions(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if _, err := s.DB.GetScript(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	list, err := s.DB.ListScriptVersions(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Omit full bodies in list for payload size; include sha/meta only.
	slim := make([]gin.H, 0, len(list))
	for _, v := range list {
		slim = append(slim, gin.H{
			"id": v.ID, "script_id": v.ScriptID, "version": v.Version, "sha256": v.SHA256,
			"status_at_snapshot": v.StatusAtSnapshot, "note": v.Note, "created_by": v.CreatedBy,
			"created_at": v.CreatedAt, "risk_level": v.RiskLevel,
		})
	}
	c.JSON(http.StatusOK, slim)
}

func (s *Server) getScriptVersion(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	vid, _ := strconv.ParseInt(c.Param("vid"), 10, 64)
	v, err := s.DB.GetScriptVersion(id, vid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, v)
}

func (s *Server) restoreScriptVersion(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	vid, _ := strconv.ParseInt(c.Param("vid"), 10, 64)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	sc, err := s.DB.GetScript(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	v, err := s.DB.GetScriptVersion(id, vid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "version not found"})
		return
	}
	a := s.currentAdmin(c)
	if sc.Status == "approved" || sc.Status == "published" {
		_, _ = s.DB.SnapshotScriptVersion(sc, "pre-restore", a.Username)
	}
	sc.Content = v.Content
	sc.RollbackContent = v.RollbackContent
	sc.HealthcheckContent = v.Healthcheck
	sc.ParamsSchema = v.ParamsSchema
	sc.RiskLevel = v.RiskLevel
	sc.SHA256 = scripts.ContentSHA256(sc.Content)
	sc.Status = "draft"
	if err := s.DB.UpdateScriptBody(sc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "script_restore_version", TargetType: "script",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
		Detail: fmt.Sprintf("version_id=%d ver=%s", vid, v.Version),
	})
	c.JSON(http.StatusOK, gin.H{"script": sc, "dangerous": scripts.DangerousPatterns(sc.Content)})
}

func (s *Server) listTasks(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	list, err := s.DB.ListTasksFiltered(c.Query("status"), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) exportTask(c *gin.Context) {
	t, err := s.DB.GetTask(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	items, _ := s.DB.ListTaskItems(t.ID)
	c.Header("Content-Disposition", `attachment; filename="task-`+t.ID+`.json"`)
	c.JSON(http.StatusOK, gin.H{"task": t, "items": items})
}

func (s *Server) getTask(c *gin.Context) {
	t, err := s.DB.GetTask(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	items, _ := s.DB.ListTaskItems(t.ID)
	c.JSON(http.StatusOK, gin.H{"task": t, "items": items})
}

func (s *Server) streamTask(c *gin.Context) {
	id := c.Param("id")
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stream unsupported"})
		return
	}
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	last := ""
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		task, err := s.DB.GetTask(id)
		if err != nil {
			fmt.Fprintf(c.Writer, "event: error\ndata: {\"error\":\"not found\"}\n\n")
			flusher.Flush()
			return
		}
		items, _ := s.DB.ListTaskItems(id)
		payload, _ := json.Marshal(gin.H{"task": task, "items": items})
		cur := string(payload)
		if cur != last {
			fmt.Fprintf(c.Writer, "data: %s\n\n", cur)
			flusher.Flush()
			last = cur
		}
		switch task.Status {
		case "success", "failed", "cancelled", "timeout", "rejected":
			fmt.Fprintf(c.Writer, "event: done\ndata: {}\n\n")
			flusher.Flush()
			return
		}
		select {
		case <-c.Request.Context().Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) createTask(c *gin.Context) {
	var req struct {
		Type                 string  `json:"type" binding:"required"`
		VPSIds               []int64 `json:"vps_ids" binding:"required"`
		RiskLevel            string  `json:"risk_level"`
		DryRun               bool    `json:"dry_run"`
		Concurrency          int     `json:"concurrency"`
		TimeoutSec           int     `json:"timeout_sec"`
		RetryMax             int     `json:"retry_max"`
		CanaryVPSIds         []int64 `json:"canary_vps_ids"`
		RollBatch            int     `json:"roll_batch"`
		FailThreshold        float64 `json:"fail_threshold"`
		OnFail               string  `json:"on_fail"` // pause (default) | continue
		Payload              any     `json:"payload"`
		Confirm              bool    `json:"confirm"`
		ConfirmOutsideWindow bool    `json:"confirm_outside_window"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RiskLevel == "" {
		req.RiskLevel = "medium"
	}
	if req.OnFail != "" && req.OnFail != "pause" && req.OnFail != "continue" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "on_fail must be pause or continue"})
		return
	}
	if (req.Type == "config_backup" || req.Type == "config_restore") && req.RiskLevel != "high" && req.RiskLevel != "critical" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config backup/restore requires high risk"})
		return
	}
	if (req.RiskLevel == "high" || req.RiskLevel == "critical") && !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required for high risk"})
		return
	}
	for _, id := range req.VPSIds {
		v, err := s.DB.GetVPS(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "vps not found", "vps_id": id})
			return
		}
		if req.Type != "scan" {
			if err := store.AllowChange(v.OpMode, req.RiskLevel); err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
				return
			}
		}
		if (req.RiskLevel == "high" || req.RiskLevel == "critical") && !store.InMaintenanceWindow(v.MaintenanceWins, time.Now()) && !req.ConfirmOutsideWindow {
			c.JSON(http.StatusConflict, gin.H{"error": "outside_maintenance_window", "vps": v.Name})
			return
		}
	}
	if req.Type == "script" {
		sid := scriptIDFromPayload(req.Payload)
		if sid <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "script_id required"})
			return
		}
		sc, err := s.DB.GetScript(sid)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "script not found"})
			return
		}
		if err := scripts.CanExecute(sc, false); err != nil {
			// Production check still happens per-VPS at run time; here block drafts.
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		if err := scripts.CanBatch(sc, len(req.VPSIds)); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
	}
	if req.Concurrency <= 0 {
		req.Concurrency = s.Cfg.TaskMaxConc
	}
	if req.FailThreshold == 0 {
		req.FailThreshold = 0.5
	}
	if req.TimeoutSec == 0 {
		req.TimeoutSec = 600
	}
	payloadMap := map[string]any{}
	switch p := req.Payload.(type) {
	case map[string]any:
		for k, v := range p {
			payloadMap[k] = v
		}
	case nil:
	default:
		b, _ := json.Marshal(p)
		_ = json.Unmarshal(b, &payloadMap)
	}
	if req.OnFail == "continue" {
		payloadMap["on_fail"] = "continue"
	} else if _, ok := payloadMap["on_fail"]; !ok {
		payloadMap["on_fail"] = "pause"
	}
	payload, _ := json.Marshal(payloadMap)
	canary, _ := json.Marshal(req.CanaryVPSIds)
	a := s.currentAdmin(c)
	t := &store.Task{
		ID: uuid.NewString(), Type: req.Type, Status: store.InitialTaskStatus(req.Type, req.RiskLevel, req.DryRun), RiskLevel: req.RiskLevel,
		DryRun: req.DryRun, Concurrency: req.Concurrency, TimeoutSec: req.TimeoutSec,
		RetryMax: req.RetryMax, CanaryVPSIds: string(canary), RollBatch: req.RollBatch,
		FailThreshold: req.FailThreshold, Payload: string(payload), CreatedBy: a.Username,
	}
	if err := s.DB.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, id := range req.VPSIds {
		_, _ = s.DB.CreateTaskItem(t.ID, id)
	}
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "task_create", TargetType: "task",
		TargetID: t.ID, RiskLevel: req.RiskLevel, TaskID: t.ID,
		Detail: fmt.Sprintf("type=%s targets=%d dry_run=%v", req.Type, len(req.VPSIds), req.DryRun),
	})
	c.JSON(http.StatusOK, t)
}

func (s *Server) cancelTask(c *gin.Context) {
	s.Worker.Cancel(c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) approveTask(c *gin.Context) {
	var req struct {
		Confirm                bool `json:"confirm"`
		ConfirmDanger          bool `json:"confirm_danger"`
		ConfirmDisablePassword bool `json:"confirm_disable_password"`
		ConfirmOutsideWindow   bool `json:"confirm_outside_window"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	id := c.Param("id")
	t, err := s.DB.GetTask(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if t.Status != "waiting_approval" {
		c.JSON(http.StatusConflict, gin.H{"error": "not waiting approval"})
		return
	}
	items, err := s.DB.ListTaskItems(id)
	if err != nil || len(items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no targets"})
		return
	}
	requires := payloadRequires(t.Payload)
	now := time.Now()
	for _, it := range items {
		v, err := s.DB.GetVPS(it.VPSID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "vps not found", "vps_id": it.VPSID})
			return
		}
		risk := t.RiskLevel
		if t.Type == "config_backup" || t.Type == "config_restore" {
			risk = "high"
		}
		if err := store.CheckApproval(v, t.Type, risk, requires, req.Confirm, req.ConfirmDanger, req.ConfirmDisablePassword, req.ConfirmOutsideWindow, now); err != nil {
			writeApprovalErr(c, err, v.Name)
			return
		}
	}
	if err := s.DB.UpdateTaskStatus(id, "pending"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "task_approve", TargetType: "task",
		TargetID: id, RiskLevel: t.RiskLevel, TaskID: id, Detail: "status=pending",
	})
	t.Status = "pending"
	c.JSON(http.StatusOK, t)
}

func (s *Server) rejectTask(c *gin.Context) {
	id := c.Param("id")
	t, err := s.DB.GetTask(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := s.DB.RejectWaitingTask(id); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "task_reject", TargetType: "task",
		TargetID: id, RiskLevel: t.RiskLevel, TaskID: id, Detail: "status=rejected",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": "rejected"})
}

func payloadRequires(raw string) []string {
	var p struct {
		Requires []string `json:"requires"`
	}
	_ = json.Unmarshal([]byte(raw), &p)
	return p.Requires
}

func writeApprovalErr(c *gin.Context, err error, name string) {
	switch {
	case errors.Is(err, store.ErrOpMode):
		c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": name})
	case errors.Is(err, store.ErrOutsideWindow):
		c.JSON(http.StatusConflict, gin.H{"error": "outside_maintenance_window", "vps": name})
	case errors.Is(err, store.ErrDangerConfirm), errors.Is(err, store.ErrConfirmRequired):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

func (s *Server) retryFailed(c *gin.Context) {
	oldID := c.Param("id")
	old, err := s.DB.GetTask(oldID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	items, _ := s.DB.ListTaskItems(oldID)
	var ids []int64
	for _, it := range items {
		if it.Status == "failed" || it.Status == "timeout" {
			ids = append(ids, it.VPSID)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no failed items"})
		return
	}
	a := s.currentAdmin(c)
	t := &store.Task{
		ID: uuid.NewString(), Type: old.Type, Status: store.InitialTaskStatus(old.Type, old.RiskLevel, old.DryRun), RiskLevel: old.RiskLevel,
		DryRun: old.DryRun, Concurrency: old.Concurrency, TimeoutSec: old.TimeoutSec,
		RetryMax: old.RetryMax, CanaryVPSIds: "[]", RollBatch: old.RollBatch,
		FailThreshold: old.FailThreshold, Payload: old.Payload, CreatedBy: a.Username,
	}
	_ = s.DB.CreateTask(t)
	for _, id := range ids {
		_, _ = s.DB.CreateTaskItem(t.ID, id)
	}
	c.JSON(http.StatusOK, t)
}

func (s *Server) listModules(c *gin.Context) {
	c.JSON(http.StatusOK, services.ListModules())
}

func (s *Server) serviceImpact(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		name = c.Query("on")
	}
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	deps := c.Query("dependencies")
	if deps != "" {
		c.JSON(http.StatusOK, services.TemplateImpact(name, deps))
		return
	}
	c.JSON(http.StatusOK, services.ServiceImpact(name))
}

func (s *Server) importScript(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		Content  string `json:"content" binding:"required"`
		Category string `json:"category"`
		Source   string `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Category == "" {
		req.Category = "imported"
	}
	src := req.Source
	if src == "" {
		src = "import"
	}
	a := s.currentAdmin(c)
	sc := store.Script{
		Name: req.Name, Content: req.Content, Category: req.Category,
		Source: src, Status: "draft", RiskLevel: "medium", Version: "1.0.0",
		CreatedBy: a.Username, OSFilter: "[]", ParamsSchema: "[]",
	}
	sc.SHA256 = scripts.ContentSHA256(sc.Content)
	id, err := s.DB.CreateScript(&sc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	sc.ID = id
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "script_import", TargetType: "script",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "medium", Detail: "sha256=" + sc.SHA256,
	})
	c.JSON(http.StatusOK, gin.H{
		"script":    sc,
		"sha256":    sc.SHA256,
		"dangerous": scripts.DangerousPatterns(sc.Content),
		"note":      "imported as draft; review and approve before execute",
	})
}

func (s *Server) upgradePlan(c *gin.Context) {
	var req struct {
		Module      string `json:"module" binding:"required"`
		Version     string `json:"version" binding:"required"`
		SHA256      string `json:"sha256" binding:"required"`
		DownloadURL string `json:"download_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := services.UpgradePlan(req.Module, req.Version, req.SHA256, req.DownloadURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plan": plan})
}

func (s *Server) listAlerts(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	unacked := c.Query("acknowledged") == "0" || c.Query("open") == "1"
	list, err := s.DB.ListAlertsFiltered(store.AlertListFilter{UnackedOnly: unacked, Limit: limit})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) panelBackup(c *gin.Context) {
	b, err := s.Backup.CreatePanelBackup()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{Actor: a.Username, IP: c.ClientIP(), Action: "panel_backup", RiskLevel: "high"})
	c.JSON(http.StatusOK, b)
}

func (s *Server) downloadBackup(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	f, b, err := s.Backup.OpenLocal(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "backup_download", TargetType: "backup",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", Detail: b.Name,
	})
	c.Header("Content-Disposition", `attachment; filename="`+b.Name+`"`)
	c.DataFromReader(http.StatusOK, st.Size(), "application/octet-stream", f, nil)
}

func (s *Server) listBackups(c *gin.Context) {
	list, err := s.DB.ListBackups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) deleteBackup(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	b, err := s.Backup.DeleteLocal(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "backup_delete", TargetType: "backup",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", Detail: b.Name,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) restoreBackup(c *gin.Context) {
	var req struct {
		ID      int64  `json:"id"`
		Path    string `json:"path"`
		Confirm bool   `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	path := req.Path
	if req.ID > 0 {
		b, err := s.DB.GetBackup(req.ID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "backup not found"})
			return
		}
		path = b.Path
	}
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id or path required"})
		return
	}
	if err := s.Backup.RestorePanelBackup(path); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "panel_restore", RiskLevel: "critical",
		TargetType: "backup", TargetID: strconv.FormatInt(req.ID, 10), Detail: path,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "note": "wrote vpshub.db.restored — stop panel, run: vpshub restore-db -yes"})
}

func (s *Server) listTokens(c *gin.Context) {
	list, err := s.DB.ListAPITokens()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) createToken(c *gin.Context) {
	var req struct {
		Name      string `json:"name" binding:"required"`
		Scopes    string `json:"scopes"`
		ExpiresIn int    `json:"expires_in_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	raw, err := crypto.RandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var exp *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Hour)
		exp = &t
	}
	if req.Scopes == "" {
		req.Scopes = `["*"]`
	}
	id, err := s.DB.CreateAPIToken(req.Name, hashToken(raw), req.Scopes, exp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "api_token_create", TargetType: "token",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
	})
	c.JSON(http.StatusOK, gin.H{"id": id, "token": raw, "note": "store token now; it will not be shown again"})
}

func (s *Server) revokeToken(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	_ = s.DB.RevokeAPIToken(id)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "api_token_revoke", TargetType: "token",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) features(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"webssh_enabled":   s.Cfg.WebSSHEnabled,
		"sftp_enabled":     s.Cfg.SFTPEnabled,
		"ssh_max_per_host": s.Cfg.SSHMaxPerHost,
		"ssh_max_output":   s.Cfg.SSHMaxOutput,
		"task_max_conc":    s.Cfg.TaskMaxConc,
		"task_prod_conc":   s.Cfg.TaskProdConc,
		"listen":           s.Cfg.Listen,
		"ip_whitelist_on":  len(s.Cfg.IPWhitelist) > 0,
		"ip_whitelist_n":   len(s.Cfg.IPWhitelist),
		"alert_webhook":    s.Cfg.AlertWebhook != "",
		"alert_telegram":   s.Cfg.AlertTelegram != "" && s.Cfg.AlertChatID != "",
		"alert_smtp":       s.Cfg.SMTPHost != "" && s.Cfg.SMTPFrom != "",
		"vault_lock_ttl":   s.Cfg.VaultLockTTL.String(),
		"version":          Version,
		"ai_enabled":       s.AI != nil && s.AI.Enabled(),
	})
}

func (s *Server) BindTaskSSH() {
	s.Worker.BindSSHRunner(func(ctx context.Context, item *store.TaskItem, task *store.Task, vps *store.VPS) (string, error) {
		opts, err := s.connectOpts(vps)
		if err != nil {
			return "", err
		}
		if task.Type == "scan" {
			res, err := s.Collector.Scan(ctx, opts, vps.ID, s.Fingerprints)
			crypto.Wipe(opts.PrivateKey)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(res)
			_ = s.DB.AppendTaskItemLog(item.ID, string(b))
			return "scanned", nil
		}
		var payload map[string]any
		_ = json.Unmarshal([]byte(task.Payload), &payload)
		cmd, _ := payload["command"].(string)
		var script *store.Script
		env := map[string]string{}
		if task.Type == "script" {
			sid, _ := payload["script_id"].(float64)
			sc, err := s.DB.GetScript(int64(sid))
			if err != nil {
				return "", err
			}
			if err := scripts.CanExecute(sc, vps.Environment == "production"); err != nil {
				return "", err
			}
			rawParams := map[string]string{}
			if e, ok := payload["params"].(map[string]any); ok {
				for k, v := range e {
					rawParams[k] = fmt.Sprint(v)
				}
			} else if e, ok := payload["env"].(map[string]any); ok {
				// Legacy field: still filtered through params_schema.
				for k, v := range e {
					rawParams[k] = fmt.Sprint(v)
				}
			}
			env, err = scripts.BuildScriptEnv(sc.ParamsSchema, rawParams)
			if err != nil {
				return "", err
			}
			script = sc
			cmd = scripts.WrapWithEnv(sc.Content, env)
		}
		wantReboot := false
		if task.Type == "sysupgrade" {
			pm, _ := payload["package_manager"].(string)
			scope, _ := payload["scope"].(string)
			reboot, _ := payload["reboot"].(bool)
			if vps.Environment == "production" {
				reboot = false
			}
			wantReboot = reboot && !task.DryRun
			plan, err := services.SysUpgradePlan(pm, scope, reboot, task.DryRun)
			if err != nil {
				return "", err
			}
			cmd = plan
		}
		if task.Type == "upgrade" {
			mod, _ := payload["module"].(string)
			ver, _ := payload["version"].(string)
			sum, _ := payload["sha256"].(string)
			url, _ := payload["download_url"].(string)
			plan, err := services.UpgradePlan(mod, ver, sum, url)
			if err != nil {
				return "", err
			}
			cmd = plan
			if task.DryRun {
				_ = s.DB.AppendTaskItemLog(item.ID, "[dry-run]\n"+cmd)
				crypto.Wipe(opts.PrivateKey)
				return "dry-run", nil
			}
		}
		if task.Type == "config_backup" {
			extra := pathsFromPayload(payload)
			plan, err := backup.ConfigBackupPlanWith(extra, task.DryRun)
			if err != nil {
				crypto.Wipe(opts.PrivateKey)
				return "", err
			}
			cmd = plan
		}
		if task.Type == "config_restore" {
			stamp, _ := payload["stamp"].(string)
			extra := pathsFromPayload(payload)
			plan, err := backup.ConfigRestorePlanWith(stamp, extra, task.DryRun)
			if err != nil {
				crypto.Wipe(opts.PrivateKey)
				return "", err
			}
			cmd = plan
		}
		if cmd == "" {
			crypto.Wipe(opts.PrivateKey)
			return "", fmt.Errorf("empty command")
		}
		if task.DryRun && task.Type != "sysupgrade" {
			msg := "[dry-run] " + cmd
			_ = s.DB.AppendTaskItemLog(item.ID, msg)
			crypto.Wipe(opts.PrivateKey)
			return msg, nil
		}
		snap := !task.DryRun && (task.Type == "upgrade" || task.Type == "sysupgrade")
		if snap {
			s.captureScan(ctx, item, task, vps, opts, "before")
		}
		out, stderr, _, err := s.SSH.Run(ctx, opts, cmd)
		if script != nil && script.Sensitive {
			_ = s.DB.AppendTaskItemLog(item.ID, "[sensitive output redacted]")
			if stderr != "" {
				_ = s.DB.AppendTaskItemLog(item.ID, "[sensitive stderr redacted]")
			}
		} else {
			_ = s.DB.AppendTaskItemLog(item.ID, out)
			if stderr != "" {
				_ = s.DB.AppendTaskItemLog(item.ID, "STDERR: "+stderr)
			}
		}
		if wantReboot {
			err = s.afterReboot(ctx, item, opts, err)
		}
		if err == nil && script != nil && strings.TrimSpace(script.HealthcheckContent) != "" {
			hout, hstderr, _, herr := s.SSH.Run(ctx, opts, scripts.WrapWithEnv(script.HealthcheckContent, env))
			if script.Sensitive {
				_ = s.DB.AppendTaskItemLog(item.ID, "=== health ===\n[sensitive output redacted]")
			} else {
				_ = s.DB.AppendTaskItemLog(item.ID, "=== health ===\n"+hout)
				if hstderr != "" {
					_ = s.DB.AppendTaskItemLog(item.ID, "STDERR: "+hstderr)
				}
			}
			if herr != nil && strings.TrimSpace(script.RollbackContent) != "" {
				rout, rstderr, _, rerr := s.SSH.Run(ctx, opts, scripts.WrapWithEnv(script.RollbackContent, env))
				if script.Sensitive {
					_ = s.DB.AppendTaskItemLog(item.ID, "=== rollback ===\n[sensitive output redacted]")
				} else {
					_ = s.DB.AppendTaskItemLog(item.ID, "=== rollback ===\n"+rout)
					if rstderr != "" {
						_ = s.DB.AppendTaskItemLog(item.ID, "STDERR: "+rstderr)
					}
				}
				if rerr != nil {
					_ = s.DB.AppendTaskItemLog(item.ID, "rollback failed: "+rerr.Error())
				}
			}
			if herr != nil {
				err = fmt.Errorf("healthcheck failed: %w", herr)
			}
		}
		if snap {
			s.captureScan(ctx, item, task, vps, opts, "after")
		}
		crypto.Wipe(opts.PrivateKey)
		if err != nil {
			return "", err
		}
		if script != nil && script.Sensitive {
			return "[sensitive output redacted]", nil
		}
		return out, nil
	})
}

func (s *Server) afterReboot(ctx context.Context, item *store.TaskItem, opts sshx.ConnectOpts, runErr error) error {
	dropped := runErr != nil && !sshx.RemoteExit(runErr)
	if runErr != nil && !dropped {
		return runErr
	}
	if dropped {
		_ = s.DB.AppendTaskItemLog(item.ID, "ssh dropped after reboot request")
	} else {
		werr := sshx.WaitTCP(ctx, opts.Host, opts.Port, false, 90*time.Second)
		if errors.Is(werr, sshx.ErrStillUp) {
			_ = s.DB.AppendTaskItemLog(item.ID, "ssh stayed up; reboot was not required")
			return nil
		}
		if werr != nil {
			return werr
		}
		_ = s.DB.AppendTaskItemLog(item.ID, "ssh dropped, waiting for it to return")
		dropped = true
	}
	if dropped {
		if werr := sshx.WaitTCP(ctx, opts.Host, opts.Port, true, 3*time.Minute); werr != nil {
			return werr
		}
		_ = s.DB.AppendTaskItemLog(item.ID, "ssh port is back")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

func pathsFromPayload(payload map[string]any) []string {
	raw, ok := payload["paths"]
	if !ok {
		return nil
	}
	var out []string
	switch v := raw.(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}

func (s *Server) captureScan(ctx context.Context, item *store.TaskItem, task *store.Task, vps *store.VPS, opts sshx.ConnectOpts, phase string) {
	res, err := s.Collector.Scan(ctx, opts, vps.ID, s.Fingerprints)
	var payload []byte
	if err != nil {
		_ = s.DB.AppendTaskItemLog(item.ID, phase+" scan failed: "+err.Error())
		payload, _ = json.Marshal(map[string]string{"error": err.Error()})
	} else {
		payload, _ = json.Marshal(res)
	}
	if err := s.DB.SaveSnapshot(vps.ID, task.ID, phase, string(payload)); err != nil {
		_ = s.DB.AppendTaskItemLog(item.ID, phase+" snapshot failed: "+err.Error())
	}
}
