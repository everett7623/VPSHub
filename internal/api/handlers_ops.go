package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/backup"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/docker"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/evenfrank/vpshub/internal/systemd"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Server) dockerAction(c *gin.Context) {
	s.remoteAction(c, "docker")
}

func (s *Server) systemdAction(c *gin.Context) {
	s.remoteAction(c, "systemd")
}

func (s *Server) dockerQuery(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Action string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var cmd string
	switch req.Action {
	case "stats":
		cmd = docker.StatsCmd()
	case "images":
		cmd = docker.ImagesCmd()
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action"})
		return
	}
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
	out, stderr, _, err := s.SSH.Run(c.Request.Context(), opts, cmd)
	crypto.Wipe(opts.PrivateKey)
	if stderr != "" {
		out += "\n" + stderr
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "docker_query", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "low", Detail: req.Action,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "output": out})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": out})
}

func (s *Server) remoteAction(c *gin.Context, kind string) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Action               string `json:"action" binding:"required"`
		Name                 string `json:"name"`
		Confirm              bool   `json:"confirm"`
		ConfirmDanger        bool   `json:"confirm_danger"`
		ConfirmOutsideWindow bool   `json:"confirm_outside_window"`
		DryRun               bool   `json:"dry_run"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	if kind == "docker" && docker.Dangerous(req.Action) && !req.ConfirmDanger {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm_danger required"})
		return
	}
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var cmd, risk string
	switch kind {
	case "docker":
		cmd, risk, err = docker.ActionCmd(req.Action, req.Name, req.DryRun)
	default:
		cmd, err = systemd.UnitActionCmd(req.Action, req.Name)
		risk = "medium"
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := store.AllowChange(v.OpMode, risk); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
		return
	}
	if !store.InMaintenanceWindow(v.MaintenanceWins, time.Now()) && !req.ConfirmOutsideWindow {
		c.JSON(http.StatusConflict, gin.H{"error": "outside_maintenance_window", "vps": v.Name})
		return
	}
	a := s.currentAdmin(c)
	body := map[string]any{"command": cmd}
	if kind == "docker" && docker.Dangerous(req.Action) {
		body["requires"] = []string{"confirm_danger"}
	}
	payload, _ := json.Marshal(body)
	// Compose dry-run embeds a read-only command; leave Task.DryRun false so the worker still SSHes.
	t := &store.Task{
		ID: uuid.NewString(), Type: "shell", Status: store.InitialTaskStatus("shell", risk, false), RiskLevel: risk,
		Concurrency: 1, TimeoutSec: 600, CanaryVPSIds: "[]", FailThreshold: 1,
		Payload: string(payload), CreatedBy: a.Username,
	}
	if err := s.DB.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.DB.CreateTaskItem(t.ID, id)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: kind + "_action", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: risk, TaskID: t.ID, Detail: req.Action + " " + req.Name,
	})
	c.JSON(http.StatusOK, t)
}

func (s *Server) configBackup(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Confirm              bool `json:"confirm"`
		ConfirmOutsideWindow bool `json:"confirm_outside_window"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required"})
		return
	}
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := store.AllowChange(v.OpMode, "high"); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
		return
	}
	if !store.InMaintenanceWindow(v.MaintenanceWins, time.Now()) && !req.ConfirmOutsideWindow {
		c.JSON(http.StatusConflict, gin.H{"error": "outside_maintenance_window", "vps": v.Name})
		return
	}
	extra := s.templateConfigPaths(id)
	paths := backup.MergeConfigPaths(extra)
	if _, err := backup.ConfigBackupPlanWith(extra, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	payload, _ := json.Marshal(map[string]any{"paths": paths})
	a := s.currentAdmin(c)
	t := &store.Task{
		ID: uuid.NewString(), Type: "config_backup", Status: store.InitialTaskStatus("config_backup", "high", false), RiskLevel: "high",
		Concurrency: 1, TimeoutSec: 600, CanaryVPSIds: "[]", FailThreshold: 1,
		Payload: string(payload), CreatedBy: a.Username,
	}
	if err := s.DB.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.DB.CreateTaskItem(t.ID, id)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "config_backup", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", TaskID: t.ID,
		Detail: "paths=" + strings.Join(paths, ","),
	})
	c.JSON(http.StatusOK, t)
}

func (s *Server) templateConfigPaths(vpsID int64) []string {
	tpls, err := s.DB.ListExpectationTemplates(vpsID)
	if err != nil {
		return nil
	}
	var out []string
	for _, t := range tpls {
		var paths []string
		if err := json.Unmarshal([]byte(t.ConfigPaths), &paths); err != nil {
			continue
		}
		out = append(out, paths...)
	}
	return out
}

func (s *Server) configBackupPaths(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if _, err := s.DB.GetVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	extra := s.templateConfigPaths(id)
	paths := backup.MergeConfigPaths(extra)
	c.JSON(http.StatusOK, gin.H{"paths": paths, "from_templates": extra})
}

func (s *Server) configStamps(c *gin.Context) {
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
	out, _, _, err := s.SSH.Run(c.Request.Context(), opts,
		`ls -1 /var/backups/vpshub 2>/dev/null | grep -E '^[0-9]{14}$' | sort -r | head -n 30`)
	crypto.Wipe(opts.PrivateKey)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "stamps": []string{}})
		return
	}
	var stamps []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 14 {
			stamps = append(stamps, line)
		}
	}
	if stamps == nil {
		stamps = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"stamps": stamps})
}

func (s *Server) configRestore(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Stamp                string `json:"stamp"`
		Confirm              bool   `json:"confirm"`
		ConfirmOutsideWindow bool   `json:"confirm_outside_window"`
		DryRun               bool   `json:"dry_run"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm || req.Stamp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "stamp and confirm required"})
		return
	}
	extra := s.templateConfigPaths(id)
	paths := backup.MergeConfigPaths(extra)
	if _, err := backup.ConfigRestorePlanWith(req.Stamp, extra, false); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := store.AllowChange(v.OpMode, "high"); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "op_mode_blocks", "vps": v.Name})
		return
	}
	if !store.InMaintenanceWindow(v.MaintenanceWins, time.Now()) && !req.ConfirmOutsideWindow {
		c.JSON(http.StatusConflict, gin.H{"error": "outside_maintenance_window", "vps": v.Name})
		return
	}
	payload, _ := json.Marshal(map[string]any{"stamp": req.Stamp, "paths": paths})
	a := s.currentAdmin(c)
	t := &store.Task{
		ID: uuid.NewString(), Type: "config_restore", Status: store.InitialTaskStatus("config_restore", "high", req.DryRun), RiskLevel: "high",
		DryRun: req.DryRun, Concurrency: 1, TimeoutSec: 600, CanaryVPSIds: "[]", FailThreshold: 1,
		Payload: string(payload), CreatedBy: a.Username,
	}
	if err := s.DB.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.DB.CreateTaskItem(t.ID, id)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "config_restore", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "high", TaskID: t.ID,
		Detail: "stamp=" + req.Stamp,
	})
	c.JSON(http.StatusOK, t)
}
