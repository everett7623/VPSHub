package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/evenfrank/vpshub/internal/collector"
	"github.com/evenfrank/vpshub/internal/docker"
	"github.com/evenfrank/vpshub/internal/services"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/evenfrank/vpshub/internal/systemd"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Server) scanDiff(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	scans, err := s.DB.ListScans(id, 2)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(scans) < 2 {
		c.JSON(http.StatusOK, gin.H{"changes": []collector.FieldChange{}, "note": "need two scans"})
		return
	}
	changes, err := collector.DiffPayloads(scans[1].Payload, scans[0].Payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if changes == nil {
		changes = []collector.FieldChange{}
	}
	c.JSON(http.StatusOK, gin.H{
		"changes": changes,
		"before":  scans[1].CreatedAt,
		"after":   scans[0].CreatedAt,
	})
}

func (s *Server) listTemplates(c *gin.Context) {
	list, err := s.DB.ListTemplates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if list == nil {
		list = []store.ServiceTemplate{}
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) createTemplate(c *gin.Context) {
	t, ok := bindTemplate(c)
	if !ok {
		return
	}
	id, err := s.DB.CreateTemplate(t)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	t.ID = id
	c.JSON(http.StatusOK, t)
}

func (s *Server) updateTemplate(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	t, ok := bindTemplate(c)
	if !ok {
		return
	}
	t.ID = id
	if err := s.DB.UpdateTemplate(t); err != nil {
		code := http.StatusBadRequest
		if err == store.ErrNotFound {
			code = http.StatusNotFound
		}
		c.JSON(code, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, t)
}

func (s *Server) deleteTemplate(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := s.DB.DeleteTemplate(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) listTemplateVPS(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	list, err := s.DB.ListTemplateVPS(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if list == nil {
		list = []store.TemplateVPSRef{}
	}
	c.JSON(http.StatusOK, list)
}

func bindTemplate(c *gin.Context) (*store.ServiceTemplate, bool) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		ServiceType  string `json:"service_type" binding:"required"`
		Healthcheck  string `json:"healthcheck"`
		Dependencies string `json:"dependencies"`
		ConfigPaths  string `json:"config_paths"`
		RiskLevel    string `json:"risk_level"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, false
	}
	deps := req.Dependencies
	if deps == "" {
		deps = "[]"
	}
	if !json.Valid([]byte(deps)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "dependencies must be a JSON array"})
		return nil, false
	}
	paths := req.ConfigPaths
	if paths == "" {
		paths = "[]"
	}
	if !json.Valid([]byte(paths)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_paths must be a JSON array"})
		return nil, false
	}
	return &store.ServiceTemplate{
		Name: req.Name, ServiceType: req.ServiceType, Healthcheck: req.Healthcheck,
		Dependencies: deps, RiskLevel: req.RiskLevel, ConfigPaths: paths, Meta: "{}",
	}, true
}

func (s *Server) vpsExpectations(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	assigned, err := s.DB.ListExpectationTemplates(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if assigned == nil {
		assigned = []store.ServiceTemplate{}
	}
	inv, err := s.DB.ListServiceInventory(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	status := map[string]string{}
	for _, row := range inv {
		status[row.ServiceType] = row.Status
	}
	type gap struct {
		TemplateID   int64    `json:"template_id"`
		Template     string   `json:"template"`
		ServiceType  string   `json:"service_type"`
		Actual       string   `json:"actual"`
		Dependencies string   `json:"dependencies"`
		ConfigPaths  string   `json:"config_paths,omitempty"`
		DependsOn    []string `json:"depends_on"`
		DependedOnBy []string `json:"depended_on_by"`
	}
	var gaps []gap
	for _, t := range assigned {
		actual := status[t.ServiceType]
		if actual == "" {
			actual = "missing"
		}
		if actual != "running" {
			imp := services.TemplateImpact(t.ServiceType, t.Dependencies)
			gaps = append(gaps, gap{
				TemplateID: t.ID, Template: t.Name, ServiceType: t.ServiceType,
				Actual: actual, Dependencies: t.Dependencies, ConfigPaths: t.ConfigPaths,
				DependsOn: imp.DependsOn, DependedOnBy: imp.DependedOnBy,
			})
		}
	}
	if gaps == nil {
		gaps = []gap{}
	}
	c.JSON(http.StatusOK, gin.H{"assigned": assigned, "gaps": gaps})
}

func (s *Server) setVPSExpectations(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		TemplateIDs []int64 `json:"template_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := s.DB.GetVPS(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := s.DB.SetExpectations(id, req.TemplateIDs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) hostLogs(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Kind  string `json:"kind" binding:"required"`
		Name  string `json:"name" binding:"required"`
		Lines int    `json:"lines"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Lines <= 0 || req.Lines > 500 {
		req.Lines = 200
	}
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var cmd string
	switch req.Kind {
	case "docker":
		cmd, err = docker.ContainerLogsCmd(req.Name, req.Lines)
	case "systemd":
		cmd, err = systemd.UnitLogsCmd(req.Name, req.Lines)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "kind must be docker or systemd"})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	opts, err := s.connectOpts(v)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, stderr, _, err := s.SSH.Run(c.Request.Context(), opts, cmd)
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "log_view", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "low", Detail: req.Kind + " " + req.Name,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if stderr != "" {
		out += "\n" + stderr
	}
	c.JSON(http.StatusOK, gin.H{"output": out})
}

func (s *Server) disablePasswordAuth(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Confirm                bool `json:"confirm"`
		ConfirmDisablePassword bool `json:"confirm_disable_password"`
		ConfirmOutsideWindow   bool `json:"confirm_outside_window"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !req.Confirm || !req.ConfirmDisablePassword {
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
	if !store.InMaintenanceWindow(v.MaintenanceWins, time.Now()) && !req.ConfirmOutsideWindow {
		c.JSON(http.StatusConflict, gin.H{"error": "outside_maintenance_window", "vps": v.Name})
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"command":  services.DisablePasswordPlan(),
		"requires": []string{"confirm_disable_password"},
	})
	a := s.currentAdmin(c)
	t := &store.Task{
		ID: uuid.NewString(), Type: "shell", Status: store.InitialTaskStatus("shell", "critical", false), RiskLevel: "critical",
		Concurrency: 1, TimeoutSec: 120, CanaryVPSIds: "[]", FailThreshold: 1,
		Payload: string(payload), CreatedBy: a.Username,
	}
	if err := s.DB.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.DB.CreateTaskItem(t.ID, id)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "sshd_disable_password", TargetType: "vps",
		TargetID: strconv.FormatInt(id, 10), RiskLevel: "critical", TaskID: t.ID,
	})
	c.JSON(http.StatusOK, t)
}
