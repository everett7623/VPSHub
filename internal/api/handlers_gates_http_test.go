package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

func testAPIServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	dir := t.TempDir()
	root, _ := os.Getwd()
	t.Setenv("VPSHUB_MIGRATIONS", filepath.Join(root, "..", "..", "migrations"))
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := &Server{DB: db, Cfg: config.Default()}
	return s, db
}

func withAdmin(s *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("admin", &store.Admin{ID: 1, Username: "tester"})
		c.Next()
	})
	r.POST("/api/tasks", s.createTask)
	r.POST("/api/tasks/:id/approve", s.approveTask)
	return r
}

func TestCreateTaskOpModeBlocksHTTP(t *testing.T) {
	s, db := testAPIServer(t)
	id, err := db.CreateVPS(&store.VPS{
		Name: "ro", Host: "10.0.0.1", SSHUser: "ops", OpMode: "readonly_monitor",
		Tags: "[]", MaintenanceWins: "[]", Environment: "testing",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := withAdmin(s)
	body, _ := json.Marshal(map[string]any{
		"type": "shell", "vps_ids": []int64{id}, "risk_level": "low",
		"confirm": true, "payload": map[string]any{"command": "true"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "op_mode_blocks" || out["vps"] != "ro" {
		t.Fatalf("body=%v", out)
	}
}

func TestCreateTaskOutsideWindowHTTP(t *testing.T) {
	s, db := testAPIServer(t)
	// Only Sunday 03:00-04:00 — request at any other time is outside.
	wins := `[{"weekdays":[0],"start":"03:00","end":"04:00"}]`
	id, err := db.CreateVPS(&store.VPS{
		Name: "win", Host: "10.0.0.2", SSHUser: "ops", OpMode: "high_risk_allowed",
		Tags: "[]", MaintenanceWins: wins, Environment: "testing",
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.InMaintenanceWindow(wins, time.Now().UTC()) {
		t.Skip("currently inside the tiny window")
	}
	r := withAdmin(s)
	body, _ := json.Marshal(map[string]any{
		"type": "shell", "vps_ids": []int64{id}, "risk_level": "high",
		"confirm": true, "payload": map[string]any{"command": "true"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "outside_maintenance_window" || out["vps"] != "win" {
		t.Fatalf("body=%v", out)
	}
}

func TestApproveTaskNotWaitingHTTP(t *testing.T) {
	s, db := testAPIServer(t)
	task := &store.Task{
		ID: "t-pending", Type: "shell", Status: "pending", RiskLevel: "low",
		CanaryVPSIds: "[]", Payload: "{}", Concurrency: 1, TimeoutSec: 30,
	}
	if err := db.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	r := withAdmin(s)
	body, _ := json.Marshal(map[string]any{"confirm": true})
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/t-pending/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict && rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWriteApprovalErrJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/op", func(c *gin.Context) { writeApprovalErr(c, store.ErrOpMode, "x") })
	r.GET("/win", func(c *gin.Context) { writeApprovalErr(c, store.ErrOutsideWindow, "y") })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/op", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/win", nil))
	if rec.Code != http.StatusConflict {
		t.Fatal(rec.Code)
	}
}
