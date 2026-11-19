package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

func withAuthRoutes(s *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("admin", &store.Admin{ID: 1, Username: "tester"})
		c.Next()
	})
	r.POST("/api/locks/clear-all", s.clearAllLocks)
	r.GET("/api/vps", s.listVPS)
	return r
}

func TestClearAllLocksHTTP(t *testing.T) {
	s, db := testAPIServer(t)
	until := time.Now().Add(time.Hour)
	_ = db.SetLock("ip:9.9.9.9", until, "fail")
	r := withAuthRoutes(s)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/locks/clear-all", bytes.NewReader([]byte(`{}`))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no confirm: code=%d", rec.Code)
	}

	body, _ := json.Marshal(map[string]any{"confirm": true})
	req := httptest.NewRequest(http.MethodPost, "/api/locks/clear-all", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["cleared"] != float64(1) {
		t.Fatalf("cleared=%v", out["cleared"])
	}
}

func TestListVPSProviderIDHTTP(t *testing.T) {
	s, db := testAPIServer(t)
	p1, err := db.CreateProvider(&store.Provider{Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := db.CreateProvider(&store.Provider{Name: "B"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateVPS(&store.VPS{
		Name: "va", Host: "10.1.1.1", SSHUser: "ops", OpMode: "normal_tasks",
		Tags: "[]", MaintenanceWins: "[]", Environment: "testing", ProviderID: &p1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateVPS(&store.VPS{
		Name: "vb", Host: "10.1.1.2", SSHUser: "ops", OpMode: "normal_tasks",
		Tags: "[]", MaintenanceWins: "[]", Environment: "testing", ProviderID: &p2,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := withAuthRoutes(s)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/vps?provider_id="+itoa64(p1), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["name"] != "va" {
		t.Fatalf("list=%v", list)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
