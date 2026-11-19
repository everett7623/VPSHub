package api

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/evenfrank/vpshub/internal/collector"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Server) exportVPS(c *gin.Context) {
	list, err := s.DB.ListVPS(store.VPSFilter{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="vpshub-vps.csv"`)
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{
		"name", "host", "ssh_port", "ssh_user", "auth_method", "environment", "op_mode", "group_name",
		"status", "provider", "region", "socks_proxy", "tags", "expires_at", "purchase_date",
		"monthly_cost", "purchase_price", "currency", "auto_renewal", "renewal_cycle", "server_type",
		"cpu_cores", "ram_gb", "disk_gb", "panel_type", "panel_url",
		"http_probe_enabled", "http_probe_url", "maintenance_windows", "jump_host_id",
		"bandwidth", "sftp_root", "notes", "ipv4", "ipv6",
	})
	for _, v := range list {
		exp, purchase, cost, price, jump := "", "", "", "", ""
		cpu, ram, disk := "", "", ""
		if v.ExpiresAt != nil {
			exp = *v.ExpiresAt
		}
		if v.PurchaseDate != nil {
			purchase = *v.PurchaseDate
		}
		if v.MonthlyCost != nil {
			cost = strconv.FormatFloat(*v.MonthlyCost, 'f', -1, 64)
		}
		if v.PurchasePrice != nil {
			price = strconv.FormatFloat(*v.PurchasePrice, 'f', -1, 64)
		}
		if v.JumpHostID != nil {
			jump = strconv.FormatInt(*v.JumpHostID, 10)
		}
		if v.CPUCores != nil {
			cpu = strconv.FormatFloat(*v.CPUCores, 'f', -1, 64)
		}
		if v.RAMGB != nil {
			ram = strconv.FormatFloat(*v.RAMGB, 'f', -1, 64)
		}
		if v.DiskGB != nil {
			disk = strconv.FormatFloat(*v.DiskGB, 'f', -1, 64)
		}
		auto := "0"
		if v.AutoRenewal {
			auto = "1"
		}
		probe := "0"
		if v.HTTPProbeEnabled {
			probe = "1"
		}
		_ = w.Write([]string{
			v.Name, v.Host, strconv.Itoa(v.SSHPort), v.SSHUser, v.AuthMethod, v.Environment, v.OpMode,
			v.GroupName, v.Status, v.Provider, v.Region, v.SocksProxy, v.Tags, exp, purchase,
			cost, price, v.Currency, auto, v.RenewalCycle, v.ServerType,
			cpu, ram, disk, v.PanelType, v.PanelURL,
			probe, v.HTTPProbeURL, v.MaintenanceWins, jump,
			v.Bandwidth, v.SFTPRoot, v.Notes, v.IPv4, v.IPv6,
		})
	}
	w.Flush()
}

func (s *Server) batchScan(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 || len(req.IDs) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids required, at most 50"})
		return
	}
	a := s.currentAdmin(c)
	t := &store.Task{
		ID: uuid.NewString(), Type: "scan", Status: "pending", RiskLevel: "low",
		Concurrency: 3, TimeoutSec: 180, CanaryVPSIds: "[]", FailThreshold: 1,
		Payload: "{}", CreatedBy: a.Username,
	}
	if err := s.DB.CreateTask(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, id := range req.IDs {
		if _, err := s.DB.GetVPS(id); err != nil {
			continue
		}
		_, _ = s.DB.CreateTaskItem(t.ID, id)
	}
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "vps_batch_scan", TargetType: "task",
		TargetID: t.ID, RiskLevel: "low",
	})
	c.JSON(http.StatusOK, t)
}

func (s *Server) batchTest(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 || len(req.IDs) > 40 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids required, at most 40"})
		return
	}
	type row struct {
		ID             int64  `json:"id"`
		Name           string `json:"name"`
		OK             bool   `json:"ok"`
		Error          string `json:"error,omitempty"`
		HostKeyPending string `json:"host_key_pending,omitempty"`
		StatusUpdated  string `json:"status_updated,omitempty"`
	}
	out := make([]row, len(req.IDs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, id := range req.IDs {
		wg.Add(1)
		go func(i int, id int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].ID = id
			v, err := s.DB.GetVPS(id)
			if err != nil {
				out[i].Error = "not found"
				return
			}
			out[i].Name = v.Name
			opts, err := s.connectOpts(v)
			if err != nil {
				out[i].Error = err.Error()
				return
			}
			defer crypto.Wipe(opts.PrivateKey)
			var pendingFP string
			opts.OnPending = func(fp string) {
				pendingFP = fp
				_ = s.DB.UpdateVPSHostKey(id, v.HostKeyFP, fp)
			}
			_, _, fp, err := s.SSH.Run(c.Request.Context(), opts, "true")
			if errors.Is(err, sshx.ErrHostKeyUnknown) {
				out[i].Error = "host_key_pending"
				out[i].HostKeyPending = pendingFP
				return
			}
			if errors.Is(err, sshx.ErrHostKeyMismatch) {
				out[i].Error = "host_key_mismatch"
				if s.Alert != nil {
					s.Alert.Emit("host_key_changed", "critical", &id, fmt.Sprintf("Host key changed for %s", v.Name))
				}
				return
			}
			if err != nil {
				_ = s.DB.TouchVPSConnect(id, "offline")
				out[i].StatusUpdated = "offline"
				out[i].Error = err.Error()
				if s.Alert != nil {
					if recent, _ := s.DB.HasRecentAlert(id, "ssh_fail", 6*time.Hour); !recent {
						s.Alert.Emit("ssh_fail", "warning", &id, fmt.Sprintf("SSH failed for %s: %s", v.Name, err.Error()))
					}
				}
				return
			}
			if v.HostKeyFP == "" && fp != "" {
				_ = s.DB.UpdateVPSHostKey(id, fp, "")
			}
			_ = s.DB.TouchVPSConnect(id, "online")
			out[i].StatusUpdated = "online"
			out[i].OK = true
		}(i, id)
	}
	wg.Wait()
	c.JSON(http.StatusOK, gin.H{"results": out})
}

func (s *Server) changeSnapshots(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	snaps, err := s.DB.ListSnapshots(id, 16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	type meta struct {
		ID        int64  `json:"id"`
		TaskID    string `json:"task_id"`
		Phase     string `json:"phase"`
		CreatedAt string `json:"created_at"`
	}
	list := make([]meta, 0, len(snaps))
	for _, sn := range snaps {
		list = append(list, meta{ID: sn.ID, TaskID: sn.TaskID, Phase: sn.Phase, CreatedAt: sn.CreatedAt.Format("2006-01-02 15:04:05")})
	}
	taskID := c.Query("task_id")
	before, after := pairForTask(snaps, taskID)
	var changes []collector.FieldChange
	if before != "" && after != "" {
		changes, _ = collector.DiffPayloads(before, after)
	}
	if changes == nil {
		changes = []collector.FieldChange{}
	}
	c.JSON(http.StatusOK, gin.H{"snapshots": list, "changes": changes, "task_id": taskID})
}

func pairForTask(snaps []store.ChangeSnapshot, taskID string) (before, after string) {
	if taskID == "" {
		return latestPair(snaps)
	}
	for _, sn := range snaps {
		if sn.TaskID != taskID {
			continue
		}
		if sn.Phase == "after" {
			after = sn.Payload
		}
		if sn.Phase == "before" {
			before = sn.Payload
		}
	}
	return before, after
}

func latestPair(snaps []store.ChangeSnapshot) (before, after string) {
	afterTask := ""
	for _, sn := range snaps {
		if sn.Phase == "after" {
			after = sn.Payload
			afterTask = sn.TaskID
			break
		}
	}
	if afterTask == "" {
		return "", ""
	}
	for _, sn := range snaps {
		if sn.Phase == "before" && sn.TaskID == afterTask {
			return sn.Payload, after
		}
	}
	return "", after
}

func (s *Server) ackAlert(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := s.DB.AckAlert(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) ackAllAlerts(c *gin.Context) {
	n, err := s.DB.AckAllAlerts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "acked": n})
}

func (s *Server) verifyAudit(c *gin.Context) {
	ok, err := s.DB.VerifyAuditChain()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": ok})
}
