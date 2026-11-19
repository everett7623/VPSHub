package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/store"
	"github.com/gin-gonic/gin"
)

type checkupFinding struct {
	ID       string `json:"id"`
	Area     string `json:"area"` // monitor|cleanup|upgrade|optimize|security
	Severity string `json:"severity"` // info|warning|critical
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Action   string `json:"action,omitempty"` // script name, sysupgrade, scan, …
}

func (s *Server) vpsCheckup(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := s.DB.GetVPS(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	payloadRaw, err := s.DB.LatestScan(id)
	hasScan := err == nil && payloadRaw != ""
	var payload map[string]any
	if hasScan {
		_ = json.Unmarshal([]byte(payloadRaw), &payload)
	}
	var scannedAt string
	if scans, e := s.DB.ListScans(id, 1); e == nil && len(scans) > 0 {
		scannedAt = scans[0].CreatedAt.UTC().Format(time.RFC3339)
	}
	findings := buildCheckup(v, payload, hasScan)
	c.JSON(http.StatusOK, gin.H{
		"vps_id":     id,
		"name":       v.Name,
		"scanned_at": scannedAt,
		"findings":   findings,
		"ai_enabled": s.AI != nil && s.AI.Enabled(),
		"areas":      []string{"monitor", "cleanup", "upgrade", "optimize", "security"},
	})
}

func buildCheckup(v *store.VPS, p map[string]any, hasScan bool) []checkupFinding {
	var out []checkupFinding
	str := func(k string) string {
		if p == nil {
			return ""
		}
		if x, ok := p[k]; ok && x != nil {
			return fmt.Sprint(x)
		}
		return ""
	}
	num := func(k string) float64 {
		if p == nil {
			return 0
		}
		switch x := p[k].(type) {
		case float64:
			return x
		case json.Number:
			f, _ := x.Float64()
			return f
		default:
			return 0
		}
	}
	truthy := func(k string) bool {
		s := strings.ToLower(str(k))
		return s == "true" || s == "1" || s == "yes"
	}

	if !hasScan {
		out = append(out, checkupFinding{
			ID: "no_scan", Area: "monitor", Severity: "warning",
			Title: "尚未扫描", Detail: "先跑一次 Scan 采集系统与服务信息", Action: "scan",
		})
		return out
	}

	if truthy("need_reboot") {
		out = append(out, checkupFinding{
			ID: "need_reboot", Area: "upgrade", Severity: "warning",
			Title: "需要重启", Detail: "内核或关键包已更新，建议维护窗口内 reboot", Action: "reboot-required",
		})
	}
	if n := num("security_updates"); n >= 1 {
		sev := "warning"
		if n >= 10 {
			sev = "critical"
		}
		out = append(out, checkupFinding{
			ID: "security_updates", Area: "upgrade", Severity: sev,
			Title:  fmt.Sprintf("安全更新待装：%.0f", n),
			Detail: "建议先 sysupgrade 演练（scope=security）再实跑", Action: "sysupgrade_security",
		})
	}
	if cert := num("cert_not_after"); cert > 0 {
		days := (cert*1000 - float64(time.Now().UnixMilli())) / 86400000
		if days <= 14 {
			sev := "warning"
			if days <= 3 {
				sev = "critical"
			}
			out = append(out, checkupFinding{
				ID: "cert_expiring", Area: "security", Severity: sev,
				Title:  fmt.Sprintf("证书约 %.0f 天后到期", days),
				Detail: "检查 nginx/caddy/letsencrypt 续期", Action: "cert-files-present",
			})
		}
	}
	if failed := str("systemd_failed"); failed != "" && failed != "null" {
		out = append(out, checkupFinding{
			ID: "systemd_failed", Area: "monitor", Severity: "critical",
			Title: "存在失败的 systemd 单元", Detail: truncateRunes(failed, 200), Action: "failed-units",
		})
	}
	disk := num("disk_used_pct")
	if disk == 0 {
		disk = num("disk_percent")
	}
	if disk >= 85 {
		sev := "warning"
		if disk >= 95 {
			sev = "critical"
		}
		out = append(out, checkupFinding{
			ID: "disk_high", Area: "cleanup", Severity: sev,
			Title:  fmt.Sprintf("磁盘使用率约 %.0f%%", disk),
			Detail: "可先跑 large-files-tmp / docker-prune-dry / journal-vacuum（审核后）", Action: "disk-report",
		})
	}
	if str("docker_version") != "" {
		out = append(out, checkupFinding{
			ID: "docker_present", Area: "cleanup", Severity: "info",
			Title: "已安装 Docker", Detail: "可用 docker-prune-dry 查看可回收空间", Action: "docker-prune-dry",
		})
	}
	load := str("loadavg")
	if load != "" {
		out = append(out, checkupFinding{
			ID: "load", Area: "monitor", Severity: "info",
			Title: "负载 " + load, Detail: "异常时可跑 process-top", Action: "process-top",
		})
	}
	out = append(out, checkupFinding{
		ID: "security_baseline", Area: "security", Severity: "info",
		Title: "建议跑安全基线检查", Detail: "sshd / 防火墙 / fail2ban / 自动更新", Action: "security-baseline",
	})
	out = append(out, checkupFinding{
		ID: "auth_log", Area: "security", Severity: "info",
		Title: "查看近期登录失败", Detail: "auth-log-tail（只读）", Action: "auth-log-tail",
	})
	out = append(out, checkupFinding{
		ID: "optimize", Area: "optimize", Severity: "info",
		Title: "网络调优只读检查", Detail: "sysctl-network-tune-check（不改配置）", Action: "sysctl-network-tune-check",
	})
	if v.Environment == "production" && v.OpMode == "high_risk_allowed" {
		out = append(out, checkupFinding{
			ID: "prod_high_risk", Area: "security", Severity: "warning",
			Title: "生产机允许高风险操作", Detail: "确认维护窗口与 op_mode 是否仍需要 high_risk_allowed",
		})
	}
	return out
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (s *Server) aiAdvise(c *gin.Context) {
	if s.AI == nil || !s.AI.Enabled() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ai_disabled", "hint": "set ai_enabled + ai_api_key in config.yaml"})
		return
	}
	var req struct {
		VPSID  int64  `json:"vps_id" binding:"required"`
		Prompt string `json:"prompt"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v, err := s.DB.GetVPS(req.VPSID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vps not found"})
		return
	}
	scanJSON, _ := s.DB.LatestScan(req.VPSID)
	var payload map[string]any
	hasScan := scanJSON != ""
	if hasScan {
		_ = json.Unmarshal([]byte(scanJSON), &payload)
	}
	findings := buildCheckup(v, payload, hasScan)
	fb, _ := json.Marshal(findings)
	system := `你是 VPSHub 运维助手。根据给定的扫描摘要与体检条目，用简洁中文给出：
1) 优先处理的 3–7 条建议（监控/清理/升级/优化/安全）
2) 每条对应可在面板执行的动作名（scan、sysupgrade_security、或内置脚本名如 docker-prune-dry）
3) 明确哪些需要人工确认、哪些只读
禁止声称已经执行了任何命令；禁止提供攻击利用步骤。`
	user := fmt.Sprintf("VPS: %s (env=%s op_mode=%s)\nFindings JSON:\n%s\n\nScan JSON (truncated):\n%s\n\nOperator question: %s",
		v.Name, v.Environment, v.OpMode, string(fb), truncateRunes(scanJSON, 6000), strings.TrimSpace(req.Prompt))
	if req.Prompt == "" {
		user += "请给出常规运维与安全建议。"
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 75*time.Second)
	defer cancel()
	advice, err := s.AI.Advise(ctx, system, user)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	a := s.currentAdmin(c)
	_ = s.DB.AppendAudit(store.AuditInput{
		Actor: a.Username, IP: c.ClientIP(), Action: "ai_advise",
		TargetType: "vps", TargetID: strconv.FormatInt(req.VPSID, 10), RiskLevel: "low",
	})
	c.JSON(http.StatusOK, gin.H{"advice": advice, "model": s.AI.Cfg.Model})
}
