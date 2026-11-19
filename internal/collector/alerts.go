package collector

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/docker"
	"github.com/evenfrank/vpshub/internal/store"
)

// Notice is a scan-derived alert before deduplication.
type Notice struct {
	Kind     string
	Severity string
	Message  string
}

// CertExpiryWarnDays alerts when the soonest known certificate expires within this many days.
const CertExpiryWarnDays = 14

// SecurityUpdatesMin alerts when the read-only security-update count reaches this value.
const SecurityUpdatesMin = 1

// Thresholds tunes scan-derived alerts (defaults match historical constants).
type Thresholds struct {
	DiskPct           int
	MemAvailPct       int
	Load1             float64
	SecurityUpdatesMin int64
	CertExpiryWarnDays int
}

func defaultThresholds() Thresholds {
	return Thresholds{
		DiskPct: 90, MemAvailPct: 10, Load1: 0, // Load1 0 = disabled until rule sets it
		SecurityUpdatesMin: SecurityUpdatesMin, CertExpiryWarnDays: CertExpiryWarnDays,
	}
}

// Notices returns threshold alerts for one scan payload.
func Notices(res Result) []Notice {
	return NoticesWith(res, time.Now(), defaultThresholds())
}

func NoticesWith(res Result, now time.Time, th Thresholds) []Notice {
	var out []Notice
	if disk, ok := res["disk"].(string); ok {
		parts := strings.Split(disk, ",")
		if len(parts) >= 4 {
			pct := strings.TrimSuffix(strings.TrimSpace(parts[3]), "%")
			if n, err := strconv.Atoi(pct); err == nil && n >= th.DiskPct {
				out = append(out, Notice{Kind: "disk_high", Severity: "warning", Message: fmt.Sprintf("root filesystem %d%% used", n)})
			}
		}
	}
	total := num(res["mem_total_kb"])
	avail := num(res["mem_avail_kb"])
	if total > 0 && avail*100/total < int64(th.MemAvailPct) {
		out = append(out, Notice{Kind: "mem_low", Severity: "warning", Message: fmt.Sprintf("available memory %d%%", avail*100/total)})
	}
	if th.Load1 > 0 {
		if load, ok := res["loadavg"].(string); ok {
			parts := strings.Split(load, ",")
			if len(parts) > 0 {
				if v, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil && v >= th.Load1 {
					out = append(out, Notice{Kind: "load_high", Severity: "warning", Message: fmt.Sprintf("load1=%.2f", v)})
				}
			}
		}
	}
	if failed, _ := res["systemd_failed"].(string); strings.Trim(failed, "; \t") != "" {
		out = append(out, Notice{Kind: "systemd_failed", Severity: "warning", Message: "failed units: " + strings.Trim(failed, ";")})
	}
	containers, _ := res["containers"].(string)
	if bad := docker.AbnormalLines(containers); len(bad) > 0 {
		out = append(out, Notice{Kind: "docker_unhealthy", Severity: "warning", Message: "abnormal containers: " + strings.Join(bad, "; ")})
	}
	if n := num(res["security_updates"]); n >= th.SecurityUpdatesMin {
		out = append(out, Notice{Kind: "security_updates", Severity: "warning", Message: fmt.Sprintf("%d security updates available", n)})
	}
	if ts := num(res["cert_not_after"]); ts > 0 {
		expiry := time.Unix(ts, 0)
		limit := now.Add(time.Duration(th.CertExpiryWarnDays) * 24 * time.Hour)
		if !expiry.After(limit) {
			days := int(expiry.Sub(now).Hours() / 24)
			out = append(out, Notice{Kind: "cert_expiring", Severity: "warning", Message: fmt.Sprintf("certificate expires in %d days", days)})
		}
	}
	return out
}

func noticesAt(res Result, now time.Time) []Notice {
	return NoticesWith(res, now, defaultThresholds())
}

func num(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n
	default:
		return 0
	}
}

func (s *Service) raiseScanAlerts(vpsID int64, res Result) {
	if s.Emit == nil || s.DB == nil {
		return
	}
	th := defaultThresholds()
	if rules, err := s.DB.ListAlertRules(); err == nil {
		if d := store.DecideAlertRule(rules, "disk_high"); d.Threshold != nil {
			th.DiskPct = int(*d.Threshold)
		}
		if d := store.DecideAlertRule(rules, "mem_low"); d.Threshold != nil {
			th.MemAvailPct = int(*d.Threshold)
		}
		if d := store.DecideAlertRule(rules, "load_high"); d.Threshold != nil {
			th.Load1 = *d.Threshold
		}
		if d := store.DecideAlertRule(rules, "security_updates"); d.Threshold != nil {
			th.SecurityUpdatesMin = int64(*d.Threshold)
		}
		if d := store.DecideAlertRule(rules, "cert_expiring"); d.DaysBefore > 0 {
			th.CertExpiryWarnDays = d.DaysBefore
		}
	}
	id := vpsID
	for _, n := range NoticesWith(res, time.Now(), th) {
		recent, err := s.DB.HasRecentAlert(vpsID, n.Kind, 6*time.Hour)
		if err != nil || recent {
			continue
		}
		s.Emit(n.Kind, n.Severity, &id, n.Message)
	}
}
