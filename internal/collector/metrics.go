package collector

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/evenfrank/vpshub/internal/store"
)

// MetricPoint is a compact time series sample extracted from a scan_results payload.
type MetricPoint struct {
	CreatedAt       time.Time `json:"created_at"`
	DiskUsedPct     *float64  `json:"disk_used_pct,omitempty"`
	MemUsedPct      *float64  `json:"mem_used_pct,omitempty"`
	Load1           *float64  `json:"load_1,omitempty"`
	SecurityUpdates *float64  `json:"security_updates,omitempty"`
	CertNotAfter    *float64  `json:"cert_not_after,omitempty"`
}

// MetricsFromScans builds a compact series from recent scan records (newest first).
func MetricsFromScans(scans []store.ScanRecord) []MetricPoint {
	out := make([]MetricPoint, 0, len(scans))
	for _, sc := range scans {
		out = append(out, extractMetrics(sc.CreatedAt, sc.Payload))
	}
	return out
}

func extractMetrics(at time.Time, payload string) MetricPoint {
	p := MetricPoint{CreatedAt: at}
	var res Result
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		return p
	}
	if disk, ok := res["disk"].(string); ok {
		parts := strings.Split(disk, ",")
		if len(parts) >= 4 {
			pct := strings.TrimSuffix(strings.TrimSpace(parts[3]), "%")
			if n, err := strconv.ParseFloat(pct, 64); err == nil {
				p.DiskUsedPct = &n
			}
		}
	}
	total := num(res["mem_total_kb"])
	avail := num(res["mem_avail_kb"])
	if total > 0 {
		used := float64(total-avail) * 100 / float64(total)
		p.MemUsedPct = &used
	}
	if load, ok := res["loadavg"].(string); ok && load != "" {
		first := strings.Split(load, ",")[0]
		if n, err := strconv.ParseFloat(strings.TrimSpace(first), 64); err == nil {
			p.Load1 = &n
		}
	}
	if v := num(res["security_updates"]); res["security_updates"] != nil {
		f := float64(v)
		p.SecurityUpdates = &f
	}
	if v := num(res["cert_not_after"]); v > 0 {
		f := float64(v)
		p.CertNotAfter = &f
	}
	return p
}
