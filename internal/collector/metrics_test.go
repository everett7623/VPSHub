package collector

import (
	"testing"
	"time"

	"github.com/evenfrank/vpshub/internal/store"
)

func TestMetricsFromScans(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	scans := []store.ScanRecord{{
		CreatedAt: at,
		Payload: `{
			"disk":"100,80,20,80%",
			"mem_total_kb":1000,
			"mem_avail_kb":250,
			"loadavg":"1.5,2.0,2.5",
			"security_updates":3,
			"cert_not_after":1700000000
		}`,
	}}
	pts := MetricsFromScans(scans)
	if len(pts) != 1 {
		t.Fatalf("len=%d", len(pts))
	}
	p := pts[0]
	if p.DiskUsedPct == nil || *p.DiskUsedPct != 80 {
		t.Fatalf("disk=%v", p.DiskUsedPct)
	}
	if p.MemUsedPct == nil || *p.MemUsedPct != 75 {
		t.Fatalf("mem=%v", p.MemUsedPct)
	}
	if p.Load1 == nil || *p.Load1 != 1.5 {
		t.Fatalf("load=%v", p.Load1)
	}
	if p.SecurityUpdates == nil || *p.SecurityUpdates != 3 {
		t.Fatalf("sec=%v", p.SecurityUpdates)
	}
	if p.CertNotAfter == nil || *p.CertNotAfter != 1700000000 {
		t.Fatalf("cert=%v", p.CertNotAfter)
	}
}
