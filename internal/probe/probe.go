package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/evenfrank/vpshub/internal/alert"
	"github.com/evenfrank/vpshub/internal/store"
)

type Service struct {
	DB     *store.DB
	Alert  *alert.Service
	Log    *slog.Logger
	Client *http.Client
}

func New(db *store.DB, al *alert.Service, log *slog.Logger) *Service {
	return &Service{
		DB: db, Alert: al, Log: log,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func (s *Service) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		time.Sleep(8 * time.Second)
		t := time.NewTicker(interval)
		defer t.Stop()
		s.RunOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.RunOnce(ctx)
			}
		}
	}()
}

func (s *Service) RunOnce(ctx context.Context) {
	s.probeWebsites(ctx)
	s.probeVPSHTTP(ctx)
	s.probeVPSTCP(ctx)
	s.checkExpiryAlerts()
	if n, err := s.DB.AdvanceAutoRenewals(); err == nil && n > 0 {
		s.Log.Info("auto renewal advanced", "count", n)
	}
}

func (s *Service) probeWebsites(ctx context.Context) {
	list, err := s.DB.ListProbeWebsites()
	if err != nil {
		return
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, w := range list {
		w := w
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			url := w.HTTPProbeURL
			if url == "" {
				url = w.Domain
			}
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "https://" + url
			}
			ok, msg := s.checkURL(ctx, url)
			_ = s.DB.UpdateWebsiteProbe(w.ID, ok, msg)
			if !ok {
				id := w.ID
				if recent, _ := s.DB.HasRecentAlertTarget(id, "website", "http_probe", 6*time.Hour); recent {
					return
				}
				s.Alert.EmitTarget("http_probe", "warning", "website", &id, fmt.Sprintf("website %s probe failed: %s", w.Name, msg))
			}
		}()
	}
	wg.Wait()
}

func (s *Service) probeVPSHTTP(ctx context.Context) {
	list, err := s.DB.ListProbeVPS()
	if err != nil || len(list) == 0 {
		return
	}
	for _, v := range list {
		url := v.HTTPProbeURL
		if url == "" {
			continue
		}
		ok, msg := s.checkURL(ctx, url)
		_ = s.DB.UpdateVPSProbe(v.ID, ok, msg)
		if !ok {
			id := v.ID
			if recent, _ := s.DB.HasRecentAlert(id, "http_probe", 6*time.Hour); recent {
				continue
			}
			s.Alert.Emit("http_probe", "warning", &id, fmt.Sprintf("vps %s probe failed: %s", v.Name, msg))
		}
	}
}

func (s *Service) probeVPSTCP(ctx context.Context) {
	list, err := s.DB.ListVPS(store.VPSFilter{})
	if err != nil {
		return
	}
	for _, v := range list {
		addr := net.JoinHostPort(v.Host, fmt.Sprintf("%d", v.SSHPort))
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		ok := err == nil
		if conn != nil {
			_ = conn.Close()
		}
		_ = s.DB.UpdateVPSTCP(v.ID, ok)
		if !ok && v.Status == "online" {
			id := v.ID
			if recent, _ := s.DB.HasRecentAlert(id, "vps_offline", 6*time.Hour); recent {
				continue
			}
			s.Alert.Emit("vps_offline", "warning", &id, fmt.Sprintf("TCP unreachable: %s (%s)", v.Name, addr))
		}
	}
}

func (s *Service) checkURL(ctx context.Context, raw string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("User-Agent", "VPSHub-Probe/1.0")
	resp, err := s.Client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return false, fmt.Sprintf("status %d", resp.StatusCode)
	}
	return true, ""
}

func (s *Service) checkExpiryAlerts() {
	vpsWarn := s.warnDaysFor("vps_expiry", 7)
	webWarn := s.warnDaysFor("website_expiry", 7)
	window := vpsWarn
	if webWarn > window {
		window = webWarn
	}
	if window < 14 {
		window = 14
	}
	items, err := s.DB.ListExpiring(window)
	if err != nil {
		return
	}
	for _, it := range items {
		kind := it.Kind + "_expiry"
		warnDays := vpsWarn
		if it.Kind == "website" {
			warnDays = webWarn
		}
		var sev string
		var msg string
		if it.DaysLeft < 0 {
			sev = "critical"
			msg = fmt.Sprintf("overdue %s: %s (%s)", it.Kind, it.Name, it.ExpiryDate)
		} else if it.DaysLeft <= warnDays {
			sev = "warning"
			msg = fmt.Sprintf("expiring in %d days: %s %s", it.DaysLeft, it.Kind, it.Name)
		} else {
			continue
		}
		id := it.ID
		targetKind := "vps"
		if it.Kind == "website" {
			targetKind = "website"
		}
		if recent, _ := s.DB.HasRecentAlertTarget(id, targetKind, kind, 6*time.Hour); recent {
			continue
		}
		s.Alert.EmitTarget(kind, sev, targetKind, &id, msg)
	}
}

// warnDaysFor returns days_before from an enabled alert rule, or fallback.
func (s *Service) warnDaysFor(ruleKind string, fallback int) int {
	if s.DB == nil {
		return fallback
	}
	rules, err := s.DB.ListAlertRules()
	if err != nil {
		return fallback
	}
	best := 0
	for _, r := range rules {
		if !r.Enabled || r.Kind != ruleKind {
			continue
		}
		if r.DaysBefore > best {
			best = r.DaysBefore
		}
	}
	if best <= 0 {
		return fallback
	}
	return best
}
