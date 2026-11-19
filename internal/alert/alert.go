package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"time"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/store"
)

type Service struct {
	DB  *store.DB
	Cfg *config.Config
	Log *slog.Logger
}

func New(db *store.DB, cfg *config.Config, log *slog.Logger) *Service {
	return &Service{DB: db, Cfg: cfg, Log: log}
}

func (s *Service) Emit(kind, severity string, vpsID *int64, message string) {
	s.EmitTarget(kind, severity, "vps", vpsID, message)
}

// EmitTarget records an alert for a vps or website target (target_kind).
func (s *Service) EmitTarget(kind, severity, targetKind string, targetID *int64, message string) {
	rules, _ := s.DB.ListAlertRules()
	dec := store.DecideAlertRule(rules, kind)
	if !dec.Allow {
		return
	}
	_ = s.DB.CreateAlertTarget(kind, severity, targetKind, targetID, message)
	go s.notify(kind, severity, message, dec.Channels)
}

func (s *Service) notify(kind, severity, message string, channels []string) {
	want := func(name string) bool {
		if len(channels) == 0 {
			return true
		}
		for _, c := range channels {
			if c == name {
				return true
			}
		}
		return false
	}
	text := fmt.Sprintf("[VPSHub][%s][%s] %s", severity, kind, message)
	if want("webhook") && s.Cfg.AlertWebhook != "" {
		body, _ := json.Marshal(map[string]string{"text": text, "kind": kind, "severity": severity})
		req, _ := http.NewRequest(http.MethodPost, s.Cfg.AlertWebhook, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			s.Log.Warn("webhook alert failed", "err", err)
		} else {
			_ = resp.Body.Close()
		}
	}
	if want("telegram") && s.Cfg.AlertTelegram != "" && s.Cfg.AlertChatID != "" {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", s.Cfg.AlertTelegram)
		body, _ := json.Marshal(map[string]string{"chat_id": s.Cfg.AlertChatID, "text": text})
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			s.Log.Warn("telegram alert failed", "err", err)
		} else {
			_ = resp.Body.Close()
		}
	}
	if want("smtp") && s.Cfg.SMTPHost != "" && s.Cfg.SMTPFrom != "" {
		to := s.Cfg.SMTPTo
		if to == "" {
			to = s.Cfg.SMTPUser
		}
		if to == "" {
			return
		}
		port := s.Cfg.SMTPPort
		if port <= 0 {
			port = 587
		}
		addr := fmt.Sprintf("%s:%d", s.Cfg.SMTPHost, port)
		msg := []byte("To: " + to + "\r\nSubject: VPSHub Alert\r\n\r\n" + text + "\r\n")
		var auth smtp.Auth
		if s.Cfg.SMTPUser != "" {
			auth = smtp.PlainAuth("", s.Cfg.SMTPUser, s.Cfg.SMTPPass, s.Cfg.SMTPHost)
		}
		if err := smtp.SendMail(addr, auth, s.Cfg.SMTPFrom, []string{to}, msg); err != nil {
			s.Log.Warn("smtp alert failed", "err", err)
		}
	}
}
