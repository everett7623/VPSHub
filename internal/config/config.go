package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen         string        `yaml:"listen"`
	DataDir        string        `yaml:"data_dir"`
	SessionTTL     time.Duration `yaml:"-"`
	VaultLockTTL   time.Duration `yaml:"-"`
	SecureCookie   bool          `yaml:"secure_cookie"`
	IPWhitelist    []string      `yaml:"ip_whitelist"`
	LoginMaxFails  int           `yaml:"login_max_fails"`
	LoginLockMin   int           `yaml:"login_lock_minutes"`
	SSHDialTimeout time.Duration `yaml:"-"`
	SSHCmdTimeout  time.Duration `yaml:"-"`
	SSHMaxOutput   int64         `yaml:"ssh_max_output"`
	SSHMaxPerHost  int           `yaml:"ssh_max_per_host"`
	TaskMaxConc    int           `yaml:"task_max_concurrency"`
	TaskProdConc   int           `yaml:"task_prod_concurrency"`
	WebSSHEnabled  bool          `yaml:"webssh_enabled"`
	SFTPEnabled    bool          `yaml:"sftp_enabled"`
	AlertTelegram  string        `yaml:"alert_telegram_token"`
	AlertChatID    string        `yaml:"alert_telegram_chat_id"`
	AlertWebhook   string        `yaml:"alert_webhook_url"`
	SMTPHost       string        `yaml:"smtp_host"`
	SMTPPort       int           `yaml:"smtp_port"`
	SMTPUser       string        `yaml:"smtp_user"`
	SMTPPass       string        `yaml:"smtp_pass"`
	SMTPFrom       string        `yaml:"smtp_from"`
	SMTPTo         string        `yaml:"smtp_to"`
	S3Endpoint     string        `yaml:"s3_endpoint"`
	S3Bucket       string        `yaml:"s3_bucket"`
	S3AccessKey    string        `yaml:"s3_access_key"`
	S3SecretKey    string        `yaml:"s3_secret_key"`
	TrustedProxies []string      `yaml:"trusted_proxies"`
	BasePath       string        `yaml:"base_path"`
	ProbeInterval  time.Duration `yaml:"-"`
	BasicAuthUser  string        `yaml:"basic_auth_user"`
	BasicAuthHash  string        `yaml:"basic_auth_hash"`
	TLSCert        string        `yaml:"tls_cert"`
	TLSKey         string        `yaml:"tls_key"`
	AIEnabled      bool          `yaml:"ai_enabled"`
	AIBaseURL      string        `yaml:"ai_base_url"`
	AIAPIKey       string        `yaml:"ai_api_key"`
	AIModel        string        `yaml:"ai_model"`

	SessionTTLRaw     string `yaml:"session_ttl"`
	VaultLockTTLRaw   string `yaml:"vault_lock_ttl"`
	SSHDialTimeoutRaw string `yaml:"ssh_dial_timeout"`
	SSHCmdTimeoutRaw  string `yaml:"ssh_cmd_timeout"`
	ProbeIntervalRaw  string `yaml:"probe_interval"`
}

func Default() *Config {
	return &Config{
		Listen:         "127.0.0.1:8080",
		DataDir:        "./data",
		SessionTTL:     8 * time.Hour,
		VaultLockTTL:   30 * time.Minute,
		SecureCookie:   false,
		LoginMaxFails:  5,
		LoginLockMin:   15,
		SSHDialTimeout: 15 * time.Second,
		SSHCmdTimeout:  5 * time.Minute,
		SSHMaxOutput:   2 << 20,
		SSHMaxPerHost:  2,
		TaskMaxConc:    5,
		TaskProdConc:   1,
		WebSSHEnabled:  false,
		SFTPEnabled:    false,
		ProbeInterval:  5 * time.Minute,
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config: %w", err)
			}
		} else {
			if err := yaml.Unmarshal(b, cfg); err != nil {
				return nil, fmt.Errorf("parse config: %w", err)
			}
		}
	}
	parseDur := func(raw string, dest *time.Duration) {
		if raw == "" {
			return
		}
		if d, err := time.ParseDuration(raw); err == nil {
			*dest = d
		}
	}
	parseDur(cfg.SessionTTLRaw, &cfg.SessionTTL)
	parseDur(cfg.VaultLockTTLRaw, &cfg.VaultLockTTL)
	parseDur(cfg.SSHDialTimeoutRaw, &cfg.SSHDialTimeout)
	parseDur(cfg.SSHCmdTimeoutRaw, &cfg.SSHCmdTimeout)
	parseDur(cfg.ProbeIntervalRaw, &cfg.ProbeInterval)
	applyEnv(cfg)
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("VPSHUB_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("VPSHUB_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("VPSHUB_SECURE_COOKIE"); v != "" {
		cfg.SecureCookie = v == "1" || v == "true"
	}
	if v := os.Getenv("VPSHUB_WEBSSH"); v != "" {
		cfg.WebSSHEnabled = v == "1" || v == "true"
	}
	if v := os.Getenv("VPSHUB_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SessionTTL = d
		}
	}
	if v := os.Getenv("VPSHUB_VAULT_LOCK_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.VaultLockTTL = d
		}
	}
	if v := os.Getenv("VPSHUB_TASK_MAX_CONC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TaskMaxConc = n
		}
	}
	if v := os.Getenv("VPSHUB_ALERT_WEBHOOK"); v != "" {
		cfg.AlertWebhook = v
	}
	if v := os.Getenv("VPSHUB_ALERT_TELEGRAM_TOKEN"); v != "" {
		cfg.AlertTelegram = v
	}
	if v := os.Getenv("VPSHUB_ALERT_TELEGRAM_CHAT_ID"); v != "" {
		cfg.AlertChatID = v
	}
	if v := os.Getenv("VPSHUB_SMTP_HOST"); v != "" {
		cfg.SMTPHost = v
	}
	if v := os.Getenv("VPSHUB_SMTP_FROM"); v != "" {
		cfg.SMTPFrom = v
	}
	if v := os.Getenv("VPSHUB_SMTP_TO"); v != "" {
		cfg.SMTPTo = v
	}
	if v := os.Getenv("VPSHUB_SMTP_USER"); v != "" {
		cfg.SMTPUser = v
	}
	if v := os.Getenv("VPSHUB_SMTP_PASS"); v != "" {
		cfg.SMTPPass = v
	}
	if v := os.Getenv("VPSHUB_AI_ENABLED"); v != "" {
		cfg.AIEnabled = v == "1" || v == "true"
	}
	if v := os.Getenv("VPSHUB_AI_BASE_URL"); v != "" {
		cfg.AIBaseURL = v
	}
	if v := os.Getenv("VPSHUB_AI_API_KEY"); v != "" {
		cfg.AIAPIKey = v
	}
	if v := os.Getenv("VPSHUB_AI_MODEL"); v != "" {
		cfg.AIModel = v
	}
}

// BasicAuthEnabled reports whether browser basic auth is configured.
func (c *Config) BasicAuthEnabled() bool {
	return c.BasicAuthUser != "" && c.BasicAuthHash != ""
}

// TLSEnabled reports whether both certificate files are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCert != "" && c.TLSKey != ""
}
