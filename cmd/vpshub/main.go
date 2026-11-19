package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/evenfrank/vpshub/internal/ai"
	"github.com/evenfrank/vpshub/internal/alert"
	"github.com/evenfrank/vpshub/internal/api"
	"github.com/evenfrank/vpshub/internal/auth"
	"github.com/evenfrank/vpshub/internal/backup"
	"github.com/evenfrank/vpshub/internal/collector"
	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/crypto"
	"github.com/evenfrank/vpshub/internal/probe"
	"github.com/evenfrank/vpshub/internal/scripts"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/evenfrank/vpshub/internal/tasks"
	webfs "github.com/evenfrank/vpshub/web"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "status", "password", "restart", "bootstrap", "restore-db":
			if err := runCLI(os.Args[1], os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		case "help", "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: vpshub [-config path] | vpshub status|password|restart|bootstrap|restore-db [-config path]")
			return
		}
	}
	serve()
}

// version may be overridden at link time: -ldflags "-X main.version=1.2.3"
var version = "dev"

func serve() {
	cfgPath := flag.String("config", "config.yaml", "config file path")
	flag.Parse()
	if version != "" {
		api.Version = version
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Error("data dir", "err", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Error("db", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := scripts.Seed(db); err != nil {
		log.Error("seed scripts", "err", err)
		os.Exit(1)
	}

	vault := crypto.NewVault(cfg.VaultLockTTL)
	sshClient := sshx.New(sshx.Config{
		DialTimeout: cfg.SSHDialTimeout,
		CmdTimeout:  cfg.SSHCmdTimeout,
		MaxOutput:   cfg.SSHMaxOutput,
		MaxPerHost:  cfg.SSHMaxPerHost,
	})
	coll := collector.New(sshClient, db)
	worker := tasks.NewWorker(db, cfg, sshClient, log)
	bak := backup.New(db, cfg.DataDir, vault)
	al := alert.New(db, cfg, log)
	coll.Emit = al.Emit
	pr := probe.New(db, al, log)
	au := auth.New(db, cfg)
	au.OnLockout = func(username, ip, scope string) {
		if recent, _ := db.HasRecentAlert(0, "login_locked", time.Hour); recent {
			return
		}
		al.Emit("login_locked", "warning", nil, "login lockout scope="+scope+" user="+username+" ip="+ip)
	}
	au.OnLoginFail = func(username, ip, reason string) {
		since := time.Now().Add(-15 * time.Minute)
		uf, _, _ := db.CountRecentFails(username, ip, since)
		if uf < 3 {
			return
		}
		if recent, _ := db.HasRecentAlert(0, "login_failed", 30*time.Minute); recent {
			return
		}
		al.Emit("login_failed", "warning", nil, "repeated login failures user="+username+" ip="+ip+" reason="+reason+" count="+strconv.Itoa(uf))
	}
	worker.OnItemFailed = func(vpsID int64, taskID, taskType string) {
		if recent, _ := db.HasRecentAlert(vpsID, "task_failed", 6*time.Hour); recent {
			return
		}
		id := vpsID
		al.Emit("task_failed", "warning", &id, "task "+taskID+" type="+taskType+" failed")
	}

	fps := loadFingerprints(
		"/usr/lib/vpshub/fingerprints/default.yaml",
		filepath.Join("fingerprints", "default.yaml"),
	)

	webFS := webfs.DistFS()
	if disk := api.LoadWebFS(filepath.Join("web", "dist")); disk != nil {
		// Prefer on-disk dist during development when present
		webFS = disk
	}

	aiClient := ai.New(ai.Config{
		Enabled: cfg.AIEnabled,
		BaseURL: cfg.AIBaseURL,
		APIKey:  cfg.AIAPIKey,
		Model:   cfg.AIModel,
	})

	srv := &api.Server{
		Cfg: cfg, DB: db, Auth: au, Vault: vault, SSH: sshClient,
		Collector: coll, Worker: worker, Backup: bak, Alert: al, Probe: pr, AI: aiClient, Log: log,
		Fingerprints: fps, WebFS: webFS,
	}
	srv.BindTaskSSH()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Start(ctx)
	pr.Start(ctx, cfg.ProbeInterval)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("listening", "addr", cfg.Listen, "base_path", cfg.BasePath, "tls", cfg.TLSEnabled(), "webssh", cfg.WebSSHEnabled)
		var err error
		if cfg.TLSEnabled() {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shCancel()
	_ = httpSrv.Shutdown(shCtx)
	vault.Lock()
}

func loadFingerprints(paths ...string) []collector.Fingerprint {
	for _, path := range paths {
		b, err := os.ReadFile(path) // #nosec G304 -- fixed installer / repo fingerprint paths
		if err != nil {
			continue
		}
		var fps []collector.Fingerprint
		if err := yaml.Unmarshal(b, &fps); err != nil || len(fps) == 0 {
			continue
		}
		return fps
	}
	return nil
}
