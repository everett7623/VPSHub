package api

import (
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/evenfrank/vpshub/internal/ai"
	"github.com/evenfrank/vpshub/internal/alert"
	"github.com/evenfrank/vpshub/internal/auth"
	"github.com/evenfrank/vpshub/internal/backup"
	"github.com/evenfrank/vpshub/internal/collector"
	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/crypto"
	mw "github.com/evenfrank/vpshub/internal/middleware"
	"github.com/evenfrank/vpshub/internal/probe"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
	"github.com/evenfrank/vpshub/internal/tasks"
	"github.com/gin-gonic/gin"
)

// Version is set from main via -ldflags or defaults to "dev".
var Version = "dev"

type Server struct {
	Cfg          *config.Config
	DB           *store.DB
	Auth         *auth.Service
	Vault        *crypto.Vault
	SSH          *sshx.Client
	Collector    *collector.Service
	Worker       *tasks.Worker
	Backup       *backup.Service
	Alert        *alert.Service
	Probe        *probe.Service
	AI           *ai.Client
	Log          *slog.Logger
	Fingerprints []collector.Fingerprint
	WebFS        fs.FS
}

func (s *Server) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), mw.BasicAuth(s.Cfg.BasicAuthUser, s.Cfg.BasicAuthHash), mw.SecurityHeaders(), mw.BasePath(s.Cfg.BasePath), mw.CSRF(), s.accessLog())

	r.GET("/healthz", func(c *gin.Context) {
		dbOK := true
		if err := s.DB.Ping(); err != nil {
			dbOK = false
		}
		c.JSON(http.StatusOK, gin.H{
			"ok": dbOK, "vault": s.Vault.State(), "version": Version, "db_ok": dbOK,
		})
	})

	api := r.Group("/api")
	{
		api.GET("/setup/status", s.setupStatus)
		api.POST("/setup", s.setup)
		api.POST("/login", s.login)
		api.POST("/logout", s.requireAuth(), s.logout)
		api.GET("/me", s.requireAuth(), s.me)
		api.POST("/password", s.requireAuth(), s.changePassword)
		api.POST("/totp/enable", s.requireAuth(), s.enableTOTP)
		api.GET("/totp/setup", s.requireAuth(), s.totpSetup)
		api.GET("/sessions", s.requireAuth(), s.listSessions)
		api.DELETE("/sessions/:id", s.requireAuth(), s.revokeSession)
		api.POST("/sessions/revoke-all", s.requireAuth(), s.revokeAll)
		api.GET("/locks", s.requireAuth(), s.listLocks)
		api.POST("/locks/clear", s.requireAuth(), s.clearLock)
		api.POST("/locks/clear-all", s.requireAuth(), s.clearAllLocks)

		api.GET("/vault/status", s.requireAuth(), s.vaultStatus)
		api.POST("/vault/init", s.requireAuth(), s.vaultInit)
		api.POST("/vault/unlock", s.requireAuth(), s.vaultUnlock)
		api.POST("/vault/lock", s.requireAuth(), s.vaultLock)
		api.POST("/vault/rotate", s.requireAuth(), s.vaultRotate)
		api.POST("/vault/recover", s.requireAuth(), s.vaultRecover)

		api.GET("/view-password/status", s.requireAuth(), s.viewPasswordStatus)
		api.POST("/view-password/setup", s.requireAuth(), s.viewPasswordSetup)
		api.POST("/view-password/unlock", s.requireAuth(), s.viewPasswordUnlock)

		api.GET("/dashboard", s.requireAuth(), s.dashboard)

		api.GET("/providers", s.requireAuth(), s.listProviders)
		api.POST("/providers", s.requireAuth(), s.createProvider)
		api.PUT("/providers/:id", s.requireAuth(), s.updateProvider)
		api.DELETE("/providers/:id", s.requireAuth(), s.deleteProvider)
		api.POST("/providers/:id/reveal-notes", s.requireAuth(), s.requireVault(), s.revealProviderNotes)

		api.GET("/websites", s.requireAuth(), s.listWebsites)
		api.POST("/websites", s.requireAuth(), s.createWebsite)
		api.PUT("/websites/:id", s.requireAuth(), s.updateWebsite)
		api.DELETE("/websites/:id", s.requireAuth(), s.deleteWebsite)
		api.POST("/websites/:id/password", s.requireAuth(), s.requireVault(), s.setWebsitePanelPassword)
		api.POST("/websites/:id/reveal", s.requireAuth(), s.requireVault(), s.revealWebsitePassword)

		api.GET("/vps", s.requireAuth(), s.listVPS)
		api.GET("/vps/deleted", s.requireAuth(), s.listDeletedVPS)
		api.POST("/vps/purge-batch", s.requireAuth(), s.purgeVPSBatch)
		api.GET("/vps/export", s.requireAuth(), s.exportVPS)
		api.POST("/vps", s.requireAuth(), s.createVPS)
		api.GET("/vps/:id", s.requireAuth(), s.getVPS)
		api.PUT("/vps/:id", s.requireAuth(), s.updateVPS)
		api.DELETE("/vps/:id", s.requireAuth(), s.deleteVPS)
		api.POST("/vps/:id/restore", s.requireAuth(), s.restoreVPS)
		api.POST("/vps/:id/purge", s.requireAuth(), s.purgeVPS)
		api.GET("/vps/:id/maintenance-status", s.requireAuth(), s.maintenanceStatus)
		api.POST("/vps/import", s.requireAuth(), s.importVPSCSV)
		api.POST("/vps/batch", s.requireAuth(), s.batchVPS)
		api.POST("/vps/batch-scan", s.requireAuth(), s.requireVault(), s.batchScan)
		api.POST("/vps/batch-test", s.requireAuth(), s.requireVault(), s.batchTest)
		api.POST("/vps/:id/credentials", s.requireAuth(), s.setCredentials)
		api.POST("/vps/:id/reveal/:kind", s.requireAuth(), s.requireVault(), s.revealVPSCredential)
		api.POST("/vps/:id/test", s.requireAuth(), s.requireVault(), s.testConnection)
		api.POST("/vps/:id/hostkey/confirm", s.requireAuth(), s.confirmHostKey)
		api.POST("/vps/:id/hostkey/clear", s.requireAuth(), s.clearHostKey)
		api.POST("/vps/:id/scan", s.requireAuth(), s.requireVault(), s.scanVPS)
		api.GET("/vps/:id/scan", s.requireAuth(), s.getScan)
		api.GET("/vps/:id/checkup", s.requireAuth(), s.vpsCheckup)
		api.POST("/ai/advise", s.requireAuth(), s.aiAdvise)
		api.GET("/vps/:id/metrics", s.requireAuth(), s.vpsMetrics)
		api.GET("/vps/:id/diff", s.requireAuth(), s.scanDiff)
		api.GET("/vps/:id/changes", s.requireAuth(), s.changeSnapshots)
		api.GET("/vps/:id/expectations", s.requireAuth(), s.vpsExpectations)
		api.PUT("/vps/:id/expectations", s.requireAuth(), s.setVPSExpectations)
		api.POST("/vps/:id/logs", s.requireAuth(), s.requireVault(), s.hostLogs)
		api.POST("/vps/:id/convert-key", s.requireAuth(), s.requireVault(), s.convertToKey)
		api.POST("/vps/:id/sshd/disable-password", s.requireAuth(), s.requireVault(), s.disablePasswordAuth)
		api.POST("/vps/:id/docker", s.requireAuth(), s.requireVault(), s.dockerAction)
		api.POST("/vps/:id/docker/query", s.requireAuth(), s.requireVault(), s.dockerQuery)
		api.POST("/vps/:id/systemd", s.requireAuth(), s.requireVault(), s.systemdAction)
		api.GET("/vps/:id/webssh", s.requireAuth(), s.webssh)
		api.POST("/vps/:id/webssh/snippet", s.requireAuth(), s.requireVault(), s.websshSnippet)
		api.GET("/vps/:id/sftp", s.requireAuth(), s.requireVault(), s.sftpList)
		api.GET("/vps/:id/sftp/text", s.requireAuth(), s.requireVault(), s.sftpReadText)
		api.GET("/vps/:id/sftp/download", s.requireAuth(), s.requireVault(), s.sftpDownload)
		api.POST("/vps/:id/sftp", s.requireAuth(), s.requireVault(), s.sftpUpload)
		api.PUT("/vps/:id/sftp/text", s.requireAuth(), s.requireVault(), s.sftpWriteText)
		api.POST("/sftp/distribute", s.requireAuth(), s.requireVault(), s.sftpDistribute)
		api.GET("/vps/:id/config-backup-paths", s.requireAuth(), s.configBackupPaths)
		api.GET("/vps/:id/config-stamps", s.requireAuth(), s.requireVault(), s.configStamps)
		api.POST("/vps/:id/config-backup", s.requireAuth(), s.requireVault(), s.configBackup)
		api.POST("/vps/:id/config-restore", s.requireAuth(), s.requireVault(), s.configRestore)

		api.GET("/matrix", s.requireAuth(), s.serviceMatrix)
		api.GET("/audit", s.requireAuth(), s.listAudit)
		api.GET("/audit/actions", s.requireAuth(), s.listAuditActions)
		api.GET("/audit/export", s.requireAuth(), s.exportAudit)
		api.GET("/audit/verify", s.requireAuth(), s.verifyAudit)

		api.GET("/scripts", s.requireAuth(), s.listScripts)
		api.POST("/scripts", s.requireAuth(), s.createScript)
		api.POST("/scripts/import", s.requireAuth(), s.importScript)
		api.GET("/scripts/:id", s.requireAuth(), s.getScript)
		api.POST("/scripts/:id/review", s.requireAuth(), s.reviewScript)
		api.PATCH("/scripts/:id/flags", s.requireAuth(), s.updateScriptFlags)
		api.PUT("/scripts/:id", s.requireAuth(), s.updateScriptBody)
		api.GET("/scripts/:id/versions", s.requireAuth(), s.listScriptVersions)
		api.GET("/scripts/:id/versions/:vid", s.requireAuth(), s.getScriptVersion)
		api.POST("/scripts/:id/versions/:vid/restore", s.requireAuth(), s.restoreScriptVersion)

		api.GET("/tasks", s.requireAuth(), s.listTasks)
		api.POST("/tasks", s.requireAuth(), s.requireVault(), s.createTask)
		api.GET("/tasks/:id", s.requireAuth(), s.getTask)
		api.GET("/tasks/:id/export", s.requireAuth(), s.exportTask)
		api.GET("/tasks/:id/stream", s.requireAuth(), s.streamTask)
		api.POST("/tasks/:id/cancel", s.requireAuth(), s.cancelTask)
		api.POST("/tasks/:id/approve", s.requireAuth(), s.requireVault(), s.approveTask)
		api.POST("/tasks/:id/reject", s.requireAuth(), s.rejectTask)
		api.POST("/tasks/:id/retry-failed", s.requireAuth(), s.requireVault(), s.retryFailed)

		api.GET("/templates", s.requireAuth(), s.listTemplates)
		api.POST("/templates", s.requireAuth(), s.createTemplate)
		api.PUT("/templates/:id", s.requireAuth(), s.updateTemplate)
		api.DELETE("/templates/:id", s.requireAuth(), s.deleteTemplate)
		api.GET("/templates/:id/vps", s.requireAuth(), s.listTemplateVPS)

		api.GET("/modules", s.requireAuth(), s.listModules)
		api.GET("/services/impact", s.requireAuth(), s.serviceImpact)
		api.POST("/modules/upgrade-plan", s.requireAuth(), s.upgradePlan)

		api.GET("/alerts", s.requireAuth(), s.listAlerts)
		api.POST("/alerts/ack-all", s.requireAuth(), s.ackAllAlerts)
		api.POST("/alerts/:id/ack", s.requireAuth(), s.ackAlert)
		api.GET("/alert-rules", s.requireAuth(), s.listAlertRules)
		api.POST("/alert-rules", s.requireAuth(), s.createAlertRule)
		api.PUT("/alert-rules/:id", s.requireAuth(), s.updateAlertRule)
		api.DELETE("/alert-rules/:id", s.requireAuth(), s.deleteAlertRule)
		api.POST("/smtp/test", s.requireAuth(), s.smtpTest)
		api.POST("/alerts/test/:channel", s.requireAuth(), s.alertChannelTest)
		api.POST("/probes/run", s.requireAuth(), s.runProbesNow)

		api.POST("/backup/panel", s.requireAuth(), s.requireVault(), s.panelBackup)
		api.GET("/backups", s.requireAuth(), s.listBackups)
		api.GET("/backups/:id/download", s.requireAuth(), s.downloadBackup)
		api.DELETE("/backups/:id", s.requireAuth(), s.requireVault(), s.deleteBackup)
		api.POST("/backup/restore", s.requireAuth(), s.requireVault(), s.restoreBackup)

		api.GET("/tokens", s.requireAuth(), s.listTokens)
		api.POST("/tokens", s.requireAuth(), s.createToken)
		api.DELETE("/tokens/:id", s.requireAuth(), s.revokeToken)

		api.GET("/settings/features", s.requireAuth(), s.features)
	}

	if s.WebFS != nil {
		fileServer := http.FileServer(http.FS(s.WebFS))
		r.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			path := strings.TrimPrefix(c.Request.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			if _, err := fs.Stat(s.WebFS, path); err != nil {
				c.Request.URL.Path = "/"
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}
			fileServer.ServeHTTP(c.Writer, c.Request)
		})
	}
	return r
}

func (s *Server) accessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		s.Log.Info("http", "method", c.Request.Method, "path", c.Request.URL.Path, "status", c.Writer.Status(), "ip", s.clientIP(c))
	}
}

func LoadWebFS(dir string) fs.FS {
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return os.DirFS(dir)
	}
	return nil
}
