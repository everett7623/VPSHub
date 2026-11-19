package store

import "time"

type Admin struct {
	ID                 int64
	Username           string
	PasswordHash       string
	TOTPSecretEnc      []byte
	TOTPEnabled        bool
	MustChangePassword bool
	WebAuthnCreds      string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Session struct {
	ID        string
	AdminID   int64
	IP        string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type VPS struct {
	ID               int64      `json:"id"`
	Name             string     `json:"name"`
	Host             string     `json:"host"`
	IPv4             string     `json:"ipv4,omitempty"`
	IPv6             string     `json:"ipv6,omitempty"`
	SSHPort          int        `json:"ssh_port"`
	SSHUser          string     `json:"ssh_user"`
	AuthMethod       string     `json:"auth_method"`
	JumpHostID       *int64     `json:"jump_host_id,omitempty"`
	Provider         string     `json:"provider,omitempty"`
	ProviderID       *int64     `json:"provider_id,omitempty"`
	ProviderName     string     `json:"provider_name,omitempty"`
	Region           string     `json:"region,omitempty"`
	ExpiresAt        *string    `json:"expires_at,omitempty"`
	MonthlyCost      *float64   `json:"monthly_cost,omitempty"`
	GroupName        string     `json:"group_name,omitempty"`
	Tags             string     `json:"tags"`
	Environment      string     `json:"environment"`
	OpMode           string     `json:"op_mode"`
	Notes            string     `json:"notes,omitempty"`
	HostKeyFP        string     `json:"host_key_fp,omitempty"`
	HostKeyPending   string     `json:"host_key_pending,omitempty"`
	Status           string     `json:"status"`
	LastConnectAt    *time.Time `json:"last_connect_at,omitempty"`
	LastScanAt       *time.Time `json:"last_scan_at,omitempty"`
	MaintenanceWins  string     `json:"maintenance_windows"`
	ServerType       string     `json:"server_type,omitempty"`
	PanelType        string     `json:"panel_type,omitempty"`
	PanelURL         string     `json:"panel_url,omitempty"`
	PanelUsername    string     `json:"panel_username,omitempty"`
	PurchaseDate     *string    `json:"purchase_date,omitempty"`
	RenewalCycle     string     `json:"renewal_cycle,omitempty"`
	AutoRenewal      bool       `json:"auto_renewal"`
	Currency         string     `json:"currency,omitempty"`
	PurchasePrice    *float64   `json:"purchase_price,omitempty"`
	HTTPProbeEnabled bool       `json:"http_probe_enabled"`
	HTTPProbeURL     string     `json:"http_probe_url,omitempty"`
	HTTPProbeHealthy *bool      `json:"http_probe_healthy,omitempty"`
	HTTPProbeLastAt  *time.Time `json:"http_probe_last_at,omitempty"`
	HTTPProbeError   string     `json:"http_probe_last_error,omitempty"`
	TCPReachable     *bool      `json:"tcp_reachable,omitempty"`
	TCPCheckedAt     *time.Time `json:"tcp_checked_at,omitempty"`
	Bandwidth        string     `json:"bandwidth,omitempty"`
	CPUCores         *float64   `json:"cpu_cores,omitempty"`
	RAMGB            *float64   `json:"ram_gb,omitempty"`
	DiskGB           *float64   `json:"disk_gb,omitempty"`
	SFTPRoot         string     `json:"sftp_root,omitempty"`
	SocksProxy       string     `json:"socks_proxy,omitempty"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type Credential struct {
	ID         int64
	VPSID      int64
	Kind       string
	Ciphertext []byte
}

type AuditEntry struct {
	ID            int64     `json:"id"`
	Actor         string    `json:"actor"`
	IP            string    `json:"ip"`
	Action        string    `json:"action"`
	TargetType    string    `json:"target_type"`
	TargetID      string    `json:"target_id"`
	RiskLevel     string    `json:"risk_level"`
	TaskID        string    `json:"task_id,omitempty"`
	Result        string    `json:"result"`
	Detail        string    `json:"detail,omitempty"`
	FailureReason string    `json:"failure_reason,omitempty"`
	PrevHash      string    `json:"prev_hash"`
	EntryHash     string    `json:"entry_hash"`
	CreatedAt     time.Time `json:"created_at"`
}

type Script struct {
	ID                 int64     `json:"id"`
	Name               string    `json:"name"`
	Category           string    `json:"category"`
	Version            string    `json:"version"`
	OSFilter           string    `json:"os_filter"`
	ParamsSchema       string    `json:"params_schema"`
	Content            string    `json:"content"`
	RollbackContent    string    `json:"rollback_content,omitempty"`
	HealthcheckContent string    `json:"healthcheck_content,omitempty"`
	Sensitive          bool      `json:"sensitive"`
	RiskLevel          string    `json:"risk_level"`
	AllowBatch         bool      `json:"allow_batch"`
	AllowProduction    bool      `json:"allow_production"`
	SHA256             string    `json:"sha256"`
	Source             string    `json:"source,omitempty"`
	Status             string    `json:"status"`
	CreatedBy          string    `json:"created_by,omitempty"`
	ReviewedBy         string    `json:"reviewed_by,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ScriptVersion is an immutable snapshot of a script body.
type ScriptVersion struct {
	ID               int64     `json:"id"`
	ScriptID         int64     `json:"script_id"`
	Version          string    `json:"version"`
	SHA256           string    `json:"sha256"`
	Content          string    `json:"content,omitempty"`
	RollbackContent  string    `json:"rollback_content,omitempty"`
	Healthcheck      string    `json:"healthcheck_content,omitempty"`
	ParamsSchema     string    `json:"params_schema,omitempty"`
	RiskLevel        string    `json:"risk_level"`
	StatusAtSnapshot string    `json:"status_at_snapshot"`
	Note             string    `json:"note,omitempty"`
	CreatedBy        string    `json:"created_by,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type Task struct {
	ID            string     `json:"id"`
	Type          string     `json:"type"`
	Status        string     `json:"status"`
	RiskLevel     string     `json:"risk_level"`
	DryRun        bool       `json:"dry_run"`
	Concurrency   int        `json:"concurrency"`
	TimeoutSec    int        `json:"timeout_sec"`
	RetryMax      int        `json:"retry_max"`
	CanaryVPSIds  string     `json:"canary_vps_ids"`
	RollBatch     int        `json:"roll_batch"`
	FailThreshold float64    `json:"fail_threshold"`
	Payload       string     `json:"payload"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

type TaskItem struct {
	ID         int64      `json:"id"`
	TaskID     string     `json:"task_id"`
	VPSID      int64      `json:"vps_id"`
	Status     string     `json:"status"`
	Attempt    int        `json:"attempt"`
	LogText    string     `json:"log_text"`
	Result     string     `json:"result,omitempty"`
	Error      string     `json:"error,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type ServiceInventory struct {
	ID          int64     `json:"id"`
	VPSID       int64     `json:"vps_id"`
	ServiceType string    `json:"service_type"`
	Status      string    `json:"status"`
	Version     string    `json:"version,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AlertEvent struct {
	ID           int64     `json:"id"`
	Kind         string    `json:"kind"`
	Severity     string    `json:"severity"`
	VPSID        *int64    `json:"vps_id,omitempty"` // target id (vps or website depending on TargetKind)
	TargetKind   string    `json:"target_kind,omitempty"`
	Message      string    `json:"message"`
	Acknowledged bool      `json:"acknowledged"`
	CreatedAt    time.Time `json:"created_at"`
}

type Backup struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	VPSID     *int64    `json:"vps_id,omitempty"`
	Name      string    `json:"name"`
	Storage   string    `json:"storage"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256,omitempty"`
	Encrypted bool      `json:"encrypted"`
	CreatedAt time.Time `json:"created_at"`
}

type APIToken struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	TokenHash string     `json:"-"`
	Scopes    string     `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
