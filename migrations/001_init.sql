-- VPSHub Phase 1+ schema

PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret_enc BLOB,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    webauthn_credentials TEXT DEFAULT '[]',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    ip TEXT,
    user_agent TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS account_locks (
    key TEXT PRIMARY KEY,
    until DATETIME NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL,
    verifier BLOB NOT NULL,
    recovery_key_hash TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    ipv4 TEXT,
    ipv6 TEXT,
    ssh_port INTEGER NOT NULL DEFAULT 22,
    ssh_user TEXT NOT NULL DEFAULT 'root',
    auth_method TEXT NOT NULL DEFAULT 'password', -- password | key
    jump_host_id INTEGER REFERENCES vps(id),
    provider TEXT,
    region TEXT,
    expires_at DATE,
    monthly_cost REAL,
    group_name TEXT,
    tags TEXT DEFAULT '[]',
    environment TEXT NOT NULL DEFAULT 'production', -- production | testing
    op_mode TEXT NOT NULL DEFAULT 'normal_tasks', -- readonly_monitor | normal_tasks | high_risk_allowed | no_changes
    notes TEXT,
    host_key_fp TEXT,
    host_key_pending TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_connect_at DATETIME,
    last_scan_at DATETIME,
    maintenance_windows TEXT DEFAULT '[]',
    deleted_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vps_host ON vps(host);
CREATE INDEX IF NOT EXISTS idx_vps_group ON vps(group_name);
CREATE INDEX IF NOT EXISTS idx_vps_deleted ON vps(deleted_at);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vps_id INTEGER NOT NULL REFERENCES vps(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, -- ssh_password | ssh_private_key | key_passphrase | sudo_password | api_token
    ciphertext BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vps_id, kind)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    ip TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    risk_level TEXT NOT NULL DEFAULT 'low',
    task_id TEXT,
    result TEXT NOT NULL DEFAULT 'success',
    detail TEXT,
    failure_reason TEXT,
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT DEFAULT '[]',
    expires_at DATETIME,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vps_id INTEGER NOT NULL REFERENCES vps(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_vps ON scan_results(vps_id, created_at DESC);

CREATE TABLE IF NOT EXISTS service_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vps_id INTEGER NOT NULL REFERENCES vps(id) ON DELETE CASCADE,
    service_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown', -- installed | running | stopped | error | unknown
    version TEXT,
    detail TEXT,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vps_id, service_type)
);

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT,
    version TEXT NOT NULL DEFAULT '1.0.0',
    os_filter TEXT DEFAULT '[]',
    params_schema TEXT DEFAULT '[]',
    content TEXT NOT NULL,
    rollback_content TEXT,
    healthcheck_content TEXT,
    sensitive INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    allow_batch INTEGER NOT NULL DEFAULT 0,
    allow_production INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL,
    source TEXT,
    status TEXT NOT NULL DEFAULT 'draft', -- draft | review | approved | published | disabled | archived
    created_by TEXT,
    reviewed_by TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    risk_level TEXT NOT NULL DEFAULT 'medium',
    dry_run INTEGER NOT NULL DEFAULT 0,
    concurrency INTEGER NOT NULL DEFAULT 5,
    timeout_sec INTEGER NOT NULL DEFAULT 600,
    retry_max INTEGER NOT NULL DEFAULT 0,
    canary_vps_ids TEXT DEFAULT '[]',
    roll_batch INTEGER NOT NULL DEFAULT 0,
    fail_threshold REAL NOT NULL DEFAULT 0.5,
    payload TEXT,
    created_by TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME,
    finished_at DATETIME
);

CREATE TABLE IF NOT EXISTS task_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    vps_id INTEGER NOT NULL REFERENCES vps(id),
    status TEXT NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 0,
    log_text TEXT DEFAULT '',
    result TEXT,
    error TEXT,
    started_at DATETIME,
    finished_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_task_items_task ON task_items(task_id);
CREATE INDEX IF NOT EXISTS idx_task_items_status ON task_items(status);

CREATE TABLE IF NOT EXISTS change_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vps_id INTEGER NOT NULL REFERENCES vps(id) ON DELETE CASCADE,
    task_id TEXT,
    phase TEXT NOT NULL, -- before | after
    payload TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, -- panel | remote_config
    vps_id INTEGER,
    name TEXT NOT NULL,
    storage TEXT NOT NULL DEFAULT 'local', -- local | s3
    path TEXT NOT NULL,
    sha256 TEXT,
    encrypted INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    vps_id INTEGER,
    message TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS service_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    service_type TEXT NOT NULL,
    config_paths TEXT DEFAULT '[]',
    healthcheck TEXT,
    dependencies TEXT DEFAULT '[]',
    risk_level TEXT NOT NULL DEFAULT 'medium',
    meta TEXT DEFAULT '{}'
);
