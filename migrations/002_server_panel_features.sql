-- Features adapted from naibabiji/server-panel

CREATE TABLE IF NOT EXISTS providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    website TEXT,
    contact TEXT,
    private_notes_enc BLOB,
    notes TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    site_type TEXT DEFAULT 'other',
    vps_id INTEGER REFERENCES vps(id) ON DELETE SET NULL,
    panel_type TEXT DEFAULT 'none',
    panel_url TEXT,
    panel_username TEXT,
    panel_password_enc BLOB,
    expiry_date DATE,
    status TEXT NOT NULL DEFAULT 'active',
    http_probe_enabled INTEGER NOT NULL DEFAULT 0,
    http_probe_healthy INTEGER,
    http_probe_last_at DATETIME,
    http_probe_last_error TEXT,
    notes TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_websites_vps ON websites(vps_id);
CREATE INDEX IF NOT EXISTS idx_websites_expiry ON websites(expiry_date);

CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL, -- vps_offline | http_probe | vps_expiry | website_expiry | cpu | mem | disk
    enabled INTEGER NOT NULL DEFAULT 1,
    threshold REAL,
    days_before INTEGER DEFAULT 14,
    notify_channels TEXT DEFAULT '["webhook"]',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS view_tokens (
    token TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Enrich VPS with billing / probe fields from server-panel
ALTER TABLE vps ADD COLUMN provider_id INTEGER REFERENCES providers(id);
ALTER TABLE vps ADD COLUMN server_type TEXT DEFAULT 'vps';
ALTER TABLE vps ADD COLUMN panel_type TEXT DEFAULT 'none';
ALTER TABLE vps ADD COLUMN panel_url TEXT;
ALTER TABLE vps ADD COLUMN panel_username TEXT;
ALTER TABLE vps ADD COLUMN panel_password_enc BLOB;
ALTER TABLE vps ADD COLUMN purchase_date DATE;
ALTER TABLE vps ADD COLUMN renewal_cycle TEXT DEFAULT 'monthly';
ALTER TABLE vps ADD COLUMN auto_renewal INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vps ADD COLUMN currency TEXT DEFAULT 'USD';
ALTER TABLE vps ADD COLUMN purchase_price REAL;
ALTER TABLE vps ADD COLUMN http_probe_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vps ADD COLUMN http_probe_url TEXT;
ALTER TABLE vps ADD COLUMN http_probe_healthy INTEGER;
ALTER TABLE vps ADD COLUMN http_probe_last_at DATETIME;
ALTER TABLE vps ADD COLUMN http_probe_last_error TEXT;
ALTER TABLE vps ADD COLUMN tcp_reachable INTEGER;
ALTER TABLE vps ADD COLUMN tcp_checked_at DATETIME;
ALTER TABLE vps ADD COLUMN bandwidth TEXT;
ALTER TABLE vps ADD COLUMN cpu_cores REAL;
ALTER TABLE vps ADD COLUMN ram_gb REAL;
ALTER TABLE vps ADD COLUMN disk_gb REAL;
