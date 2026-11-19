-- Immutable script body snapshots for publish / pre-edit history.
CREATE TABLE IF NOT EXISTS script_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    content TEXT NOT NULL,
    rollback_content TEXT,
    healthcheck_content TEXT,
    params_schema TEXT DEFAULT '[]',
    risk_level TEXT NOT NULL DEFAULT 'medium',
    status_at_snapshot TEXT NOT NULL,
    note TEXT,
    created_by TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_script_versions_script ON script_versions(script_id, id DESC);
