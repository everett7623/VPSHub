package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func Open(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "vpshub.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)",
		filepath.ToSlash(dbPath))
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	db := &DB{sqlDB}
	if err := db.migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func migrationsDir() string {
	if d := os.Getenv("VPSHUB_MIGRATIONS"); d != "" {
		return d
	}
	// Prefer cwd/migrations, then relative to this source file (dev).
	if st, err := os.Stat("migrations"); err == nil && st.IsDir() {
		return "migrations"
	}
	_, file, _, ok := runtime.Caller(0)
	if ok {
		cand := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return "migrations"
}

func (db *DB) migrate() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}
	path := migrationsDir()
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read migrations %s: %w", path, err)
	}
	migRoot, err := os.OpenRoot(path)
	if err != nil {
		return fmt.Errorf("open migrations %s: %w", path, err)
	}
	defer migRoot.Close()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var exists int
		_ = db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version=?`, e.Name()).Scan(&exists)
		if exists > 0 {
			continue
		}
		b, err := migRoot.ReadFile(e.Name())
		if err != nil {
			return err
		}
		for _, stmt := range splitSQL(string(b)) {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("migration %s: %w\nstmt: %s", e.Name(), err, truncate(stmt, 120))
			}
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(version) VALUES(?)`, e.Name()); err != nil {
			return err
		}
	}
	return nil
}

func splitSQL(s string) []string {
	var out []string
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		if strings.HasSuffix(strings.TrimSpace(b.String()), ";") {
			stmt := strings.TrimSpace(b.String())
			if stmt != "" && stmt != ";" {
				out = append(out, stmt)
			}
			b.Reset()
		}
	}
	if rest := strings.TrimSpace(b.String()); rest != "" {
		out = append(out, rest)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
