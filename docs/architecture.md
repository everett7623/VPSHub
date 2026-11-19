# Architecture

```
Browser → Gin API → SQLite WAL
                 → Vault (in-memory KEK)
                 → sshx short connections → VPS
                 → Task Worker (poll SQLite)
```

## Packages

| Package | Role |
|---------|------|
| `internal/crypto` | Argon2id, AES-GCM, vault state machine |
| `internal/auth` | Admin, TOTP, sessions, locks |
| `internal/store` | SQLite access + migrations |
| `internal/sshx` | SSH/SFTP short sessions, host keys |
| `internal/collector` | Read-only scan script + fingerprints |
| `internal/tasks` | Persistent worker pool |
| `internal/scripts` | Script review helpers |
| `internal/services` | Pinned upgrade modules |
| `internal/backup` | Encrypted panel backup + key rotate |
| `internal/alert` | Telegram / Webhook / SMTP |
| `internal/api` | HTTP handlers |

## Phase map

1. Security + assets
2. Scan + matrix
3. Tasks
4. Scripts + upgrades
5. Backup + alerts
6. WebSSH/SFTP (off by default), API tokens, key conversion
