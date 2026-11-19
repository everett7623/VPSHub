# VPSHub

Self-hosted, security-first Linux VPS management panel (agentless SSH).

## Features (Phase 1–6 + ideas from [server-panel](https://github.com/naibabiji/server-panel))

- Admin login with Argon2id + mandatory TOTP, cookie sessions, CSRF, security headers
- Master-key vault (Locked / Unlocked / Expired) with AES-256-GCM credential encryption
- **Independent view-password** to reveal secrets (one-time 2‑min token; 5 failures wipe credential copies)
- VPS inventory CRUD, CSV import, operation modes, billing/renewal fields, soft delete
- **Providers** and **Websites** (domain expiry + HTTP probe), dashboard overview
- SSH short connections with host-key pinning (no `InsecureIgnoreHostKey`)
- Background HTTP/TCP probes + expiry alerts; auto-renewal date advance
- Read-only server scan + service fingerprint matrix
- Persistent task worker (canary, rolling batches, fail threshold, dry-run)
- Script center with review workflow + SHA256
- Dedicated service upgrade modules (pinned version + SHA256 required)
- Encrypted panel backup, master-key rotation, recovery key
- Alerts via Telegram / Webhook / SMTP; alert rules; SMTP test
- Optional `base_path` obscure entry; trusted proxy / CF-Connecting-IP
- Bilingual UI (zh-CN / en-US)
- WebSSH / SFTP **disabled by default**; API tokens; password→Ed25519 conversion
- Frontend embeddable via `web` package (`go:embed dist`)

## Quick start (local)

```bash
# Backend
go run ./cmd/vpshub -config config.yaml

# Frontend (dev)
cd web && npm install && npm run dev
```

Panel listens on `127.0.0.1:8080` by default. Put Caddy, Nginx, Tailscale, or WireGuard in front for remote access.

### Install on a Linux server

From a checkout on the target host:

```bash
sudo bash scripts/install.sh
```

This binds a random high port on `127.0.0.1`, creates the system user `vpshub`, installs `deploy/vpshub.service`, and prints a one-time summary (also written to `/root/vpshub-install.txt`, mode `0600`). Delete that file after you save it offline. Reach the panel through an SSH tunnel or Tailscale.

```bash
sudo bash scripts/install.sh --public
```

`--public` binds `0.0.0.0` with a self-signed certificate. The installer does not open firewall ports. Restrict the port yourself, and put Caddy or Tailscale in front when you can.

Local commands after install: `vpshub status`, `vpshub password`, `vpshub restart`. `vpshub -config config.yaml` still starts the server.

### First-run flow

The Linux installer already creates the admin, so skip setup on that host and start at the password change. For a local dev run:

1. Open `/setup` — create admin
2. Scan TOTP URL into authenticator
3. Login with password + TOTP
4. Initialize vault with a long master password — **store the recovery key offline**
5. Add VPS, unlock vault, set credentials, test SSH (confirm host key)

## Docker Compose

```bash
docker compose up -d --build
```

Binds `127.0.0.1:8080` only.

## Configuration

See `config.yaml` and env overrides: `VPSHUB_LISTEN`, `VPSHUB_DATA_DIR`, `VPSHUB_SECURE_COOKIE`, `VPSHUB_WEBSSH`, `VPSHUB_MIGRATIONS`. Optional `basic_auth_user` / `basic_auth_hash` protect every route, including `/healthz`. `tls_cert` and `tls_key` turn on HTTPS.

## Ops (中文)

运维与验收清单见 [docs/ops-zh.md](docs/ops-zh.md)。`GET /healthz` 返回 `ok`、`vault`、`version`、`db_ok`。

## Security

Read [SECURITY.md](SECURITY.md). Never expose the panel directly to the public internet without TLS termination and network controls.

## Development checks

```bash
# Windows: scripts/check.ps1
# Unix: scripts/check.sh
go test ./...
go vet ./...
# optional: gosec ./... && govulncheck ./...
```

CI (`.github/workflows/ci.yml`) runs vet, tests, govulncheck, gosec, and the web build.

After restoring a panel backup to `vpshub.db.restored`, stop the process and run `vpshub restore-db -yes`.
