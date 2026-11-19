# Features adapted from server-panel

Reference: https://github.com/naibabiji/server-panel

## Adopted

| Feature | VPSHub location |
|---------|-----------------|
| Independent view-password + one-shot reveal token | `internal/auth/viewpassword.go`, `/api/view-password/*`, `/api/*/reveal*` |
| Wipe secrets after 5 failed view attempts | same |
| CSRF double-submit cookie | `internal/middleware/security.go` |
| Security headers + HSTS | same |
| Trusted proxy / CF-Connecting-IP | `ClientIP()` |
| Optional obscure `base_path` | config `base_path` |
| Providers entity | `providers` table + API + UI |
| Websites + domain expiry | `websites` table + API + UI |
| Dashboard stats / expiring list | `/api/dashboard` |
| HTTP probe + TCP reachability loop | `internal/probe` |
| Auto-renewal date advance | `AdvanceAutoRenewals` |
| Alert rules + SMTP test | `/api/alert-rules`, `/api/smtp/test` |
| Billing fields (cycle, currency, purchase) | migration `002_*` |
| zh-CN / en-US UI toggle | `web/src/i18n.ts` |
| Embed frontend | `web/embed.go` |

## Not ported (on purpose)

- nftables IP ban (prefer Tailscale / reverse proxy)
- Built-in ACME / random install path installer (use Caddy + Compose)
- Full Agent metrics history (optional Phase 6 Agent)
- Local disk format / unrestricted file manager (use SFTP later)
- Customers CRM (single-admin first)
- Panel self-update with Ed25519 (can add later)
