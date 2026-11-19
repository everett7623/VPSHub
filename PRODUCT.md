# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary user is the operator themselves: a single admin self-hosting VPSHub to manage their own fleet of Linux VPS machines (inventory, scan, scripts, upgrades, alerts). Not a multi-tenant SaaS audience.

## Product Purpose

VPSHub is a self-hosted, security-first, agentless SSH management panel. Success means the operator can safely inventory hosts, inspect health, run reviewed tasks/scripts, and renew/monitor related assets without agents on the servers and without leaking credentials.

## Positioning

Security-first personal fleet ops panel: master-key vault for credentials, mandatory TOTP, view-password reveal, host-key pinning, script review before execution, and AI that only advises (never auto-SSH). Neighboring “generic multi-server consoles” that optimize for feature breadth rather than gated execution cannot truthfully claim this posture.

## Operating Context

Typical flow: unlock vault → manage VPS/providers/websites → Scan → checkup findings → create dry-run or reviewed tasks/scripts → matrix/fleet batch reads → alerts and backups. Runs behind localhost, tunnel, Tailscale, or reverse proxy; bilingual UI (zh-CN / en-US). Optional WebSSH/SFTP stay off by default.

## Capabilities and Constraints

Confirmed capabilities include: admin auth (Argon2id + TOTP), vault lifecycle, VPS CRUD/CSV, providers/websites + probes, scan + service matrix, task worker with dry-run/canary, script center with review/SHA256, host ops / sysupgrade modules, checkup + optional AI advise, alerts (webhook/telegram/smtp), encrypted backups, API tokens, i18n.

Explicit non-goals (do not design as if present): Agent常驻, WebAuthn, S3, asciicast, nftables解封, 面板自更新, CRM, SOCKS5 userinfo, AI auto-execution.

Stack is already decided by the codebase: Go backend + embedded React/Vite frontend + SQLite.

## Brand Commitments

Product name: **VPSHub**. Voice: direct, ops-oriented, bilingual; prefer clarity over marketing flourish on Operate surfaces.

## Evidence on Hand

- README.md — product overview and install
- docs/ops-zh.md — ops acceptance and AI config
- config.yaml — runtime feature flags
- web/src — live UI (dashboard, VPS, matrix, tasks, scripts, checkup, settings)

Do not fabricate testimonials, customer logos, or external benchmarks.

## Product Principles

1. Credentials stay gated: vault locked means no secret use; reveal needs view-password.
2. Suggest ≠ execute: scans/AI advise freely; mutating actions go through review, dry-run, and confirmation.
3. Single-admin self-host: optimize for one trusted operator, not multi-user tenancy.
4. Prefer readable ops density over decorative chrome on dashboards and matrices.
5. Bilingual parity: zh-CN and en-US remain first-class for operator-facing copy.

## Accessibility & Inclusion

No formal WCAG conformance target. Prefer keyboard-usable admin flows, visible focus, and readable contrast as craft defaults; do not block features on certification.
