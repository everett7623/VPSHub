# VPSHub Security Model

## Threat model (personal / small-team self-host)

- Attacker with DB file access must not recover SSH secrets without master password / recovery key
- Compromised session cookie is time-bounded; Secure + SameSite=Strict when behind HTTPS
- Target VPS host-key MITM is blocked after first trust (fingerprint pin)
- Malicious or unreviewed scripts must not run (`approved` / `published` only)
- High-risk actions require explicit confirmation and are audited

## Master key

| State | Behavior |
|-------|----------|
| Locked | Default after restart; no SSH / credential decrypt |
| Unlocked | KEK in process memory only; auto-expire via `vault_lock_ttl` |
| Expired | Same as locked after idle timeout |

- Argon2id derives KEK from master password + salt
- AES-256-GCM encrypts each credential with a unique nonce
- Master password is never written to DB or logs
- Recovery key hash is stored; plaintext recovery key shown once at init/rotate

## SSH

- Short-lived connections only (no connection pool)
- Host key: first connect → pending confirmation; mismatch → refuse + alert
- Prefer dedicated management user + Ed25519 keys; password→key conversion deletes DB password after verify
- Output size and command timeouts enforced

## Audit

Append-only audit log with hash chain (`prev_hash` / `entry_hash`). Secrets must never appear in `detail`.

## Defaults

- Listen `127.0.0.1`
- WebSSH off
- SFTP off
- Production sysupgrade does not auto-reboot
- No `curl | bash`, no `latest` binary upgrades without pin + SHA256

## Memory caveat

Go cannot guarantee zeroization of secrets; keep plaintext credential lifetime short and wipe buffers after use.
