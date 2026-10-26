# SatuVault — Architecture

Internal web platform that replaces spreadsheets/notepad for team credentials, secret
text and server inventory. One ASP.NET Core app in IIS (`https://abc.yyy.com/this_platform`)
plus MySQL. No browser-side crypto, no extra services.

Status (2026-10-25): v1 built — all of §1 implemented, 36 tests passing (crypto, MySQL
integration incl. a scan that finds no plaintext in any table, and in-process web tests).
Not yet run against a real Entra tenant or a Windows/IIS host (DPAPI path untested on macOS).

## 1. Requirements → design

| Requirement | Design |
|---|---|
| Sign in with company Microsoft account | Entra ID app registration, OpenID Connect (code + PKCE), single tenant. Optional "Assignment required" on the enterprise app limits who can sign in. |
| Authenticator app on first login | Before anything else the user enrolls TOTP (RFC 6238, Google/Microsoft Authenticator, any app): scan QR, confirm one code. |
| Code for every reveal/copy | `POST …/reveal` with a fresh code; server verifies before decrypting. |
| Teams, members add/edit/remove | Teams with `manager` (manages members) and `member` (CRUD items and servers). Platform admins see and manage everything. |
| Server inventory | Hostname, IP, OS, CPU, RAM, disk, asset ID, environment, notes; credentials can link to a server. People connect with their own RDP/SSH client (optional `.rdp` download, never with a password). |
| "All data highly encrypted" | Every human-readable value is AES-256-GCM encrypted by the app before it reaches MySQL (§3). |
| Detailed logs | Append-only audit table, HMAC-chained with a key MySQL never sees (§4). |
| First installer is admin | `init` generates a one-time setup token; the first signed-in user who enters it becomes admin. |

## 2. Components

```
Browser ──HTTPS── IIS (TLS, /this_platform app, ASP.NET Core Module, in-process)
                    └── SatuVault (ASP.NET Core 10, Razor Pages)
                          ├── Entra ID (OIDC sign-in)
                          ├── keys/master.key  (DPAPI-protected)
                          └── MySQL 8 (TLS required)
```

- Razor Pages (server-rendered); one small JS file for reveal/copy and confirm dialogs. No SPA, no npm.
  UI assets are self-hosted under `wwwroot` (the CSP allows no CDNs and no inline styles): Geist and
  Geist Mono fonts (OFL, `fonts/OFL.txt`), Phosphor icons as an SVG sprite (MIT, `icons.svg`).
- NuGet dependencies: MySqlConnector, Dapper, QRCoder, Microsoft.AspNetCore.Authentication.OpenIdConnect.
  TOTP, encryption and the audit chain are implemented in-repo on .NET's built-in crypto.
- The same executable has CLI commands: `init`, `migrate`, `backup-key`, `restore-key`, `verify-audit`.

## 3. Encryption

- **Master key**: 256-bit random, created by `init`, stored in `keys/master.key` protected
  with DPAPI (scope: the IIS app pool account; `loadUserProfile=true`). Unreadable on any
  other machine or account. Non-Windows dev hosts store it unprotected and the app refuses
  to start that way in Production.
- **Backup**: `init` / `backup-key` also writes the master key encrypted with an admin
  passphrase (PBKDF2-SHA256 600k → AES-256-GCM). Losing both the machine and the backup
  loses every secret — keep the backup offline.
- **Subkeys** via HKDF-SHA256 from the master key: `data`, `index`, `audit`, `totp`.
- **Field encryption**: AES-256-GCM, random 96-bit nonce, AAD = `table.column:rowId` (a
  ciphertext can't be moved to another row/column). Format: `version | keyId | nonce | tag | ct`
  so keys can rotate.
- **What is plaintext in MySQL**: ids (UUIDs), foreign keys, timestamps, enums (item kind,
  role, audit action), counters. Everything else — names, emails, titles, usernames, URLs,
  passwords, secret text, notes, server details, audit details (IP, user agent, labels) —
  is ciphertext.
- **Lookups without plaintext**: Entra object id and email use a blind index
  (HMAC-SHA256 with the `index` key). Text search decrypts the caller's visible rows in
  memory (fine for thousands of items).
- **Items** are two ciphertexts: `meta` (title, username, URL, tags) for lists and
  `secret` (password / secret text / notes), decrypted only by the reveal endpoint.
- Recommended on the MySQL side as well: InnoDB tablespace encryption and `require_secure_transport`.

## 4. Audit trail

- Table `audit_events(seq, ts, actor_id, action, target_type, target_id, details_enc, mac)`.
  `details_enc` holds IP, user agent, item/server/team label and action-specific data.
- `mac = HMAC-SHA256(audit key, prev_mac ‖ seq ‖ ts ‖ actor ‖ action ‖ target ‖ details_enc)`,
  written under a row lock on `audit_head`. A DBA can't edit, insert or delete a row
  without breaking the chain, because the key isn't in the database.
- The app's DB user has `SELECT, INSERT` on `audit_events` only (no UPDATE/DELETE).
- Every write also logs `seq` + `mac` to the application log, an external anchor that
  detects truncation of the newest rows.
- Events: sign-in/out, TOTP enroll/fail/lockout/reset, item create/update/delete/restore/
  reveal/copy, server create/update/delete, team and membership changes, admin changes,
  setup, audit export.
- Admin page: filter by user / action / target / date, verify chain, CSV export (itself audited).

## 5. TOTP rules

- SHA-1, 6 digits, 30 s, ±1 step tolerance. Secret: 160 random bits, encrypted (`totp` key).
- A code is accepted once: the last used step is stored, older/equal steps are rejected.
  Two reveals in a row therefore need the next code (≤ 30 s wait).
- 5 wrong codes → locked for 15 minutes (audited). Admins can reset a user's enrollment
  (requires the admin's own code; audited); the user re-enrolls at next sign-in.

## 6. Web security

- Cookie session: `Secure`, `HttpOnly`, `SameSite=Lax`, path `/this_platform`, 8 h max,
  30 min idle. Data Protection keys persisted to `keys/` and DPAPI-protected.
- Antiforgery on every POST, CSP `default-src 'self'` (no inline script), `frame-ancestors 'none'`,
  `Referrer-Policy: same-origin`, `Cache-Control: no-store` on pages with secrets.
- Revealed values are returned to `fetch()` only (never rendered into HTML), auto-hidden
  after 30 s; copied values are cleared from the clipboard after 30 s where the browser allows.
- Disabled users (in-app) are signed out on their next request.

## 7. Data model (MySQL 8)

```
users(id, oid_idx UNIQUE, email_idx, email_enc, name_enc, totp_secret_enc, totp_enrolled_at,
      totp_last_step, totp_failures, totp_locked_until, is_admin, disabled, created_at, last_login_at)
teams(id, name_enc, created_at, created_by)
team_members(team_id, user_id, role, added_at, added_by)
servers(id, team_id, data_enc, created_*, updated_*, deleted_at)
items(id, team_id, kind, server_id NULL, meta_enc, secret_enc, version, created_*, updated_*, deleted_at)
item_versions(item_id, version, meta_enc, secret_enc, changed_at, changed_by)
audit_events(seq, ts, actor_id, action, target_type, target_id, details_enc, mac)
audit_head(id = 1, seq, mac)
settings(name, value)            -- setup token hash, schema version
```

## 8. Deployment (IIS)

1. Install the ASP.NET Core 10 Hosting Bundle; create app pool (No Managed Code,
   `loadUserProfile=true`), add application `/this_platform` under the existing site.
2. `SatuVault.exe init` (as the app pool identity): master key, passphrase backup, setup token.
3. `SatuVault.exe migrate` with a DB admin connection string; it creates the app DB user grants.
4. Configure `appsettings.Production.json`: Entra tenant/client id/secret, MySQL connection
   (`SslMode=Required`). Redirect URI: `https://abc.yyy.com/this_platform/signin-oidc`.
5. First sign-in → enroll authenticator → Setup page → enter the token → admin.

## 9. Not in scope (v1)

Remote-desktop gateway (dropped), browser extension/autofill, mobile app, Entra group
sync (teams are managed in the app), SIEM forwarding (CSV export now; the app log can be
shipped later).
