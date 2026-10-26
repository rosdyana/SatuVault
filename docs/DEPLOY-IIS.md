# Deploying SatuVault on IIS (`https://abc.yyy.com/this_platform`)

## 0. What you need

- Windows Server with IIS, the existing site `abc.yyy.com` on HTTPS.
- [ASP.NET Core 10 Hosting Bundle](https://dotnet.microsoft.com/download/dotnet/10.0) (restart IIS after installing).
- MySQL 8.0+ reachable from the IIS server, TLS on (`require_secure_transport=ON` recommended).
- An Entra ID app registration (step 3).
- A dedicated Windows service account for the app pool, e.g. `CORP\svc-satuvault`.
  The master key is DPAPI-encrypted **for this account**, so `init` must run as it.

## 1. Build

On any machine with the .NET 10 SDK:

```powershell
dotnet publish src/SatuVault -c Release -r win-x64 --self-contained false -o publish
```

Copy `publish\` to e.g. `D:\apps\satuvault\` on the server.

## 2. MySQL

```sql
CREATE DATABASE satuvault CHARACTER SET utf8mb4;
CREATE USER 'satuvault_app'@'iis-server-ip' IDENTIFIED BY '<long random password>' REQUIRE SSL;
-- an admin account for migrations (can be your DBA account)
```

Create `D:\apps\satuvault\appsettings.Production.json` (readable only by the service account and admins):

```json
{
  "ConnectionStrings": {
    "App":   "Server=mysql01;Database=satuvault;User ID=satuvault_app;Password=...;SslMode=VerifyFull",
    "Admin": "Server=mysql01;Database=satuvault;User ID=dba;Password=...;SslMode=VerifyFull"
  },
  "Entra": { "TenantId": "<tenant id>", "ClientId": "<client id>", "ClientSecret": "<secret>" },
  "SatuVault": { "KeyDirectory": "D:\\apps\\satuvault-keys", "DisplayTimeZone": "SE Asia Standard Time" }
}
```

Apply the schema and the least-privilege grants (the app user can't update or delete audit rows):

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Production"
.\SatuVault.exe migrate --app-user satuvault_app --app-host iis-server-ip
```

Afterwards remove the `Admin` connection string from the file.

## 3. Entra app registration

1. Entra admin center → App registrations → New: "SatuVault", single tenant.
2. Redirect URI (Web): `https://abc.yyy.com/this_platform/signin-oidc`.
   Front-channel logout URL: `https://abc.yyy.com/this_platform/signout-callback-oidc`.
3. Certificates & secrets → new client secret → put it in `Entra:ClientSecret`.
4. Token configuration → optional claim `email` (ID token).
5. Enterprise applications → SatuVault → Properties → **Assignment required = Yes**, then
   assign the users/groups allowed to sign in. Optionally add a Conditional Access policy.

## 4. Master key and setup token

Run **as the app pool's service account** (DPAPI binds the key to it):

```powershell
runas /user:CORP\svc-satuvault powershell
# in the new window:
cd D:\apps\satuvault
$env:ASPNETCORE_ENVIRONMENT = "Production"
.\SatuVault.exe init --backup E:\offline\satuvault-key-backup.json
```

It asks for a backup passphrase (16+ characters) and prints the **one-time setup token**.

- Move the backup file off the server; keep the passphrase somewhere else (two people).
  Without both, a dead server means every secret is gone.
- `D:\apps\satuvault-keys` must be outside the site folder. Grant only the service account
  (Modify) and Administrators; nobody else.
- If a dedicated account isn't possible: `init --protection dpapi-machine` binds the key to
  the machine instead (any process on it can read the key — weaker).

## 5. IIS

1. Application pool "SatuVault": .NET CLR version **No Managed Code**, Identity = `CORP\svc-satuvault`,
   Advanced → **Load User Profile = True** (required for DPAPI), Idle time-out 0 (optional).
2. Under the site `abc.yyy.com`: Add Application, alias `this_platform`, physical path
   `D:\apps\satuvault`, pool "SatuVault".
3. The shipped `web.config` runs the app in-process with `ASPNETCORE_ENVIRONMENT=Production`
   and adds HSTS.
4. Browse `https://abc.yyy.com/this_platform`.

## 6. First sign-in

1. Sign in with your Microsoft account → scan the QR code with an authenticator app.
2. Open `https://abc.yyy.com/this_platform/Setup`, enter the setup token and a code → you are admin.
3. Teams → create a team, add members (they must sign in once first).

## Operations

- **Verify the audit trail:** Audit log → Verify integrity, or `SatuVault.exe verify-audit`.
  The app log (`stdout` / Event Log) also records each event's sequence number and MAC as an
  external anchor.
- **Lost phone:** Users → Reset authenticator (needs your own code). The user enrolls again.
- **Leaver:** Users → Disable. Also remove them from the Entra enterprise app.
- **Backups:** MySQL dump (everything is ciphertext) + the offline key backup. Test a restore:
  `SatuVault.exe restore-key --in backup.json` on a new server as the service account.
- **Updates:** publish, stop the app pool, copy files (keep `appsettings.Production.json`), run
  `migrate` if the release notes say so, start the pool.
