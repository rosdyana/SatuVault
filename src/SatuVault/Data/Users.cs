using Dapper;
using Microsoft.Extensions.Options;
using SatuVault.Crypto;

namespace SatuVault.Data;

public sealed record UserRecord(
    string Id,
    string Email,
    string Name,
    bool TotpEnrolled,
    bool IsAdmin,
    bool Disabled,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    DateTime? TotpLockedUntil);

public enum TotpOutcome { Ok, Invalid, Locked, NotEnrolled }

public sealed record TotpResult(TotpOutcome Outcome, DateTime? LockedUntil = null, int FailuresLeft = 0)
{
    public bool Ok => Outcome == TotpOutcome.Ok;
}

public sealed class Users(Db db, FieldCipher cipher, BlindIndex index, IOptions<SatuOptions> options, TimeProvider clock)
{
    private sealed class Row
    {
        public string Id { get; set; } = "";
        public byte[] EmailEnc { get; set; } = [];
        public byte[] NameEnc { get; set; } = [];
        public DateTime? TotpEnrolledAt { get; set; }
        public bool IsAdmin { get; set; }
        public bool Disabled { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public DateTime? TotpLockedUntil { get; set; }
    }

    private const string Columns = """
        id AS Id, email_enc AS EmailEnc, name_enc AS NameEnc, totp_enrolled_at AS TotpEnrolledAt,
        is_admin AS IsAdmin, disabled AS Disabled, created_at AS CreatedAt, last_login_at AS LastLoginAt,
        totp_locked_until AS TotpLockedUntil
        """;

    private UserRecord Map(Row r) => new(
        r.Id,
        cipher.DecryptString(r.EmailEnc, FieldCipher.Aad("users", "email", r.Id)),
        cipher.DecryptString(r.NameEnc, FieldCipher.Aad("users", "name", r.Id)),
        r.TotpEnrolledAt is not null, r.IsAdmin, r.Disabled, r.CreatedAt, r.LastLoginAt, r.TotpLockedUntil);

    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    /// <summary>Create or refresh the user behind an Entra sign-in. Returns (user, created).</summary>
    public async Task<(UserRecord User, bool Created)> UpsertFromSignInAsync(string tenantId, string objectId, string email, string name)
    {
        var oidIdx = index.Compute("oid", $"{tenantId}/{objectId}");
        await using var c = await db.OpenAsync();
        var id = await c.QuerySingleOrDefaultAsync<string>("SELECT id FROM users WHERE oid_idx = @oidIdx", new { oidIdx });
        var created = id is null;
        id ??= Guid.NewGuid().ToString();
        var p = new
        {
            id,
            oidIdx,
            emailIdx = index.Compute("email", email),
            emailEnc = cipher.EncryptString(email, FieldCipher.Aad("users", "email", id)),
            nameEnc = cipher.EncryptString(name, FieldCipher.Aad("users", "name", id)),
            now = Now,
        };
        if (created)
        {
            await c.ExecuteAsync("""
                INSERT INTO users (id, oid_idx, email_idx, email_enc, name_enc, created_at, last_login_at)
                VALUES (@id, @oidIdx, @emailIdx, @emailEnc, @nameEnc, @now, @now)
                """, p);
        }
        else
        {
            await c.ExecuteAsync("""
                UPDATE users SET email_idx = @emailIdx, email_enc = @emailEnc, name_enc = @nameEnc, last_login_at = @now
                WHERE id = @id
                """, p);
        }
        return ((await GetAsync(id))!, created);
    }

    public async Task<UserRecord?> GetAsync(string id)
    {
        await using var c = await db.OpenAsync();
        var r = await c.QuerySingleOrDefaultAsync<Row>($"SELECT {Columns} FROM users WHERE id = @id", new { id });
        return r is null ? null : Map(r);
    }

    public async Task<UserRecord?> FindByEmailAsync(string email)
    {
        await using var c = await db.OpenAsync();
        var r = await c.QueryFirstOrDefaultAsync<Row>($"SELECT {Columns} FROM users WHERE email_idx = @idx", new { idx = index.Compute("email", email) });
        return r is null ? null : Map(r);
    }

    public async Task<List<UserRecord>> ListAsync()
    {
        await using var c = await db.OpenAsync();
        return (await c.QueryAsync<Row>($"SELECT {Columns} FROM users")).Select(Map).OrderBy(u => u.Email).ToList();
    }

    public async Task<Dictionary<string, UserRecord>> GetManyAsync(IEnumerable<string> ids)
    {
        var list = ids.Distinct().ToArray();
        if (list.Length == 0) return [];
        await using var c = await db.OpenAsync();
        return (await c.QueryAsync<Row>($"SELECT {Columns} FROM users WHERE id IN @list", new { list })).Select(Map).ToDictionary(u => u.Id);
    }

    public async Task<bool> AnyAdminAsync()
    {
        await using var c = await db.OpenAsync();
        return await c.ExecuteScalarAsync<bool>("SELECT EXISTS (SELECT 1 FROM users WHERE is_admin AND NOT disabled)");
    }

    public async Task SetAdminAsync(string id, bool isAdmin)
    {
        await using var c = await db.OpenAsync();
        await c.ExecuteAsync("UPDATE users SET is_admin = @isAdmin WHERE id = @id", new { id, isAdmin });
    }

    public async Task SetDisabledAsync(string id, bool disabled)
    {
        await using var c = await db.OpenAsync();
        await c.ExecuteAsync("UPDATE users SET disabled = @disabled WHERE id = @id", new { id, disabled });
    }

    // ---- TOTP ----

    private string TotpAad(string id) => FieldCipher.Aad("users", "totp_secret", id);

    /// <summary>Start (or restart) enrollment: a new secret that is not active until confirmed.</summary>
    public async Task<byte[]> BeginEnrollmentAsync(string id)
    {
        var secret = Totp.NewSecret();
        await using var c = await db.OpenAsync();
        var n = await c.ExecuteAsync("""
            UPDATE users SET totp_secret_enc = @enc, totp_last_step = 0, totp_failures = 0
            WHERE id = @id AND totp_enrolled_at IS NULL
            """, new { id, enc = cipher.Encrypt(secret, TotpAad(id)) });
        if (n != 1) throw new InvalidOperationException("Authenticator is already enrolled");
        return secret;
    }

    public async Task<byte[]?> GetPendingSecretAsync(string id)
    {
        await using var c = await db.OpenAsync();
        var enc = await c.QuerySingleOrDefaultAsync<byte[]?>(
            "SELECT totp_secret_enc FROM users WHERE id = @id AND totp_enrolled_at IS NULL", new { id });
        return enc is null ? null : cipher.Decrypt(enc, TotpAad(id));
    }

    /// <summary>Confirm enrollment with a first code from the app.</summary>
    public Task<TotpResult> ConfirmEnrollmentAsync(string id, string code) => CheckAsync(id, code, enrolling: true);

    /// <summary>Verify a code for a reveal/copy/admin action. One code works once; repeated failures lock.</summary>
    public Task<TotpResult> VerifyCodeAsync(string id, string code) => CheckAsync(id, code, enrolling: false);

    private async Task<TotpResult> CheckAsync(string id, string code, bool enrolling)
    {
        var opt = options.Value;
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        var u = await c.QuerySingleOrDefaultAsync<(byte[]? Enc, DateTime? Enrolled, long LastStep, int Failures, DateTime? LockedUntil)>(
            "SELECT totp_secret_enc, totp_enrolled_at, totp_last_step, totp_failures, totp_locked_until FROM users WHERE id = @id FOR UPDATE",
            new { id }, tx);
        if (u.Enc is null || (u.Enrolled is null) != enrolling) return new TotpResult(TotpOutcome.NotEnrolled);
        var now = Now;
        if (u.LockedUntil > now) return new TotpResult(TotpOutcome.Locked, u.LockedUntil);

        var step = Totp.Verify(cipher.Decrypt(u.Enc, TotpAad(id)), code, clock.GetUtcNow(), u.LastStep);
        if (step is not null)
        {
            await c.ExecuteAsync("""
                UPDATE users SET totp_last_step = @step, totp_failures = 0, totp_locked_until = NULL,
                       totp_enrolled_at = COALESCE(totp_enrolled_at, @now)
                WHERE id = @id
                """, new { id, step, now }, tx);
            await tx.CommitAsync();
            return new TotpResult(TotpOutcome.Ok);
        }

        var failures = u.Failures + 1;
        DateTime? lockedUntil = failures >= opt.TotpMaxFailures ? now.AddMinutes(opt.TotpLockoutMinutes) : null;
        await c.ExecuteAsync(
            "UPDATE users SET totp_failures = @f, totp_locked_until = @lockedUntil WHERE id = @id",
            new { id, f = lockedUntil is null ? failures : 0, lockedUntil }, tx);
        await tx.CommitAsync();
        return lockedUntil is null
            ? new TotpResult(TotpOutcome.Invalid, FailuresLeft: opt.TotpMaxFailures - failures)
            : new TotpResult(TotpOutcome.Locked, lockedUntil);
    }

    /// <summary>Admin reset: the user must enroll again at next sign-in.</summary>
    public async Task ResetTotpAsync(string id)
    {
        await using var c = await db.OpenAsync();
        await c.ExecuteAsync("""
            UPDATE users SET totp_secret_enc = NULL, totp_enrolled_at = NULL, totp_last_step = 0,
                   totp_failures = 0, totp_locked_until = NULL
            WHERE id = @id
            """, new { id });
    }
}
