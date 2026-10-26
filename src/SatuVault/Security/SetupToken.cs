using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Options;
using SatuVault.Audit;
using SatuVault.Data;

namespace SatuVault.Security;

public enum SetupOutcome { Ok, AlreadyDone, BadToken, NoTokenFile }

/// <summary>
/// First-installer bootstrap. <c>init</c> writes the SHA-256 of a random token next to
/// the master key; while setup isn't done, the first signed-in, enrolled user who
/// enters that token becomes admin. A settings row makes it single-use.
/// </summary>
public sealed class SetupToken(Db db, AuditLog audit, IOptions<SatuOptions> options)
{
    private sealed record TokenFile(string Sha256);

    public static string Generate() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_');

    public static void WriteHash(string path, string token)
    {
        var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        File.WriteAllText(path, JsonSerializer.Serialize(new TokenFile(hash)));
    }

    public async Task<bool> IsDoneAsync()
    {
        await using var c = await db.OpenAsync();
        return await c.ExecuteScalarAsync<bool>("SELECT EXISTS (SELECT 1 FROM settings WHERE name = 'setup_done')");
    }

    public async Task<SetupOutcome> ClaimAsync(string userId, RequestInfo req, string token)
    {
        var path = options.Value.SetupTokenPath;
        if (!File.Exists(path)) return SetupOutcome.NoTokenFile;
        var stored = Convert.FromBase64String(JsonSerializer.Deserialize<TokenFile>(File.ReadAllText(path))!.Sha256);
        var given = SHA256.HashData(Encoding.UTF8.GetBytes(token.Trim()));

        if (await IsDoneAsync()) return SetupOutcome.AlreadyDone;
        if (!CryptographicOperations.FixedTimeEquals(stored, given))
        {
            await audit.WriteAsync(userId, req, "setup.failed");
            return SetupOutcome.BadToken;
        }

        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        try
        {
            // The primary key makes this single-use even if two people submit at once.
            await c.ExecuteAsync("INSERT INTO settings (name, value) VALUES ('setup_done', @v)", new { v = Encoding.UTF8.GetBytes(userId) }, tx);
        }
        catch (MySqlConnector.MySqlException e) when (e.ErrorCode == MySqlConnector.MySqlErrorCode.DuplicateKeyEntry)
        {
            return SetupOutcome.AlreadyDone;
        }
        await c.ExecuteAsync("UPDATE users SET is_admin = TRUE WHERE id = @userId", new { userId }, tx);
        await audit.WriteAsync(c, tx, userId, req, "setup.admin", "user", userId);
        await tx.CommitAsync();
        return SetupOutcome.Ok;
    }
}
