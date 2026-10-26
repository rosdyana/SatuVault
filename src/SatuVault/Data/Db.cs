using System.Reflection;
using Dapper;
using MySqlConnector;

namespace SatuVault.Data;

public sealed class Db(string connectionString)
{
    private readonly string _cs = Normalize(connectionString);

    /// <summary>Ids are CHAR(36) strings in this app; stop the driver turning them into Guid.</summary>
    public static string Normalize(string cs) => new MySqlConnectionStringBuilder(cs) { GuidFormat = MySqlGuidFormat.None }.ConnectionString;

    public async Task<MySqlConnection> OpenAsync()
    {
        var c = new MySqlConnection(_cs);
        await c.OpenAsync();
        return c;
    }
}

/// <summary>Applies the embedded Data/Migrations/*.sql files once each, in name order.</summary>
public static class Migrator
{
    public static async Task<IReadOnlyList<string>> MigrateAsync(string adminConnectionString)
    {
        await using var c = new MySqlConnection(Db.Normalize(adminConnectionString));
        await c.OpenAsync();
        await c.ExecuteAsync("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                name VARCHAR(128) NOT NULL PRIMARY KEY,
                applied_at DATETIME(6) NOT NULL
            ) ENGINE=InnoDB
            """);
        var applied = (await c.QueryAsync<string>("SELECT name FROM schema_migrations")).ToHashSet();
        var done = new List<string>();
        var asm = Assembly.GetExecutingAssembly();
        foreach (var res in asm.GetManifestResourceNames().Where(n => n.EndsWith(".sql")).Order())
        {
            var name = res[(res.IndexOf("Migrations.", StringComparison.Ordinal) + "Migrations.".Length)..];
            if (applied.Contains(name)) continue;
            await using var stream = asm.GetManifestResourceStream(res)!;
            var sql = await new StreamReader(stream).ReadToEndAsync();
            // MySQL DDL auto-commits, so a failed file must be fixed by hand; keep files small.
            await c.ExecuteAsync(sql);
            await c.ExecuteAsync("INSERT INTO schema_migrations (name, applied_at) VALUES (@name, UTC_TIMESTAMP(6))", new { name });
            done.Add(name);
        }
        return done;
    }

    /// <summary>
    /// Least privilege for the app's own DB user: full DML on its tables, but only
    /// SELECT + INSERT on the audit trail.
    /// </summary>
    public static async Task GrantAppUserAsync(string adminConnectionString, string appUser, string appHost)
    {
        await using var c = new MySqlConnection(Db.Normalize(adminConnectionString));
        await c.OpenAsync();
        var schema = c.Database;
        var account = $"'{Escape(appUser)}'@'{Escape(appHost)}'";
        var tables = await c.QueryAsync<string>(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = @schema", new { schema });
        foreach (var t in tables)
        {
            var privileges = t switch
            {
                "audit_events" => "SELECT, INSERT",
                "schema_migrations" => "SELECT",
                _ => "SELECT, INSERT, UPDATE, DELETE",
            };
            try
            {
                await c.ExecuteAsync($"REVOKE ALL PRIVILEGES ON `{schema}`.`{t}` FROM {account}");
            }
            catch (MySqlException e) when (e.ErrorCode == MySqlErrorCode.NonExistingTableGrant)
            {
                // nothing granted yet
            }
            await c.ExecuteAsync($"GRANT {privileges} ON `{schema}`.`{t}` TO {account}");
        }
    }

    private static string Escape(string s) =>
        s.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-' or '.' or '%')
            ? s
            : throw new ArgumentException($"Unsupported characters in MySQL account name: {s}");
}
