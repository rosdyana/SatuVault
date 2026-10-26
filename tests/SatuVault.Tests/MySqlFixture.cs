using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using MySqlConnector;
using SatuVault.Audit;
using SatuVault.Crypto;
using SatuVault.Data;
using SatuVault.Security;
using SatuVault.Services;

namespace SatuVault.Tests;

/// <summary>
/// A fresh database per test class, migrated as root, used through a least-privilege
/// app account exactly like production. MySQL from SATU_TEST_MYSQL (default: the
/// docker container on 127.0.0.1:53306, root/test).
/// </summary>
public sealed class TestDb : IAsyncDisposable
{
    public static string Server => Environment.GetEnvironmentVariable("SATU_TEST_MYSQL") ?? "Server=127.0.0.1;Port=53306;User ID=root;Password=test";

    public string Name { get; }
    public string RootConnectionString { get; }
    public string AppConnectionString { get; }
    public string AppUser { get; }

    private TestDb(string name, string root, string app, string appUser)
    {
        Name = name;
        RootConnectionString = root;
        AppConnectionString = app;
        AppUser = appUser;
    }

    public static async Task<TestDb> CreateAsync()
    {
        var name = $"satu_test_{Guid.NewGuid():N}"[..24];
        var appUser = $"app_{name[10..]}";
        await using (var c = new MySqlConnection(Server))
        {
            await c.OpenAsync();
            await c.ExecuteAsync($"CREATE DATABASE `{name}`");
            await c.ExecuteAsync($"CREATE USER '{appUser}'@'%' IDENTIFIED BY 'app-pass'");
        }
        var root = $"{Server};Database={name}";
        await Migrator.MigrateAsync(root);
        await Migrator.GrantAppUserAsync(root, appUser, "%");
        var app = $"Server=127.0.0.1;Port={new MySqlConnectionStringBuilder(Server).Port};User ID={appUser};Password=app-pass;Database={name}";
        return new TestDb(name, root, app, appUser);
    }

    public async Task<MySqlConnection> RootAsync()
    {
        var c = new MySqlConnection(Data.Db.Normalize(RootConnectionString));
        await c.OpenAsync();
        return c;
    }

    public async ValueTask DisposeAsync()
    {
        await using var c = new MySqlConnection(Server);
        await c.OpenAsync();
        await c.ExecuteAsync($"DROP DATABASE IF EXISTS `{Name}`");
        await c.ExecuteAsync($"DROP USER IF EXISTS '{AppUser}'@'%'");
    }
}

/// <summary>All app services wired over a <see cref="TestDb"/>, with a controllable clock.</summary>
public sealed class Env : IAsyncDisposable
{
    public TestDb Db { get; }
    public KeyRing Keys { get; } = KeyRing.CreateNew(KeyProtection.None);
    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
    public SatuOptions Options { get; } = new() { KeyDirectory = Directory.CreateTempSubdirectory().FullName };
    public FieldCipher Cipher { get; }
    public Users Users { get; }
    public Teams Teams { get; }
    public Items Items { get; }
    public Servers Servers { get; }
    public AuditLog Audit { get; }
    public VaultService Vault { get; }

    public static readonly RequestInfo Req = new("10.1.2.3", "xunit");

    private Env(TestDb tdb)
    {
        Db = tdb;
        var db = new Db(tdb.AppConnectionString);
        Cipher = new FieldCipher(Keys);
        Users = new Users(db, Cipher, new BlindIndex(Keys), Microsoft.Extensions.Options.Options.Create(Options), Clock);
        Teams = new Teams(db, Cipher, Clock);
        Items = new Items(db, Cipher, Clock);
        Servers = new Servers(db, Cipher, Clock);
        Audit = new AuditLog(db, Cipher, Keys, NullLogger<AuditLog>.Instance);
        Vault = new VaultService(db, Items, Servers, Teams, Users, Audit);
    }

    public static async Task<Env> CreateAsync() => new(await TestDb.CreateAsync());

    public ValueTask DisposeAsync() => Db.DisposeAsync();

    /// <summary>A signed-in, enrolled user; returns their TOTP secret for generating codes.</summary>
    public async Task<(UserRecord User, byte[] Secret)> EnrolledUserAsync(string email)
    {
        var (u, _) = await Users.UpsertFromSignInAsync("tenant-1", Guid.NewGuid().ToString(), email, email.Split('@')[0]);
        var secret = await Users.BeginEnrollmentAsync(u.Id);
        Assert.True((await Users.ConfirmEnrollmentAsync(u.Id, Code(secret))).Ok);
        NextStep();
        return ((await Users.GetAsync(u.Id))!, secret);
    }

    public string Code(byte[] secret) => Totp.Code(secret, Totp.StepAt(Clock.GetUtcNow()));

    /// <summary>Codes are single-use; move to the next 30 s window.</summary>
    public void NextStep() => Clock.Advance(TimeSpan.FromSeconds(30));

    public async Task<AppUser> AsAppUserAsync(string userId)
    {
        var u = (await Users.GetAsync(userId))!;
        var all = (await Teams.ListAsync()).Select(t => t.Id).ToList();
        return new AppUser(u, await Teams.RolesOfAsync(userId), all);
    }

    public async Task<List<AuditEvent>> AuditAsync(string? actionPrefix = null) =>
        (await Audit.QueryAsync(new AuditFilter(ActionPrefix: actionPrefix, Limit: 1000))).OrderBy(e => e.Seq).ToList();
}
