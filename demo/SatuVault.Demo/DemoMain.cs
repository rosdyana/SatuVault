using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using QRCoder;
using SatuVault.Audit;
using SatuVault.Crypto;
using SatuVault.Data;
using SatuVault.Security;
using SatuVault.Services;

namespace SatuVault.Demo;

/// <summary>
/// Helper for the local demo (demo/run.sh). Reads the same settings the app gets from the
/// script's environment: ConnectionStrings__App and SatuVault__KeyDirectory.
///   seed   create demo users, teams, servers, items and some activity (once)
///   code   print the current authenticator code for the demo users
///   qr     print a QR code to add the demo key to a phone authenticator
/// </summary>
public static class DemoMain
{
    /// <summary>Shared by every seeded user so one authenticator entry works for all of them.</summary>
    public const string DemoSecret = "SATUVAULTDEMOSATUVAULTDEMO234567";

    public static readonly string[] SeededUsers = ["alice", "bob", "citra", "dewi"];
    public const string Domain = "demo.local";

    public static async Task<int> Main(string[] args)
    {
        var secret = Base32.Decode(DemoSecret);
        switch (args.FirstOrDefault())
        {
            case "seed":
                return await Seed.RunAsync(Env("ConnectionStrings__App"), Env("SatuVault__KeyDirectory"), secret);
            case "code":
                do
                {
                    var now = DateTimeOffset.UtcNow;
                    var left = 30 - now.ToUnixTimeSeconds() % 30;
                    Console.Write($"\r  {Totp.Code(secret, Totp.StepAt(now))}   (valid {left,2}s more, each code works once per user)");
                    if (!args.Contains("--watch")) break;
                    await Task.Delay(1000);
                } while (true);
                Console.WriteLine();
                return 0;
            case "qr":
                var uri = Totp.ProvisioningUri(secret, "SatuVault demo", $"demo-users@{Domain}");
                Console.WriteLine(new AsciiQRCode(new QRCodeGenerator().CreateQrCode(uri, QRCodeGenerator.ECCLevel.M)).GetGraphicSmall());
                Console.WriteLine($"  or enter the key manually: {DemoSecret}");
                return 0;
            default:
                Console.Error.WriteLine("usage: SatuVault.Demo seed | code [--watch] | qr");
                return 2;
        }
    }

    private static string Env(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : throw new InvalidOperationException($"{name} is not set");
}

/// <summary>Seeding runs on a clock a few minutes in the past so the reviewer's first code is never a replay.</summary>
internal sealed class DemoClock(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; private set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance() => Now = Now.AddSeconds(31);
}

internal static class Seed
{
    private static readonly RequestInfo Office = new("10.20.0.15", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/141.0 (demo seed)");
    private static readonly RequestInfo Remote = new("10.88.4.2", "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) Safari/26.0 (demo seed)");

    public static async Task<int> RunAsync(string connectionString, string keyDirectory, byte[] secret)
    {
        var opts = new SatuOptions { KeyDirectory = keyDirectory };
        var ring = KeyRing.Load(opts.MasterKeyPath);
        var db = new Db(connectionString);
        var clock = new DemoClock(DateTimeOffset.UtcNow.AddMinutes(-20));
        var cipher = new FieldCipher(ring);
        var users = new Users(db, cipher, new BlindIndex(ring), Options.Create(opts), clock);
        var teams = new Teams(db, cipher, clock);
        var items = new Items(db, cipher, clock);
        var servers = new Servers(db, cipher, clock);
        var audit = new AuditLog(db, cipher, ring, NullLogger<AuditLog>.Instance);
        var vault = new VaultService(db, items, servers, teams, users, audit);
        var setup = new SetupToken(db, audit, Options.Create(opts));

        if (await setup.IsDoneAsync())
        {
            Console.WriteLine("Demo data already present (setup is done); nothing to seed.");
            return 0;
        }

        // Users sign in the same way the dev sign-in page does, then get the shared demo authenticator key.
        var ids = new Dictionary<string, string>();
        foreach (var name in DemoMain.SeededUsers.Append("eko"))
        {
            var email = $"{name}@{DemoMain.Domain}";
            var (u, _) = await users.UpsertFromSignInAsync("dev-tenant", $"dev:{email}", email, name);
            await audit.WriteAsync(u.Id, Office, "auth.signin", "user", u.Id, new { firstSignIn = true, dev = true });
            ids[name] = u.Id;
        }
        await using (var c = await db.OpenAsync())
        {
            foreach (var name in DemoMain.SeededUsers)
                await c.ExecuteAsync("""
                    UPDATE users SET totp_secret_enc = @enc, totp_enrolled_at = @now, totp_last_step = 0, totp_failures = 0
                    WHERE id = @id
                    """, new { id = ids[name], enc = cipher.Encrypt(secret, FieldCipher.Aad("users", "totp_secret", ids[name])), now = clock.Now.UtcDateTime });
        }
        foreach (var name in DemoMain.SeededUsers)
            await audit.WriteAsync(ids[name], Office, "totp.enroll", "user", ids[name]);

        // Alice is the first installer: the real setup-token claim.
        var token = SetupToken.Generate();
        SetupToken.WriteHash(opts.SetupTokenPath, token);
        if (await setup.ClaimAsync(ids["alice"], Office, token) != SetupOutcome.Ok)
            throw new InvalidOperationException("Setup claim failed");

        async Task<AppUser> As(string name)
        {
            var all = (await teams.ListAsync()).Select(t => t.Id).ToList();
            return new AppUser((await users.GetAsync(ids[name]))!, await teams.RolesOfAsync(ids[name]), all);
        }
        string Code()
        {
            clock.Advance();
            return Totp.Code(secret, Totp.StepAt(clock.Now));
        }

        var alice = await As("alice");
        var infra = await vault.CreateTeamAsync(alice, Office, "Infrastructure", ids["bob"]);
        var marketing = await vault.CreateTeamAsync(alice, Office, "Marketing", ids["citra"]);
        var finance = await vault.CreateTeamAsync(alice, Office, "Finance", ids["alice"]);
        await vault.SetMemberAsync(await As("citra"), Office, marketing, $"dewi@{DemoMain.Domain}", TeamRole.Member);

        var bob = await As("bob");
        var app01 = await vault.CreateServerAsync(bob, Office, infra, new ServerInfo("app-01.corp.local", "10.0.10.11", "Windows Server 2022", "8 vCPU", "32 GB", "C: 200 GB, D: 500 GB", "AST-0042", "Production", "DC Jakarta", "IIS + .NET apps"));
        var db01 = await vault.CreateServerAsync(bob, Office, infra, new ServerInfo("db-01.corp.local", "10.0.10.21", "Ubuntu 24.04 LTS", "16 vCPU", "64 GB", "1 TB NVMe", "AST-0043", "Production", "DC Jakarta", "MySQL 8.4 primary"));
        await vault.CreateServerAsync(bob, Office, infra, new ServerInfo("dc-01.corp.local", "10.0.10.5", "Windows Server 2022", "4 vCPU", "16 GB", "C: 120 GB", "AST-0007", "Production", "DC Jakarta", "Domain controller"));
        var stg01 = await vault.CreateServerAsync(bob, Office, infra, new ServerInfo("stg-app-01.corp.local", "10.0.20.11", "Windows Server 2019", "4 vCPU", "16 GB", "C: 150 GB", "AST-0101", "Staging", "DC Bandung"));
        var citra = await As("citra");
        var wp01 = await vault.CreateServerAsync(citra, Office, marketing, new ServerInfo("web-01.corp.local", "10.0.30.8", "Ubuntu 22.04 LTS", "2 vCPU", "4 GB", "80 GB", "AST-0210", "Production", "Cloud (Jakarta region)", "Company website (WordPress)"));

        var appAdmin = await vault.CreateItemAsync(bob, Office, infra, ItemKind.Credential, app01, new ItemMeta("app-01 local Administrator", "Administrator", null, "windows, prod"), new ItemSecret("Xk7#pQ2!vLm9@Rt4", null, "Rotated quarterly. Break-glass only; normally use your domain account."));
        await vault.CreateItemAsync(bob, Office, infra, ItemKind.Credential, db01, new ItemMeta("db-01 MySQL root", "root", null, "mysql, prod"), new ItemSecret("m9V$2wQe!7bHzR1u", null, "Only from the bastion host."));
        await vault.CreateItemAsync(bob, Office, infra, ItemKind.Credential, stg01, new ItemMeta("stg-app-01 Administrator", "Administrator", null, "windows, staging"), new ItemSecret("Staging#2026!", null, null));
        await vault.CreateItemAsync(bob, Office, infra, ItemKind.Credential, null, new ItemMeta("FortiGate admin", "admin", "https://fw.corp.local", "network"), new ItemSecret("F0rt!Gate-Adm1n", null, null));
        await vault.CreateItemAsync(bob, Office, infra, ItemKind.Secret, null, new ItemMeta("Wildcard TLS key passphrase", null, null, "certificates"), new ItemSecret(null, "*.corp.local private key passphrase: tL9#xW2$kP7!", "Certificate expires 2027-03-31."));
        var oldNas = await vault.CreateItemAsync(bob, Office, infra, ItemKind.Credential, null, new ItemMeta("Old NAS admin", "admin", "http://nas-old.corp.local", "retired"), new ItemSecret("nas-admin-2019", null, null));
        await vault.CreateItemAsync(citra, Office, marketing, ItemKind.Credential, wp01, new ItemMeta("Website WordPress admin", "wp-admin", "https://www.example.com/wp-admin", "web"), new ItemSecret("Wp#Adm1n-2026", null, null));
        var youtube = await vault.CreateItemAsync(citra, Office, marketing, ItemKind.Credential, null, new ItemMeta("YouTube B (shared)", "youtube-b@example.com", "https://youtube.com", "social"), new ItemSecret("YtB-sh4red!", null, "Recovery phone is the marketing team phone."));
        var instagram = await vault.CreateItemAsync(citra, Office, marketing, ItemKind.Credential, null, new ItemMeta("Instagram brand account", "examplebrand", "https://instagram.com", "social"), new ItemSecret("Insta#2025", null, null));
        await vault.CreateItemAsync(citra, Office, marketing, ItemKind.Secret, null, new ItemMeta("Meta Ads API token", null, "https://business.facebook.com", "api"), new ItemSecret(null, "EAAG-demo-token-0000000000000000", "Expires every 60 days."));
        alice = await As("alice");
        await vault.CreateItemAsync(alice, Office, finance, ItemKind.Credential, null, new ItemMeta("Bank portal (view only)", "corp-viewer", "https://bank.example.com", "bank"), new ItemSecret("B4nk-View!only", null, "Approval tokens are with the CFO."));

        // Some everyday activity for the audit log and item history.
        bob = await As("bob");
        await vault.RevealAsync(bob, Office, appAdmin, Code(), "reveal", "password", null);
        var dewi = await As("dewi");
        await vault.RevealAsync(dewi, Remote, youtube, "000000", "copy", "password", null);
        await vault.RevealAsync(dewi, Remote, youtube, Code(), "copy", "password", null);
        citra = await As("citra");
        var ig = await vault.GetItemAsync(citra, instagram);
        await vault.UpdateItemAsync(citra, Office, instagram, ig.Version, null, ig.Meta, new SecretPatch("Insta#2026-rotated", null, null));
        await vault.SetItemDeletedAsync(bob, Office, oldNas, true);

        Console.WriteLine($"Seeded 5 users, 3 teams, 5 servers, 11 items (1 deleted) as of {clock.Now:u}.");
        return 0;
    }
}
