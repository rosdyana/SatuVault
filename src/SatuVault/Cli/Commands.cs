using SatuVault.Audit;
using SatuVault.Crypto;
using SatuVault.Data;
using SatuVault.Security;

namespace SatuVault.Cli;

/// <summary>
/// Admin commands run from the same executable:
///   init           create master key (+ passphrase backup) and the one-time setup token
///   migrate        apply the schema with ConnectionStrings:Admin, optionally grant the app user
///   backup-key     write another passphrase backup of the master key
///   restore-key    rebuild master.key on this machine from a backup
///   verify-audit   check the audit chain
/// </summary>
public static class Commands
{
    public static readonly string[] Names = ["init", "migrate", "backup-key", "restore-key", "verify-audit"];

    public static bool IsCommand(string[] args) => args.Length > 0 && Names.Contains(args[0]);

    public static async Task<int> RunAsync(string[] args, IConfiguration config, IHostEnvironment env)
    {
        var opts = config.GetSection(SatuOptions.Section).Get<SatuOptions>() ?? new SatuOptions();
        opts.KeyDirectory = Path.GetFullPath(opts.KeyDirectory, env.ContentRootPath);
        string? Arg(string name) => args.SkipWhile(a => a != name).Skip(1).FirstOrDefault();
        try
        {
            switch (args[0])
            {
                case "init": return Init(opts, Arg("--protection"), Arg("--backup") ?? Path.Combine(opts.KeyDirectory, "master-key-backup.json"), env);
                case "migrate": return await Migrate(config, Arg("--app-user"), Arg("--app-host") ?? "%");
                case "backup-key": return Backup(opts, Arg("--out") ?? throw new ArgumentException("--out <file> is required"));
                case "restore-key": return Restore(opts, Arg("--in") ?? throw new ArgumentException("--in <file> is required"), Arg("--protection"), env);
                case "verify-audit": return await VerifyAudit(config, opts);
            }
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or IOException)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return 1;
        }
        return 2;
    }

    private static KeyProtection ParseProtection(string? s, IHostEnvironment env) => s switch
    {
        null => OperatingSystem.IsWindows() ? KeyProtection.DpapiUser : env.IsProduction()
            ? throw new InvalidOperationException("Production needs DPAPI: run init on the Windows server as the app pool identity")
            : KeyProtection.None,
        "dpapi-user" => KeyProtection.DpapiUser,
        "dpapi-machine" => KeyProtection.DpapiMachine,
        "none" when !env.IsProduction() => KeyProtection.None,
        _ => throw new ArgumentException("--protection must be dpapi-user, dpapi-machine (or none outside Production)"),
    };

    private static string Passphrase(string purpose)
    {
        var fromEnv = Environment.GetEnvironmentVariable("SATU_BACKUP_PASSPHRASE");
        if (!string.IsNullOrEmpty(fromEnv)) return fromEnv;
        if (Console.IsInputRedirected) throw new InvalidOperationException("Set SATU_BACKUP_PASSPHRASE or run interactively");
        var a = ReadSecret($"{purpose} (min 16 chars): ");
        var b = ReadSecret("Repeat: ");
        if (a != b) throw new ArgumentException("Passphrases differ");
        return a;
    }

    private static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        var s = new System.Text.StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace) { if (s.Length > 0) s.Length--; continue; }
            s.Append(k.KeyChar);
        }
        Console.WriteLine();
        return s.ToString();
    }

    private static int Init(SatuOptions opts, string? protection, string backupPath, IHostEnvironment env)
    {
        Directory.CreateDirectory(opts.KeyDirectory);
        if (File.Exists(opts.MasterKeyPath))
            throw new InvalidOperationException($"{opts.MasterKeyPath} already exists. Refusing to replace it (that would make all data unreadable).");
        var ring = KeyRing.CreateNew(ParseProtection(protection, env));
        var pass = Passphrase("Backup passphrase");
        File.WriteAllText(backupPath, ring.ExportBackup(pass));
        ring.Save(opts.MasterKeyPath);

        var token = SetupToken.Generate();
        SetupToken.WriteHash(opts.SetupTokenPath, token);
        Console.WriteLine($"""
            Master key: {opts.MasterKeyPath} ({ring.Protection})
            Key backup: {backupPath}
              -> Move this file off the server (with the passphrase kept separately).
                 Without it, losing this machine means losing every secret.

            One-time setup token (the first person to enter it becomes admin):

                {token}
            """);
        return 0;
    }

    private static async Task<int> Migrate(IConfiguration config, string? appUser, string appHost)
    {
        var admin = config.GetConnectionString("Admin") ?? throw new InvalidOperationException("ConnectionStrings:Admin is not set");
        var applied = await Migrator.MigrateAsync(admin);
        Console.WriteLine(applied.Count == 0 ? "Schema is up to date" : $"Applied: {string.Join(", ", applied)}");
        if (appUser is not null)
        {
            await Migrator.GrantAppUserAsync(admin, appUser, appHost);
            Console.WriteLine($"Granted '{appUser}'@'{appHost}' DML on app tables, SELECT/INSERT only on audit_events");
        }
        return 0;
    }

    private static int Backup(SatuOptions opts, string outPath)
    {
        var ring = KeyRing.Load(opts.MasterKeyPath);
        File.WriteAllText(outPath, ring.ExportBackup(Passphrase("Backup passphrase")));
        Console.WriteLine($"Wrote {outPath}");
        return 0;
    }

    private static int Restore(SatuOptions opts, string inPath, string? protection, IHostEnvironment env)
    {
        if (File.Exists(opts.MasterKeyPath)) throw new InvalidOperationException($"{opts.MasterKeyPath} already exists");
        var ring = KeyRing.ImportBackup(File.ReadAllText(inPath), Passphrase("Backup passphrase"), ParseProtection(protection, env));
        Directory.CreateDirectory(opts.KeyDirectory);
        ring.Save(opts.MasterKeyPath);
        Console.WriteLine($"Restored {opts.MasterKeyPath} ({ring.Protection})");
        return 0;
    }

    private static async Task<int> VerifyAudit(IConfiguration config, SatuOptions opts)
    {
        var ring = KeyRing.Load(opts.MasterKeyPath);
        var db = new Db(config.GetConnectionString("App") ?? throw new InvalidOperationException("ConnectionStrings:App is not set"));
        var log = new AuditLog(db, new FieldCipher(ring), ring, Microsoft.Extensions.Logging.Abstractions.NullLogger<AuditLog>.Instance);
        var r = await log.VerifyAsync();
        Console.WriteLine(r.Intact ? $"Audit chain intact ({r.Checked} events)" : $"AUDIT CHAIN BROKEN at #{r.FirstBadSeq}: {r.Problem}");
        return r.Intact ? 0 : 3;
    }
}
