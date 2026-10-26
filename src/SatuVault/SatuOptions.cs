namespace SatuVault;

public sealed class SatuOptions
{
    public const string Section = "SatuVault";

    /// <summary>Folder for master.key and the ASP.NET Data Protection keys. Must not be inside the web root.</summary>
    public string KeyDirectory { get; set; } = "keys";

    /// <summary>Shown in authenticator apps.</summary>
    public string TotpIssuer { get; set; } = "SatuVault";

    public int TotpMaxFailures { get; set; } = 5;
    public int TotpLockoutMinutes { get; set; } = 15;

    /// <summary>Time zone for showing times (stored in UTC), e.g. "Asia/Jakarta" or "SE Asia Standard Time".</summary>
    public string? DisplayTimeZone { get; set; }

    /// <summary>Only for running under Kestrel at a sub-path; IIS provides the path base itself.</summary>
    public string? PathBase { get; set; }

    public int SessionHours { get; set; } = 8;
    public int IdleMinutes { get; set; } = 30;

    public string MasterKeyPath => Path.Combine(KeyDirectory, "master.key");
    public string SetupTokenPath => Path.Combine(KeyDirectory, "setup-token.json");
}

public sealed class EntraOptions
{
    public const string Section = "Entra";

    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
}
