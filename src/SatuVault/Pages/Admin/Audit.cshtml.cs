using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SatuVault.Audit;
using SatuVault.Data;

namespace SatuVault.Pages.Admin;

public sealed class AuditModel(AuditLog audit, Users users) : AppPageModel
{
    [BindProperty(SupportsGet = true)] public string? UserEmail { get; set; }
    [BindProperty(SupportsGet = true)] public string? Action { get; set; }
    [BindProperty(SupportsGet = true)] public string? Target { get; set; }
    [BindProperty(SupportsGet = true)] public DateTime? From { get; set; }
    [BindProperty(SupportsGet = true)] public DateTime? To { get; set; }
    [BindProperty(SupportsGet = true)] public long? Before { get; set; }

    public List<AuditEvent> Events { get; private set; } = [];
    public Dictionary<string, UserRecord> UsersById { get; private set; } = [];
    public string? FilterProblem { get; private set; }

    public static readonly (string Prefix, string Label)[] Categories =
    [
        ("item.", "Credentials (create / edit / delete / reveal / copy)"),
        ("item.reveal", "Reveals"),
        ("item.copy", "Copies"),
        ("server.", "Servers"),
        ("team.", "Teams and members"),
        ("auth.", "Sign-in / sign-out"),
        ("totp.", "Authenticator (enroll / failed / locked / reset)"),
        ("admin.", "Admin roles"),
        ("user.", "User enable / disable"),
        ("setup.", "Setup"),
        ("audit.", "Audit log access"),
    ];

    private async Task<AuditFilter?> FilterAsync(int limit)
    {
        string? actorId = null;
        if (!string.IsNullOrWhiteSpace(UserEmail))
        {
            actorId = (await users.FindByEmailAsync(UserEmail))?.Id;
            if (actorId is null)
            {
                FilterProblem = $"No user with email {UserEmail}.";
                return null;
            }
        }
        // Dates in the form are in the display time zone; the table stores UTC.
        DateTime? Utc(DateTime? local) => local is null ? null : TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local.Value, DateTimeKind.Unspecified), Fmt.Zone);
        return new AuditFilter(actorId, string.IsNullOrWhiteSpace(Action) ? null : Action, null,
            string.IsNullOrWhiteSpace(Target) ? null : Target.Trim(), Utc(From), Utc(To?.AddDays(1)), Before, limit);
    }

    public async Task<IActionResult> OnGetAsync()
    {
        if (!Me.IsAdmin) return NotFound();
        var f = await FilterAsync(100);
        if (f is not null)
        {
            Events = await audit.QueryAsync(f);
            UsersById = await users.GetManyAsync(Events.Select(e => e.ActorId).OfType<string>());
        }
        return Page();
    }

    public async Task<IActionResult> OnPostVerifyAsync()
    {
        if (!Me.IsAdmin) return NotFound();
        var r = await audit.VerifyAsync(HttpContext.RequestAborted);
        await audit.WriteAsync(Me.Id, Req, "audit.verify", details: new { r.Intact, r.Checked, r.FirstBadSeq });
        if (r.Intact) Flash = $"Audit log intact: {r.Checked} events verified.";
        else FlashError = $"AUDIT LOG TAMPERED: {r.Problem} (first bad event #{r.FirstBadSeq}). Investigate database access.";
        return RedirectToPage();
    }

    /// <summary>CSV of everything matching the filter (newest first). The export itself is logged.</summary>
    public async Task<IActionResult> OnGetCsvAsync()
    {
        if (!Me.IsAdmin) return NotFound();
        var f = await FilterAsync(1000);
        if (f is null) return RedirectToPage();
        var all = new List<AuditEvent>();
        while (true)
        {
            var batch = await audit.QueryAsync(f);
            all.AddRange(batch);
            if (batch.Count < f.Limit || all.Count >= 100_000) break;
            f = f with { BeforeSeq = batch[^1].Seq };
        }
        await audit.WriteAsync(Me.Id, Req, "audit.export", details: new { rows = all.Count, filter = new { UserEmail, Action, Target, From, To } });
        var names = await users.GetManyAsync(all.Select(e => e.ActorId).OfType<string>());

        var sb = new StringBuilder("seq,time_utc,user,action,target_type,target_id,label,ip,user_agent,details\r\n");
        foreach (var e in all)
        {
            var d = new Dictionary<string, JsonElement>(e.Details);
            string? Take(string k) => d.Remove(k, out var v) && v.ValueKind != JsonValueKind.Null ? v.ToString() : null;
            var label = Take("label");
            var ip = Take("ip");
            var ua = Take("userAgent");
            sb.AppendJoin(',', new[]
            {
                e.Seq.ToString(CultureInfo.InvariantCulture), e.Ts.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture),
                Fmt.User(names, e.ActorId), e.Action, e.TargetType, e.TargetId, label, ip, ua, JsonSerializer.Serialize(d),
            }.Select(Csv)).Append("\r\n");
        }
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv", $"satuvault-audit-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv");
    }

    // Quote every field; neutralise spreadsheet formula injection.
    private static string Csv(string? v)
    {
        v ??= "";
        if (v.Length > 0 && "=+-@\t\r".Contains(v[0])) v = "'" + v;
        return "\"" + v.Replace("\"", "\"\"") + "\"";
    }

    private static readonly Dictionary<string, string> Labels = new()
    {
        ["auth.signin"] = "Signed in", ["auth.signout"] = "Signed out", ["auth.denied_disabled"] = "Sign in refused (disabled)",
        ["totp.enroll"] = "Set up authenticator", ["totp.failed"] = "Wrong code", ["totp.locked"] = "Locked after wrong codes",
        ["totp.reset"] = "Authenticator reset",
        ["item.create"] = "Created item", ["item.update"] = "Changed item", ["item.delete"] = "Deleted item",
        ["item.restore"] = "Restored item", ["item.reveal"] = "Revealed", ["item.copy"] = "Copied",
        ["item.reveal_for_edit"] = "Loaded secrets to edit",
        ["server.create"] = "Added server", ["server.update"] = "Changed server", ["server.delete"] = "Deleted server",
        ["server.restore"] = "Restored server", ["server.rdp_download"] = "Downloaded .rdp",
        ["team.create"] = "Created team", ["team.rename"] = "Renamed team", ["team.delete"] = "Deleted team",
        ["team.member_set"] = "Added or changed member", ["team.member_remove"] = "Removed member",
        ["admin.grant"] = "Made admin", ["admin.revoke"] = "Removed admin", ["user.disable"] = "Disabled user", ["user.enable"] = "Enabled user",
        ["setup.admin"] = "Claimed first admin", ["setup.failed"] = "Wrong setup token",
        ["audit.verify"] = "Verified audit log", ["audit.export"] = "Exported audit log",
    };

    /// <summary>Plain words for an action code; the code itself stays visible for filtering and exports.</summary>
    public static string Label(string action) => Labels.GetValueOrDefault(action, action);

    /// <summary>"warn" for events an admin should notice.</summary>
    public static string Tone(string action) => action switch
    {
        "totp.failed" or "totp.locked" or "auth.denied_disabled" or "setup.failed" => "warn",
        "item.reveal" or "item.copy" or "item.reveal_for_edit" => "accent",
        _ => "",
    };

    /// <summary>Details worth showing inline: no IP/user agent/label (own columns) and no raw ids.</summary>
    public static string Summary(IReadOnlyDictionary<string, JsonElement> d) =>
        string.Join(" · ", d.Where(kv => kv.Key is not ("ip" or "userAgent" or "label" or "dev") && !kv.Key.EndsWith("Id", StringComparison.Ordinal)
                && kv.Value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Object or JsonValueKind.Array))
            .Select(kv => $"{Humanize(kv.Key)}: {(kv.Value.ValueKind == JsonValueKind.String ? kv.Value.GetString() : kv.Value.GetRawText())}"));

    // "firstSignIn" -> "first sign in"
    private static string Humanize(string key) =>
        string.Concat(key.Select(c => char.IsUpper(c) ? " " + char.ToLowerInvariant(c) : c.ToString()));

    public static string? Str(IReadOnlyDictionary<string, JsonElement> d, string key) =>
        d.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
