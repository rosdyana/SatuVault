using System.Text;
using Dapper;
using SatuVault.Data;
using SatuVault.Security;
using SatuVault.Services;

namespace SatuVault.Tests;

public class VaultServiceTests : IAsyncLifetime
{
    private Env _env = null!;
    private AppUser _admin = null!;
    private byte[] _adminSecret = null!;
    private AppUser _bob = null!;
    private byte[] _bobSecret = null!;
    private AppUser _eve = null!;
    private byte[] _eveSecret = null!;
    private string _teamId = null!;

    public async Task InitializeAsync()
    {
        _env = await Env.CreateAsync();
        var (admin, adminSecret) = await _env.EnrolledUserAsync("admin@corp.test");
        await _env.Users.SetAdminAsync(admin.Id, true);
        var (bob, bobSecret) = await _env.EnrolledUserAsync("bob@corp.test");
        var (eve, eveSecret) = await _env.EnrolledUserAsync("eve@corp.test");
        _admin = await _env.AsAppUserAsync(admin.Id);
        _adminSecret = adminSecret;
        _bobSecret = bobSecret;
        _eveSecret = eveSecret;

        _teamId = await _env.Vault.CreateTeamAsync(_admin, Env.Req, "Social Media", admin.Id);
        _admin = await _env.AsAppUserAsync(admin.Id);
        await _env.Vault.SetMemberAsync(_admin, Env.Req, _teamId, "bob@corp.test", TeamRole.Member);
        _bob = await _env.AsAppUserAsync(bob.Id);
        _eve = await _env.AsAppUserAsync(eve.Id);
    }

    public async Task DisposeAsync() => await _env.DisposeAsync();

    private string BobCode()
    {
        _env.NextStep();
        return _env.Code(_bobSecret);
    }

    private async Task<string> YouTubeAsync() => await _env.Vault.CreateItemAsync(_bob, Env.Req, _teamId, ItemKind.Credential, null,
        new ItemMeta("YouTube B", "youtube-b@corp.test", "https://youtube.com"), new ItemSecret(Password: "pa55word", Notes: "recovery: 1234"));

    [Fact]
    public async Task Reveal_needs_a_fresh_code_and_logs_who_opened_what()
    {
        var id = await YouTubeAsync();

        var bad = await _env.Vault.RevealAsync(_bob, Env.Req, id, "000000", "reveal", "password", null);
        Assert.Equal(RevealStatus.BadCode, bad.Status);
        Assert.Null(bad.Values);

        var code = BobCode();
        var ok = await _env.Vault.RevealAsync(_bob, Env.Req, id, code, "reveal", "password", null);
        Assert.Equal(RevealStatus.Ok, ok.Status);
        Assert.Equal("pa55word", ok.Values!["password"]);
        Assert.False(ok.Values.ContainsKey("notes")); // only the requested field

        // the same code can't be used for a second reveal
        Assert.Equal(RevealStatus.BadCode, (await _env.Vault.RevealAsync(_bob, Env.Req, id, code, "copy", "password", null)).Status);
        Assert.Equal(RevealStatus.Ok, (await _env.Vault.RevealAsync(_bob, Env.Req, id, BobCode(), "copy", "password", null)).Status);

        var events = await _env.AuditAsync();
        var reveal = events.Single(e => e.Action == "item.reveal");
        Assert.Equal(_bob.Id, reveal.ActorId);
        Assert.Equal(id, reveal.TargetId);
        Assert.Equal("YouTube B", reveal.Details["label"].GetString());
        Assert.Equal("password", reveal.Details["field"].GetString());
        Assert.Contains(events, e => e.Action == "item.copy");
        Assert.Equal(2, events.Count(e => e.Action == "totp.failed"));
    }

    [Fact]
    public async Task Outsiders_cannot_see_or_reveal()
    {
        var id = await YouTubeAsync();
        _env.NextStep();
        await Assert.ThrowsAsync<NotFoundException>(() => _env.Vault.RevealAsync(_eve, Env.Req, id, _env.Code(_eveSecret), "reveal", "password", null));
        await Assert.ThrowsAsync<NotFoundException>(() => _env.Vault.GetItemAsync(_eve, id));
        await Assert.ThrowsAsync<ForbiddenException>(() => _env.Vault.CreateItemAsync(_eve, Env.Req, _teamId, ItemKind.Secret, null, new ItemMeta("x"), new ItemSecret(SecretText: "y")));
        Assert.DoesNotContain(await _env.AuditAsync(), e => e.ActorId == _eve.Id && e.Action.StartsWith("item."));
        // admins see everything
        Assert.Equal("YouTube B", (await _env.Vault.GetItemAsync(_admin, id)).Meta.Title);
    }

    [Fact]
    public async Task Edits_keep_history_and_can_keep_the_secret()
    {
        var id = await YouTubeAsync();
        await _env.Vault.UpdateItemAsync(_bob, Env.Req, id, 1, null, new ItemMeta("YouTube B (brand)", "youtube-b@corp.test", "https://youtube.com"), null);
        await _env.Vault.UpdateItemAsync(_bob, Env.Req, id, 2, null, new ItemMeta("YouTube B (brand)", "youtube-b@corp.test", "https://youtube.com"), new SecretPatch("n3w-pass", null, null));

        Assert.Equal("n3w-pass", (await _env.Items.GetSecretAsync(id))!.Password);
        Assert.Equal("recovery: 1234", (await _env.Items.GetSecretAsync(id))!.Notes); // untouched field kept
        Assert.Equal("pa55word", (await _env.Items.GetSecretAsync(id, 2))!.Password); // title change kept the secret
        Assert.Equal("pa55word", (await _env.Items.GetSecretAsync(id, 1))!.Password);
        var versions = await _env.Items.VersionsAsync(id);
        Assert.Equal([2, 1], versions.Select(v => v.Version));
        Assert.Equal("YouTube B", versions[1].Meta.Title);

        var old = await _env.Vault.RevealAsync(_bob, Env.Req, id, BobCode(), "reveal", "password", 1);
        Assert.Equal("pa55word", old.Values!["password"]);

        await Assert.ThrowsAsync<ConcurrencyException>(() =>
            _env.Vault.UpdateItemAsync(_bob, Env.Req, id, 1, null, new ItemMeta("stale"), null));

        var updates = (await _env.AuditAsync("item.update")).Select(e => e.Details["changed"].EnumerateArray().Select(x => x.GetString()).ToList()).ToList();
        Assert.Equal(["title"], updates[0]);
        Assert.Equal(["password"], updates[1]);
    }

    [Fact]
    public async Task Replace_all_clears_fields_and_noop_saves_write_nothing()
    {
        var id = await YouTubeAsync();
        var meta = (await _env.Items.GetAsync(id))!.Meta;
        await _env.Vault.UpdateItemAsync(_bob, Env.Req, id, 1, null, meta, new SecretPatch("pa55word", null, null));
        Assert.Equal(1, (await _env.Items.GetAsync(id))!.Version); // same values: no new version

        await _env.Vault.UpdateItemAsync(_bob, Env.Req, id, 1, null, meta, new SecretPatch("pa55word", null, null, ReplaceAll: true));
        var s = (await _env.Items.GetSecretAsync(id))!;
        Assert.Equal("pa55word", s.Password);
        Assert.Null(s.Notes);
        var ev = (await _env.AuditAsync("item.update")).Single();
        Assert.Equal(["notes"], ev.Details["changed"].EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public async Task Nothing_readable_is_stored_in_mysql()
    {
        var id = await YouTubeAsync();
        await _env.Vault.CreateServerAsync(_bob, Env.Req, _teamId, new ServerInfo("app-01.corp.local", "10.0.0.11", "Windows Server 2022", AssetId: "AST-0042"));
        await using var root = await _env.Db.RootAsync();
        foreach (var table in new[] { "users", "teams", "items", "item_versions", "servers", "audit_events" })
        {
            var rows = await root.QueryAsync($"SELECT * FROM {table}");
            foreach (IDictionary<string, object?> row in rows)
                foreach (var v in row.Values)
                {
                    var text = v is byte[] b ? Encoding.UTF8.GetString(b) : v?.ToString() ?? "";
                    foreach (var needle in new[] { "YouTube", "pa55word", "youtube-b", "app-01", "10.0.0.11", "AST-0042", "Social Media", "bob@corp", "1234" })
                        Assert.False(text.Contains(needle), $"{table} stores '{needle}' in plaintext");
                }
        }
        Assert.NotNull(id);
    }

    [Fact]
    public async Task Members_delete_but_only_managers_restore()
    {
        var id = await YouTubeAsync();
        await _env.Vault.SetItemDeletedAsync(_bob, Env.Req, id, true);
        Assert.Empty(await _env.Items.ListAsync([_teamId]));
        await Assert.ThrowsAsync<ForbiddenException>(() => _env.Vault.SetItemDeletedAsync(_bob, Env.Req, id, false));
        await _env.Vault.SetItemDeletedAsync(_admin, Env.Req, id, false);
        Assert.Single(await _env.Items.ListAsync([_teamId]));
    }

    [Fact]
    public async Task Servers_link_only_within_the_team_and_log_changes()
    {
        var otherTeam = await _env.Vault.CreateTeamAsync(_admin, Env.Req, "Infra", _admin.Id);
        _admin = await _env.AsAppUserAsync(_admin.Id);
        var foreign = await _env.Vault.CreateServerAsync(_admin, Env.Req, otherTeam, new ServerInfo("db-01"));
        await Assert.ThrowsAsync<InvalidInputException>(() => _env.Vault.CreateItemAsync(_bob, Env.Req, _teamId, ItemKind.Credential, foreign, new ItemMeta("x"), new ItemSecret()));

        var sid = await _env.Vault.CreateServerAsync(_bob, Env.Req, _teamId, new ServerInfo("app-01", "10.0.0.11", Ram: "16 GB"));
        await _env.Vault.UpdateServerAsync(_bob, Env.Req, sid, 1, new ServerInfo("app-01", "10.0.0.12", Ram: "32 GB"));
        var ev = (await _env.AuditAsync("server.update")).Single();
        Assert.Equal("10.0.0.11", ev.Details["changes"].GetProperty("IpAddress").GetProperty("from").GetString());
        Assert.Equal("32 GB", ev.Details["changes"].GetProperty("Ram").GetProperty("to").GetString());
        await Assert.ThrowsAsync<InvalidInputException>(() => _env.Vault.CreateServerAsync(_bob, Env.Req, _teamId, new ServerInfo("x", "not-an-ip")));
    }

    [Fact]
    public async Task Only_managers_change_members_and_admin_actions_need_a_code()
    {
        await Assert.ThrowsAsync<ForbiddenException>(() => _env.Vault.SetMemberAsync(_bob, Env.Req, _teamId, "eve@corp.test", TeamRole.Member));
        await Assert.ThrowsAsync<InvalidInputException>(() => _env.Vault.SetMemberAsync(_admin, Env.Req, _teamId, "nobody@corp.test", TeamRole.Member));

        await Assert.ThrowsAsync<InvalidInputException>(() => _env.Vault.ResetTotpAsync(_admin, Env.Req, _bob.Id, "000000"));
        _env.NextStep();
        await _env.Vault.ResetTotpAsync(_admin, Env.Req, _bob.Id, _env.Code(_adminSecret));
        Assert.False((await _env.Users.GetAsync(_bob.Id))!.TotpEnrolled);
        await Assert.ThrowsAsync<ForbiddenException>(() => _env.Vault.SetAdminAsync(_bob, Env.Req, _bob.Id, true, "123456"));
        Assert.Contains(await _env.AuditAsync(), e => e.Action == "totp.reset" && e.TargetId == _bob.Id);
    }

    [Fact]
    public async Task Team_with_content_cannot_be_deleted()
    {
        await YouTubeAsync();
        await Assert.ThrowsAsync<InvalidInputException>(() => _env.Vault.DeleteTeamAsync(_admin, Env.Req, _teamId));
    }
}
