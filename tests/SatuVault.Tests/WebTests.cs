using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using SatuVault.Crypto;
using SatuVault.Security;

namespace SatuVault.Tests;

/// <summary>The whole app in-process: dev sign-in, real MySQL, real antiforgery and cookies.</summary>
public sealed partial class WebTests : IAsyncLifetime
{
    private TestDb _db = null!;
    private WebApplicationFactory<Program> _factory = null!;
    private string _keyDir = null!;
    private const string Token = "setup-token-for-web-tests";

    public async Task InitializeAsync()
    {
        _db = await TestDb.CreateAsync();
        _keyDir = Directory.CreateTempSubdirectory().FullName;
        KeyRing.CreateNew(KeyProtection.None).Save(Path.Combine(_keyDir, "master.key"));
        SetupToken.WriteHash(Path.Combine(_keyDir, "setup-token.json"), Token);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Development");
            b.UseSetting("ConnectionStrings:App", _db.AppConnectionString);
            b.UseSetting("SatuVault:KeyDirectory", _keyDir);
            b.UseSetting("SatuVault:DevLogin", "true");
            b.UseSetting("SatuVault:DisplayTimeZone", "");
        });
    }

    public async Task DisposeAsync()
    {
        await _factory.DisposeAsync();
        await _db.DisposeAsync();
    }

    /// <summary>A browser-like client: keeps cookies, doesn't follow redirects so tests can see them.</summary>
    private sealed class Browser(HttpClient http)
    {
        public HttpClient Http { get; } = http;
        public byte[]? TotpSecret { get; set; }
        private long _lastStep;

        public async Task<string> GetHtmlAsync(string url)
        {
            var res = await Http.GetAsync(url);
            Assert.True(res.StatusCode == HttpStatusCode.OK, $"GET {url} -> {(int)res.StatusCode} {res.Headers.Location}");
            return await res.Content.ReadAsStringAsync();
        }

        public static string FormToken(string html) => FormTokenRe().Match(html).Groups[1].Value;
        public static string MetaCsrf(string html) => MetaCsrfRe().Match(html).Groups[1].Value;

        /// <summary>POST a form from the page at <paramref name="pageUrl"/> (to pick up its antiforgery token).</summary>
        public async Task<HttpResponseMessage> PostFormAsync(string pageUrl, string action, Dictionary<string, string> fields)
        {
            var html = await GetHtmlAsync(pageUrl);
            fields["__RequestVerificationToken"] = FormToken(html);
            return await Http.PostAsync(action, new FormUrlEncodedContent(fields));
        }

        /// <summary>Next unused code: real users wait for the next 30 s window, tests compute it.</summary>
        public string NextCode()
        {
            var step = Math.Max(Totp.StepAt(DateTimeOffset.UtcNow) - 1, _lastStep + 1);
            if (step > Totp.StepAt(DateTimeOffset.UtcNow) + 1) throw new InvalidOperationException("Out of codes for this window");
            _lastStep = step;
            return Totp.Code(TotpSecret!, step);
        }
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex FormTokenRe();

    [GeneratedRegex("<meta name=\"csrf\" content=\"([^\"]+)\"")]
    private static partial Regex MetaCsrfRe();

    [GeneratedRegex(@"<code id=""manual-key"">([A-Z2-7 ]+)</code>")]
    private static partial Regex ManualKeyRe();

    private Browser NewBrowser() => new(_factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true }));

    private async Task<Browser> SignInAsync(string email, bool enroll = true)
    {
        var b = NewBrowser();
        var res = await b.PostFormAsync("/Account/DevSignIn", "/Account/DevSignIn", new() { ["Email"] = email });
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        if (!enroll) return b;

        var html = await b.GetHtmlAsync("/Enroll");
        b.TotpSecret = Base32.Decode(ManualKeyRe().Match(html).Groups[1].Value.Replace(" ", ""));
        var done = await b.PostFormAsync("/Enroll", "/Enroll", new() { ["Code"] = b.NextCode() });
        Assert.Equal(HttpStatusCode.Redirect, done.StatusCode);
        return b;
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> RevealAsync(Browser b, string itemId, object body, string? csrf = null)
    {
        csrf ??= Browser.MetaCsrf(await b.GetHtmlAsync($"/Items/Details?id={itemId}"));
        using var req = new HttpRequestMessage(HttpMethod.Post, $"/api/items/{itemId}/reveal") { Content = JsonContent.Create(body) };
        req.Headers.Add("X-CSRF-TOKEN", csrf);
        var res = await b.Http.SendAsync(req);
        var text = await res.Content.ReadAsStringAsync();
        return (res.StatusCode, text.Length > 0 ? JsonDocument.Parse(text).RootElement.Clone() : default);
    }

    /// <summary>Admin via setup token, one team with the admin as manager.</summary>
    private async Task<(Browser Admin, string TeamId)> AdminWithTeamAsync()
    {
        var admin = await SignInAsync("admin@corp.test");
        var setup = await admin.PostFormAsync("/Setup", "/Setup", new() { ["Token"] = Token, ["Code"] = admin.NextCode() });
        Assert.Equal("/Teams", setup.Headers.Location?.OriginalString);
        var created = await admin.PostFormAsync("/Teams", "/Teams?handler=Create", new() { ["NewName"] = "Social Media", ["ManagerEmail"] = "admin@corp.test" });
        var teamId = Regex.Match(created.Headers.Location!.OriginalString, "id=([0-9a-f-]{36})").Groups[1].Value;
        return (admin, teamId);
    }

    private static async Task<string> CreateItemAsync(Browser b, string teamId, string title, string password)
    {
        var res = await b.PostFormAsync($"/Items/Edit?team={teamId}", "/Items/Edit", new()
        {
            ["Input.TeamId"] = teamId, ["Input.Kind"] = "Credential", ["Input.Title"] = title,
            ["Input.Username"] = "youtube-b@corp.test", ["Input.Password"] = password, ["Input.Notes"] = "backup codes 1111",
        });
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        return Regex.Match(res.Headers.Location!.OriginalString, "id=([0-9a-f-]{36})").Groups[1].Value;
    }

    [Fact]
    public async Task Anonymous_users_are_sent_to_sign_in_and_get_security_headers()
    {
        var b = NewBrowser();
        var res = await b.Http.GetAsync("/Items");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("/Account/DevSignIn", res.Headers.Location!.OriginalString);
        Assert.Contains("frame-ancestors 'none'", res.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", res.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task Nothing_works_until_the_authenticator_is_enrolled()
    {
        var b = await SignInAsync("new@corp.test", enroll: false);
        var res = await b.Http.GetAsync("/Items");
        Assert.Equal("/Enroll", res.Headers.Location?.OriginalString);
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/items/x/reveal") { Content = JsonContent.Create(new { code = "123456" }) };
        Assert.Equal(HttpStatusCode.Forbidden, (await b.Http.SendAsync(req)).StatusCode);

        var html = await b.GetHtmlAsync("/Enroll");
        Assert.Contains("data:image/png;base64,", html);
        var wrong = await b.PostFormAsync("/Enroll", "/Enroll", new() { ["Code"] = "000000" });
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode); // re-rendered with an error
        Assert.Contains("didn&#x27;t match", await wrong.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task First_installer_becomes_admin_once()
    {
        var other = await SignInAsync("other@corp.test");
        var bad = await other.PostFormAsync("/Setup", "/Setup", new() { ["Token"] = "nope", ["Code"] = other.NextCode() });
        Assert.Contains("not valid", await bad.Content.ReadAsStringAsync());

        var (admin, _) = await AdminWithTeamAsync();
        Assert.Contains("Audit log", await admin.GetHtmlAsync("/"));

        // Second claim with the right token: setup is done, nothing happens.
        var late = await other.PostFormAsync("/", "/Setup", new() { ["Token"] = Token, ["Code"] = other.NextCode() });
        Assert.Equal(HttpStatusCode.Redirect, late.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await other.Http.GetAsync("/Admin/Audit")).StatusCode);
    }

    [Fact]
    public async Task Reveal_flow_end_to_end()
    {
        var (admin, teamId) = await AdminWithTeamAsync();
        var itemId = await CreateItemAsync(admin, teamId, "YouTube B", "pa55word");

        // The details page never contains the secret.
        var page = await admin.GetHtmlAsync($"/Items/Details?id={itemId}");
        Assert.Contains("YouTube B", page);
        Assert.DoesNotContain("pa55word", page);
        Assert.DoesNotContain("backup codes", page);
        var csrf = Browser.MetaCsrf(page);

        // No CSRF header -> rejected.
        var noCsrf = await admin.Http.PostAsJsonAsync($"/api/items/{itemId}/reveal", new { code = "123456", action = "reveal", field = "password" });
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);

        var bad = await RevealAsync(admin, itemId, new { code = "000000", action = "reveal", field = "password" }, csrf);
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Contains("attempt", bad.Body.GetProperty("error").GetString());

        var ok = await RevealAsync(admin, itemId, new { code = admin.NextCode(), action = "copy", field = "password" }, csrf);
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.Equal("pa55word", ok.Body.GetProperty("values").GetProperty("password").GetString());

        // A member of another team can't see it.
        var eve = await SignInAsync("eve@corp.test");
        Assert.Equal(HttpStatusCode.NotFound, (await eve.Http.GetAsync($"/Items/Details?id={itemId}")).StatusCode);
        var eveCsrf = Browser.MetaCsrf(await eve.GetHtmlAsync("/"));
        Assert.Equal(HttpStatusCode.NotFound, (await RevealAsync(eve, itemId, new { code = eve.NextCode(), action = "reveal", field = "password" }, eveCsrf)).Status);

        // The audit page shows who copied what.
        var audit = await admin.GetHtmlAsync("/Admin/Audit?Action=item.copy");
        Assert.Contains("admin@corp.test", audit);
        Assert.Contains("YouTube B", audit);
        Assert.Contains("item.copy", audit);
        Assert.Contains("field: password", audit);
    }

    [Fact]
    public async Task Edit_keeps_secret_fields_left_empty()
    {
        var (admin, teamId) = await AdminWithTeamAsync();
        var itemId = await CreateItemAsync(admin, teamId, "Router admin", "old-pass");
        var edit = await admin.GetHtmlAsync($"/Items/Edit?id={itemId}");
        Assert.DoesNotContain("old-pass", edit);
        var res = await admin.PostFormAsync($"/Items/Edit?id={itemId}", $"/Items/Edit?id={itemId}", new()
        {
            ["Input.Version"] = "1", ["Input.Kind"] = "Credential", ["Input.Title"] = "Router admin", ["Input.Username"] = "admin",
            ["Input.Password"] = "new-pass", ["Input.SecretLoaded"] = "false",
        });
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);

        var values = await RevealAsync(admin, itemId, new { code = admin.NextCode(), action = "edit" });
        Assert.Equal("new-pass", values.Body.GetProperty("values").GetProperty("password").GetString());
        Assert.Equal("backup codes 1111", values.Body.GetProperty("values").GetProperty("notes").GetString());
    }

    [Fact]
    public async Task Servers_and_rdp_file()
    {
        var (admin, teamId) = await AdminWithTeamAsync();
        var res = await admin.PostFormAsync($"/Servers/Edit?team={teamId}", "/Servers/Edit", new()
        {
            ["Input.TeamId"] = teamId, ["Input.Hostname"] = "app-01.corp.local", ["Input.IpAddress"] = "10.0.0.11",
            ["Input.Os"] = "Windows Server 2022", ["Input.Ram"] = "32 GB", ["Input.AssetId"] = "AST-0042",
        });
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        var id = Regex.Match(res.Headers.Location!.OriginalString, "id=([0-9a-f-]{36})").Groups[1].Value;

        var list = await admin.GetHtmlAsync("/Servers?q=AST-0042");
        Assert.Contains("app-01.corp.local", list);
        var rdp = await admin.Http.GetAsync($"/Servers/Details?id={id}&handler=Rdp");
        var text = await rdp.Content.ReadAsStringAsync();
        Assert.Contains("full address:s:10.0.0.11", text);
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);

        var bad = await admin.PostFormAsync($"/Servers/Edit?team={teamId}", "/Servers/Edit", new() { ["Input.TeamId"] = teamId, ["Input.Hostname"] = "x", ["Input.IpAddress"] = "999.1.1.1" });
        Assert.Contains("IP address is not valid", await bad.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Audit_verify_and_csv_export()
    {
        var (admin, teamId) = await AdminWithTeamAsync();
        await CreateItemAsync(admin, teamId, "=HYPERLINK(\"x\")", "p");
        var verify = await admin.PostFormAsync("/Admin/Audit", "/Admin/Audit?handler=Verify", []);
        Assert.Equal(HttpStatusCode.Redirect, verify.StatusCode);
        Assert.Contains("Audit log intact", await admin.GetHtmlAsync("/Admin/Audit"));

        var csv = await (await admin.Http.GetAsync("/Admin/Audit?handler=Csv")).Content.ReadAsStringAsync();
        Assert.Contains("\"item.create\"", csv);
        Assert.Contains("\"'=HYPERLINK", csv); // formula neutralised
        Assert.Contains("audit.verify", csv);
    }
}
