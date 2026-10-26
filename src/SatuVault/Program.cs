using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using SatuVault;
using SatuVault.Audit;
using SatuVault.Cli;
using SatuVault.Crypto;
using SatuVault.Data;
using SatuVault.Security;
using SatuVault.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false);

if (Commands.IsCommand(args))
    return await Commands.RunAsync(args, builder.Configuration, builder.Environment);

builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);
var services = builder.Services;
services.Configure<SatuOptions>(builder.Configuration.GetSection(SatuOptions.Section));
services.PostConfigure<SatuOptions>(o => o.KeyDirectory = Path.GetFullPath(o.KeyDirectory, builder.Environment.ContentRootPath));
services.Configure<EntraOptions>(builder.Configuration.GetSection(EntraOptions.Section));

services.AddSingleton(TimeProvider.System);
services.AddSingleton(sp =>
{
    var opts = sp.GetRequiredService<IOptions<SatuOptions>>().Value;
    if (!File.Exists(opts.MasterKeyPath))
        throw new InvalidOperationException($"No master key at {opts.MasterKeyPath}. Run `SatuVault init` first.");
    var ring = KeyRing.Load(opts.MasterKeyPath);
    if (ring.Protection == KeyProtection.None && builder.Environment.IsProduction())
        throw new InvalidOperationException("The master key is not DPAPI-protected; refusing to run in Production.");
    return ring;
});
services.AddSingleton<FieldCipher>();
services.AddSingleton<BlindIndex>();
services.AddSingleton(_ => new Db(builder.Configuration.GetConnectionString("App")
    ?? throw new InvalidOperationException("ConnectionStrings:App is not set")));
services.AddSingleton<Users>();
services.AddSingleton<Teams>();
services.AddSingleton<Items>();
services.AddSingleton<Servers>();
services.AddSingleton<AuditLog>();
services.AddSingleton<SetupToken>();
services.AddSingleton<VaultService>();

// Cookie encryption keys survive app pool recycles; DPAPI-protected on Windows.
var keyDir = Path.GetFullPath(builder.Configuration[$"{SatuOptions.Section}:KeyDirectory"] ?? "keys", builder.Environment.ContentRootPath);
var dp = services.AddDataProtection().SetApplicationName("SatuVault")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(keyDir, "dataprotection")));
if (OperatingSystem.IsWindows()) dp.ProtectKeysWithDpapi();

var satu = builder.Configuration.GetSection(SatuOptions.Section).Get<SatuOptions>() ?? new SatuOptions();
var entra = builder.Configuration.GetSection(EntraOptions.Section).Get<EntraOptions>() ?? new EntraOptions();
var devLogin = builder.Environment.IsDevelopment() && builder.Configuration.GetValue<bool>("SatuVault:DevLogin");

var auth = services.AddAuthentication(o =>
{
    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = devLogin ? CookieAuthenticationDefaults.AuthenticationScheme : OpenIdConnectDefaults.AuthenticationScheme;
});
auth.AddCookie(o =>
{
    o.Cookie.Name = "satuvault";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.SlidingExpiration = true;
    o.ExpireTimeSpan = TimeSpan.FromMinutes(satu.IdleMinutes);
    o.LoginPath = "/Account/DevSignIn";
    o.AccessDeniedPath = "/Error";
    o.Events.OnValidatePrincipal = ctx =>
    {
        // Absolute session limit on top of the sliding idle timeout.
        var at = ctx.Principal?.FindFirstValue(SatuClaims.SignedInAt);
        if (at is null || DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(long.Parse(at)) > TimeSpan.FromHours(satu.SessionHours))
            ctx.RejectPrincipal();
        return Task.CompletedTask;
    };
});
if (!devLogin)
{
    auth.AddOpenIdConnect(o =>
    {
        o.Authority = $"https://login.microsoftonline.com/{entra.TenantId}/v2.0";
        o.ClientId = entra.ClientId;
        o.ClientSecret = entra.ClientSecret;
        o.ResponseType = "code";
        o.UsePkce = true;
        o.MapInboundClaims = false;
        o.SaveTokens = false;
        o.Scope.Clear();
        foreach (var s in new[] { "openid", "profile", "email" }) o.Scope.Add(s);
        o.TokenValidationParameters.ValidIssuer = $"https://login.microsoftonline.com/{entra.TenantId}/v2.0";
        o.Events.OnTokenValidated = async ctx =>
        {
            var p = ctx.Principal!;
            var tid = p.FindFirstValue("tid");
            var oid = p.FindFirstValue("oid");
            if (tid != entra.TenantId || oid is null)
            {
                ctx.Fail("Wrong tenant");
                return;
            }
            var email = p.FindFirstValue("email") ?? p.FindFirstValue("preferred_username") ?? oid;
            var name = p.FindFirstValue("name") ?? email;
            var sp = ctx.HttpContext.RequestServices;
            var (user, created) = await sp.GetRequiredService<Users>().UpsertFromSignInAsync(tid, oid, email, name);
            var audit = sp.GetRequiredService<AuditLog>();
            if (user.Disabled)
            {
                await audit.WriteAsync(user.Id, ctx.HttpContext.RequestInfo(), "auth.denied_disabled", "user", user.Id);
                ctx.Fail("Account disabled");
                return;
            }
            await audit.WriteAsync(user.Id, ctx.HttpContext.RequestInfo(), "auth.signin", "user", user.Id, new { firstSignIn = created });
            ctx.Principal = SignIns.Principal(user.Id, name);
        };
        o.Events.OnRemoteFailure = ctx =>
        {
            ctx.Response.Redirect(ctx.Request.PathBase + "/Account/Disabled");
            ctx.HandleResponse();
            return Task.CompletedTask;
        };
    });
}

services.AddAuthorization(o => o.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
services.AddRazorPages(o =>
{
    o.Conventions.AllowAnonymousToPage("/Error");
    o.Conventions.AllowAnonymousToPage("/Account/Disabled");
    o.Conventions.AllowAnonymousToPage("/Account/SignedOut");
    o.Conventions.AllowAnonymousToPage("/Account/DevSignIn");
});
services.AddAntiforgery(o => o.HeaderName = "X-CSRF-TOKEN");

var app = builder.Build();

if (satu.DisplayTimeZone is { Length: > 0 } tz)
    SatuVault.Pages.Fmt.Zone = TimeZoneInfo.FindSystemTimeZoneById(tz);

if (builder.Configuration["SatuVault:PathBase"] is { Length: > 0 } pathBase)
{
    app.UsePathBase(pathBase); // IIS sets the path base itself for /this_platform; this is for Kestrel.
    // Outside the path base (e.g. the browser's /favicon.ico) answer 404 instead of rendering pages,
    // which would set a second antiforgery cookie at path "/" and break the next form post.
    app.Use((ctx, next) =>
    {
        if (ctx.Request.PathBase.HasValue) return next(ctx);
        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    });
}
app.UseExceptionHandler("/Error");
app.UseStatusCodePagesWithReExecute("/Error");
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseMiddleware<AppUserMiddleware>();
app.UseAuthorization();
app.UseAntiforgery();

app.MapRazorPages();

// Reveal / copy / load-for-edit. JSON in, JSON out; the value never goes into HTML.
app.MapPost("/api/items/{id}/reveal", async (string id, RevealRequest body, HttpContext ctx, VaultService vault, IAntiforgery af) =>
{
    await af.ValidateRequestAsync(ctx);
    try
    {
        var r = await vault.RevealAsync(ctx.RequireAppUser(), ctx.RequestInfo(), id, body.Code ?? "", body.Action ?? "reveal", body.Field, body.Version);
        return r.Status switch
        {
            RevealStatus.Ok => Results.Ok(new { values = r.Values }),
            RevealStatus.Locked => Results.Json(new { error = $"Too many wrong codes. Locked until {r.LockedUntil:HH:mm} UTC." }, statusCode: 423),
            RevealStatus.NotEnrolled => Results.Json(new { error = "Set up your authenticator first." }, statusCode: 403),
            _ => Results.Json(new { error = $"Wrong or already used code. {r.FailuresLeft} attempt(s) left." }, statusCode: 400),
        };
    }
    catch (AppException e)
    {
        return Results.Json(new { error = e.Message }, statusCode: e.Status);
    }
}).DisableAntiforgery(); // validated explicitly above (header token)

app.MapPost("/Account/SignOut", async (HttpContext ctx, AuditLog audit) =>
{
    if (ctx.AppUser() is { } u) await audit.WriteAsync(u.Id, ctx.RequestInfo(), "auth.signout", "user", u.Id);
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (!devLogin)
        await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = ctx.Request.PathBase + "/Account/SignedOut" });
    else
        ctx.Response.Redirect(ctx.Request.PathBase + "/Account/SignedOut");
});

app.Run();
return 0;

public sealed record RevealRequest(string? Code, string? Action, string? Field, int? Version);

namespace SatuVault.Security
{
    public static class SignIns
    {
        public static ClaimsPrincipal Principal(string userId, string name) =>
            new(new ClaimsIdentity(
                [
                    new Claim(SatuClaims.UserId, userId),
                    new Claim(ClaimTypes.Name, name),
                    new Claim(SatuClaims.SignedInAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                ],
                CookieAuthenticationDefaults.AuthenticationScheme));
    }
}

public partial class Program;
