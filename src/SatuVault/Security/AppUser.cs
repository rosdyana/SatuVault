using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using SatuVault.Audit;
using SatuVault.Data;

namespace SatuVault.Security;

/// <summary>The signed-in user for this request, loaded fresh from the database.</summary>
public sealed class AppUser(UserRecord user, Dictionary<string, TeamRole> roles, IReadOnlyList<string> allTeamIds)
{
    public UserRecord User { get; } = user;
    public string Id => User.Id;
    public bool IsAdmin => User.IsAdmin;
    public IReadOnlyDictionary<string, TeamRole> Roles { get; } = roles;

    /// <summary>Teams whose items and servers this user can see (admins: all).</summary>
    public IReadOnlyList<string> VisibleTeamIds => IsAdmin ? allTeamIds : Roles.Keys.ToList();

    public bool CanView(string teamId) => IsAdmin || Roles.ContainsKey(teamId);
    public bool CanEdit(string teamId) => CanView(teamId);
    public bool CanManage(string teamId) => IsAdmin || Roles.GetValueOrDefault(teamId) == TeamRole.Manager;
}

public static class SatuClaims
{
    public const string UserId = "satu_uid";
    public const string SignedInAt = "satu_auth_time";
}

public static class HttpContextExtensions
{
    private const string Key = "SatuVault.AppUser";

    public static AppUser? AppUser(this HttpContext ctx) => ctx.Items[Key] as AppUser;

    public static AppUser RequireAppUser(this HttpContext ctx) =>
        ctx.AppUser() ?? throw new InvalidOperationException("No signed-in user on this request");

    internal static void SetAppUser(this HttpContext ctx, AppUser user) => ctx.Items[Key] = user;

    public static RequestInfo RequestInfo(this HttpContext ctx) =>
        new(ctx.Connection.RemoteIpAddress?.ToString(), ctx.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua[..Math.Min(ua.Length, 512)] : null);
}

/// <summary>
/// Loads the user behind the cookie on every request, signs out disabled users, and
/// holds everyone without a confirmed authenticator on the enrollment page.
/// </summary>
public sealed class AppUserMiddleware(RequestDelegate next)
{
    private static readonly string[] OpenWithoutEnrollment = ["/Enroll", "/Account/SignOut", "/Error", "/css/", "/js/"];

    public async Task InvokeAsync(HttpContext ctx, Users users, Teams teams)
    {
        var uid = ctx.User.FindFirstValue(SatuClaims.UserId);
        if (uid is null)
        {
            await next(ctx);
            return;
        }

        var user = await users.GetAsync(uid);
        if (user is null || user.Disabled)
        {
            await ctx.SignOutAsync();
            ctx.Response.Redirect(ctx.Request.PathBase + "/Account/Disabled");
            return;
        }

        var roles = await teams.RolesOfAsync(uid);
        var all = user.IsAdmin ? (await teams.ListAsync()).Select(t => t.Id).ToList() : [];
        ctx.SetAppUser(new AppUser(user, roles, all));

        var path = ctx.Request.Path.Value ?? "/";
        if (!user.TotpEnrolled && !OpenWithoutEnrollment.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsJsonAsync(new { error = "Set up your authenticator app first." });
                return;
            }
            ctx.Response.Redirect(ctx.Request.PathBase + "/Enroll");
            return;
        }
        await next(ctx);
    }
}

/// <summary>Headers for every response; pages that show secrets also must not be cached.</summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        h.ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
                                  "form-action 'self' https://login.microsoftonline.com; frame-ancestors 'none'; base-uri 'self'; object-src 'none'";
        h.XContentTypeOptions = "nosniff";
        h.XFrameOptions = "DENY";
        h["Referrer-Policy"] = "same-origin";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        if (!ctx.Request.Path.StartsWithSegments("/css") && !ctx.Request.Path.StartsWithSegments("/js"))
            h.CacheControl = "no-store";
        return next(ctx);
    }
}
