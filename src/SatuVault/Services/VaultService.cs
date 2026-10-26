using SatuVault.Audit;
using SatuVault.Data;
using SatuVault.Security;

namespace SatuVault.Services;

public class AppException(int status, string message) : Exception(message)
{
    public int Status { get; } = status;
}

public sealed class NotFoundException(string what = "Not found") : AppException(404, what);
public sealed class ForbiddenException(string why = "You don't have access to this") : AppException(403, why);
public sealed class InvalidInputException(string why) : AppException(400, why);

public enum RevealStatus { Ok, BadCode, Locked, NotEnrolled }

public sealed record SecretPatch(string? Password, string? SecretText, string? Notes, bool ReplaceAll = false)
{
    public bool HasAny => !string.IsNullOrEmpty(Password) || !string.IsNullOrEmpty(SecretText) || !string.IsNullOrEmpty(Notes);
}

public sealed record RevealResult(RevealStatus Status, IReadOnlyDictionary<string, string?>? Values = null, int FailuresLeft = 0, DateTime? LockedUntil = null);

/// <summary>
/// Every state change and every secret access goes through here: permission check,
/// change, audit event (in the same transaction where there is one).
/// </summary>
public sealed class VaultService(Db db, Items items, Servers servers, Teams teams, Users users, AuditLog audit)
{
    public static readonly string[] SecretFields = ["password", "secret", "notes"];

    // ---- items ----

    public async Task<Item> GetItemAsync(AppUser u, string id)
    {
        var item = await items.GetAsync(id) ?? throw new NotFoundException("Item not found");
        if (!u.CanView(item.TeamId)) throw new NotFoundException("Item not found");
        return item;
    }

    /// <summary>
    /// Verify the authenticator code, write the audit event, then decrypt. If the audit
    /// write fails nothing is returned.
    /// action: reveal | copy (one field) or edit (all secret fields, to prefill the edit form).
    /// </summary>
    public async Task<RevealResult> RevealAsync(AppUser u, RequestInfo req, string itemId, string code, string action, string? field, int? version)
    {
        if (action is not ("reveal" or "copy" or "edit")) throw new InvalidInputException("Unknown action");
        if (action != "edit" && (field is null || !SecretFields.Contains(field))) throw new InvalidInputException("Unknown field");
        var item = await GetItemAsync(u, itemId);
        if (action == "edit" && (item.DeletedAt is not null || version is not null)) throw new InvalidInputException("Only the current version can be edited");

        var check = await users.VerifyCodeAsync(u.Id, code);
        if (!check.Ok)
        {
            var locked = check.Outcome == TotpOutcome.Locked;
            await audit.WriteAsync(u.Id, req, locked ? "totp.locked" : "totp.failed", "item", item.Id,
                new { label = item.Meta.Title, action, field });
            return check.Outcome switch
            {
                TotpOutcome.Locked => new RevealResult(RevealStatus.Locked, LockedUntil: check.LockedUntil),
                TotpOutcome.NotEnrolled => new RevealResult(RevealStatus.NotEnrolled),
                _ => new RevealResult(RevealStatus.BadCode, FailuresLeft: check.FailuresLeft),
            };
        }

        var secret = await items.GetSecretAsync(item.Id, version) ?? throw new NotFoundException("Version not found");
        await audit.WriteAsync(u.Id, req, action == "edit" ? "item.reveal_for_edit" : $"item.{action}", "item", item.Id,
            new { label = item.Meta.Title, teamId = item.TeamId, field, version = version ?? item.Version });

        var values = action == "edit"
            ? SecretFields.ToDictionary(f => f, secret.Field)
            : new Dictionary<string, string?> { [field!] = secret.Field(field!) };
        return new RevealResult(RevealStatus.Ok, values);
    }

    private static string? Blank(string? s) => string.IsNullOrEmpty(s) ? null : s;

    private async Task CheckServerLinkAsync(string teamId, string? serverId)
    {
        if (serverId is null) return;
        var s = await servers.GetAsync(serverId);
        if (s is null || s.DeletedAt is not null || s.TeamId != teamId) throw new InvalidInputException("Linked server must belong to the same team");
    }

    private static ItemMeta Clean(ItemMeta m)
    {
        if (string.IsNullOrWhiteSpace(m.Title)) throw new InvalidInputException("Title is required");
        static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
        return new ItemMeta(m.Title.Trim(), N(m.Username), N(m.Url), N(m.Tags));
    }

    public async Task<string> CreateItemAsync(AppUser u, RequestInfo req, string teamId, ItemKind kind, string? serverId, ItemMeta meta, ItemSecret secret)
    {
        if (!u.CanEdit(teamId)) throw new ForbiddenException();
        meta = Clean(meta);
        await CheckServerLinkAsync(teamId, serverId);
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        var id = await items.CreateAsync(c, tx, teamId, kind, serverId, meta, secret, u.Id);
        await audit.WriteAsync(c, tx, u.Id, req, "item.create", "item", id, new { label = meta.Title, teamId, kind = kind.ToString(), serverId });
        await tx.CommitAsync();
        return id;
    }

    /// <summary>
    /// <paramref name="patch"/> null keeps the stored secret. Otherwise, without
    /// ReplaceAll only the non-empty fields replace stored ones (so typing a new password
    /// doesn't need the old notes); with ReplaceAll (the editor loaded the secrets with a
    /// code) the form's values replace everything, including clearing fields.
    /// </summary>
    public async Task UpdateItemAsync(AppUser u, RequestInfo req, string id, int expectedVersion, string? serverId, ItemMeta meta, SecretPatch? patch)
    {
        var item = await GetItemAsync(u, id);
        if (item.DeletedAt is not null) throw new InvalidInputException("Restore the item before editing it");
        meta = Clean(meta);
        await CheckServerLinkAsync(item.TeamId, serverId);
        var changed = new List<string>();
        if (meta.Title != item.Meta.Title) changed.Add("title");
        if (meta.Username != item.Meta.Username) changed.Add("username");
        if (meta.Url != item.Meta.Url) changed.Add("url");
        if (meta.Tags != item.Meta.Tags) changed.Add("tags");
        if (serverId != item.ServerId) changed.Add("server");

        ItemSecret? secret = null;
        if (patch is not null && (patch.ReplaceAll || patch.HasAny))
        {
            // Decrypted server-side only to merge; nothing is returned to the caller.
            var cur = await items.GetSecretAsync(id) ?? new ItemSecret();
            secret = patch.ReplaceAll
                ? new ItemSecret(Blank(patch.Password), Blank(patch.SecretText), Blank(patch.Notes))
                : new ItemSecret(Blank(patch.Password) ?? cur.Password, Blank(patch.SecretText) ?? cur.SecretText, Blank(patch.Notes) ?? cur.Notes);
            if (secret.Password != cur.Password) changed.Add("password");
            if (secret.SecretText != cur.SecretText) changed.Add("secret");
            if (secret.Notes != cur.Notes) changed.Add("notes");
            if (secret == cur) secret = null;
        }
        if (changed.Count == 0) return;

        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        var v = await items.UpdateAsync(c, tx, id, expectedVersion, serverId, meta, secret, u.Id);
        await audit.WriteAsync(c, tx, u.Id, req, "item.update", "item", id,
            new { label = meta.Title, previousLabel = item.Meta.Title == meta.Title ? null : item.Meta.Title, teamId = item.TeamId, version = v, changed });
        await tx.CommitAsync();
    }

    public async Task SetItemDeletedAsync(AppUser u, RequestInfo req, string id, bool deleted)
    {
        var item = await GetItemAsync(u, id);
        // Members can delete; restoring is for managers (they review what was removed).
        if (!deleted && !u.CanManage(item.TeamId)) throw new ForbiddenException("Only team managers can restore items");
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        if (!await items.SetDeletedAsync(c, tx, id, deleted, u.Id)) return;
        await audit.WriteAsync(c, tx, u.Id, req, deleted ? "item.delete" : "item.restore", "item", id, new { label = item.Meta.Title, teamId = item.TeamId });
        await tx.CommitAsync();
    }

    // ---- servers ----

    public async Task<Server> GetServerAsync(AppUser u, string id)
    {
        var s = await servers.GetAsync(id) ?? throw new NotFoundException("Server not found");
        if (!u.CanView(s.TeamId)) throw new NotFoundException("Server not found");
        return s;
    }

    private static ServerInfo Clean(ServerInfo s)
    {
        if (string.IsNullOrWhiteSpace(s.Hostname)) throw new InvalidInputException("Hostname is required");
        static string? N(string? v) => string.IsNullOrWhiteSpace(v) ? null : v.Trim();
        if (N(s.IpAddress) is { } ip && !System.Net.IPAddress.TryParse(ip, out _)) throw new InvalidInputException("IP address is not valid");
        return new ServerInfo(s.Hostname.Trim(), N(s.IpAddress), N(s.Os), N(s.Cpu), N(s.Ram), N(s.Disk), N(s.AssetId), N(s.Environment), N(s.Location), N(s.Notes));
    }

    public async Task<string> CreateServerAsync(AppUser u, RequestInfo req, string teamId, ServerInfo info)
    {
        if (!u.CanEdit(teamId)) throw new ForbiddenException();
        info = Clean(info);
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        var id = await servers.CreateAsync(c, tx, teamId, info, u.Id);
        await audit.WriteAsync(c, tx, u.Id, req, "server.create", "server", id, new { label = info.Hostname, teamId, info.IpAddress, info.AssetId });
        await tx.CommitAsync();
        return id;
    }

    public async Task UpdateServerAsync(AppUser u, RequestInfo req, string id, int expectedVersion, ServerInfo info)
    {
        var s = await GetServerAsync(u, id);
        info = Clean(info);
        var changed = typeof(ServerInfo).GetProperties().Where(p => !Equals(p.GetValue(s.Info), p.GetValue(info))).Select(p => p.Name).ToList();
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        await servers.UpdateAsync(c, tx, id, expectedVersion, info, u.Id);
        // Inventory isn't secret, so old and new values are kept in the (encrypted) audit details.
        await audit.WriteAsync(c, tx, u.Id, req, "server.update", "server", id, new
        {
            label = info.Hostname,
            teamId = s.TeamId,
            changes = changed.ToDictionary(n => n, n => new
            {
                from = typeof(ServerInfo).GetProperty(n)!.GetValue(s.Info),
                to = typeof(ServerInfo).GetProperty(n)!.GetValue(info),
            }),
        });
        await tx.CommitAsync();
    }

    public async Task SetServerDeletedAsync(AppUser u, RequestInfo req, string id, bool deleted)
    {
        var s = await GetServerAsync(u, id);
        if (!deleted && !u.CanManage(s.TeamId)) throw new ForbiddenException("Only team managers can restore servers");
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        if (!await servers.SetDeletedAsync(c, tx, id, deleted, u.Id)) return;
        await audit.WriteAsync(c, tx, u.Id, req, deleted ? "server.delete" : "server.restore", "server", id, new { label = s.Info.Hostname, teamId = s.TeamId });
        await tx.CommitAsync();
    }

    public async Task LogRdpDownloadAsync(AppUser u, RequestInfo req, Server s) =>
        await audit.WriteAsync(u.Id, req, "server.rdp_download", "server", s.Id, new { label = s.Info.Hostname, teamId = s.TeamId });

    // ---- teams ----

    public async Task<string> CreateTeamAsync(AppUser u, RequestInfo req, string name, string managerId)
    {
        if (!u.IsAdmin) throw new ForbiddenException("Only admins can create teams");
        if (string.IsNullOrWhiteSpace(name)) throw new InvalidInputException("Team name is required");
        var manager = await users.GetAsync(managerId) ?? throw new InvalidInputException("Manager not found");
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        var id = await teams.CreateAsync(c, tx, name.Trim(), u.Id, manager.Id);
        await audit.WriteAsync(c, tx, u.Id, req, "team.create", "team", id, new { label = name.Trim(), manager = manager.Email });
        await tx.CommitAsync();
        return id;
    }

    public async Task<Team> GetTeamAsync(AppUser u, string id)
    {
        if (!u.CanView(id)) throw new NotFoundException("Team not found");
        return await teams.GetAsync(id) ?? throw new NotFoundException("Team not found");
    }

    public async Task RenameTeamAsync(AppUser u, RequestInfo req, string id, string name)
    {
        var team = await GetTeamAsync(u, id);
        if (!u.CanManage(id)) throw new ForbiddenException();
        if (string.IsNullOrWhiteSpace(name)) throw new InvalidInputException("Team name is required");
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        await teams.RenameAsync(c, tx, id, name.Trim());
        await audit.WriteAsync(c, tx, u.Id, req, "team.rename", "team", id, new { label = name.Trim(), previousLabel = team.Name });
        await tx.CommitAsync();
    }

    public async Task DeleteTeamAsync(AppUser u, RequestInfo req, string id)
    {
        if (!u.IsAdmin) throw new ForbiddenException("Only admins can delete teams");
        var team = await GetTeamAsync(u, id);
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        if (!await teams.DeleteAsync(c, tx, id)) throw new InvalidInputException("Delete or move the team's items and servers first");
        await audit.WriteAsync(c, tx, u.Id, req, "team.delete", "team", id, new { label = team.Name });
        await tx.CommitAsync();
    }

    /// <summary>Add (or change the role of) a member, by the email they sign in with.</summary>
    public async Task SetMemberAsync(AppUser u, RequestInfo req, string teamId, string email, TeamRole role)
    {
        var team = await GetTeamAsync(u, teamId);
        if (!u.CanManage(teamId)) throw new ForbiddenException("Only team managers can change members");
        var member = await users.FindByEmailAsync(email) ?? throw new InvalidInputException("No user with that email has signed in yet. Ask them to sign in once first.");
        if (member.Disabled) throw new InvalidInputException("That user is disabled");
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        await teams.SetMemberAsync(c, tx, teamId, member.Id, role, u.Id);
        await audit.WriteAsync(c, tx, u.Id, req, "team.member_set", "team", teamId, new { label = team.Name, member = member.Email, memberId = member.Id, role = role.ToString() });
        await tx.CommitAsync();
    }

    public async Task RemoveMemberAsync(AppUser u, RequestInfo req, string teamId, string userId)
    {
        var team = await GetTeamAsync(u, teamId);
        if (!u.CanManage(teamId)) throw new ForbiddenException("Only team managers can change members");
        var member = await users.GetAsync(userId);
        await using var c = await db.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        if (!await teams.RemoveMemberAsync(c, tx, teamId, userId)) return;
        await audit.WriteAsync(c, tx, u.Id, req, "team.member_remove", "team", teamId, new { label = team.Name, member = member?.Email, memberId = userId });
        await tx.CommitAsync();
    }

    // ---- admin ----

    private async Task RequireAdminCodeAsync(AppUser u, RequestInfo req, string code, string action, string targetId)
    {
        if (!u.IsAdmin) throw new ForbiddenException("Admins only");
        var check = await users.VerifyCodeAsync(u.Id, code);
        if (check.Ok) return;
        await audit.WriteAsync(u.Id, req, check.Outcome == TotpOutcome.Locked ? "totp.locked" : "totp.failed", "user", targetId, new { action });
        throw new InvalidInputException(check.Outcome == TotpOutcome.Locked ? "Too many wrong codes. Try again later." : "Wrong authenticator code");
    }

    public async Task SetAdminAsync(AppUser u, RequestInfo req, string userId, bool isAdmin, string code)
    {
        await RequireAdminCodeAsync(u, req, code, "admin.set", userId);
        if (!isAdmin && userId == u.Id) throw new InvalidInputException("You can't remove your own admin role");
        var target = await users.GetAsync(userId) ?? throw new NotFoundException("User not found");
        await users.SetAdminAsync(userId, isAdmin);
        await audit.WriteAsync(u.Id, req, isAdmin ? "admin.grant" : "admin.revoke", "user", userId, new { label = target.Email });
    }

    public async Task SetDisabledAsync(AppUser u, RequestInfo req, string userId, bool disabled, string code)
    {
        await RequireAdminCodeAsync(u, req, code, "user.disable", userId);
        if (userId == u.Id) throw new InvalidInputException("You can't disable yourself");
        var target = await users.GetAsync(userId) ?? throw new NotFoundException("User not found");
        await users.SetDisabledAsync(userId, disabled);
        await audit.WriteAsync(u.Id, req, disabled ? "user.disable" : "user.enable", "user", userId, new { label = target.Email });
    }

    public async Task ResetTotpAsync(AppUser u, RequestInfo req, string userId, string code)
    {
        await RequireAdminCodeAsync(u, req, code, "totp.reset", userId);
        var target = await users.GetAsync(userId) ?? throw new NotFoundException("User not found");
        await users.ResetTotpAsync(userId);
        await audit.WriteAsync(u.Id, req, "totp.reset", "user", userId, new { label = target.Email });
    }
}
