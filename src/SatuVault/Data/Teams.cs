using Dapper;
using MySqlConnector;
using SatuVault.Crypto;

namespace SatuVault.Data;

public enum TeamRole { Member, Manager }

public sealed record Team(string Id, string Name, DateTime CreatedAt);

public sealed record TeamMember(string UserId, TeamRole Role, DateTime AddedAt);

public sealed class Teams(Db db, FieldCipher cipher, TimeProvider clock)
{
    private static string NameAad(string id) => FieldCipher.Aad("teams", "name", id);

    private static string RoleText(TeamRole r) => r == TeamRole.Manager ? "manager" : "member";
    private static TeamRole ParseRole(string s) => s == "manager" ? TeamRole.Manager : TeamRole.Member;

    /// <summary>Team ids the user belongs to, with their role.</summary>
    public async Task<Dictionary<string, TeamRole>> RolesOfAsync(string userId)
    {
        await using var c = await db.OpenAsync();
        var rows = await c.QueryAsync<(string TeamId, string Role)>("""
            SELECT m.team_id, m.role FROM team_members m JOIN teams t ON t.id = m.team_id
            WHERE m.user_id = @userId AND t.deleted_at IS NULL
            """, new { userId });
        return rows.ToDictionary(r => r.TeamId, r => ParseRole(r.Role));
    }

    public async Task<List<Team>> ListAsync(IEnumerable<string>? onlyIds = null)
    {
        await using var c = await db.OpenAsync();
        var ids = onlyIds?.ToArray();
        if (ids is { Length: 0 }) return [];
        var rows = await c.QueryAsync<(string Id, byte[] NameEnc, DateTime CreatedAt)>(
            ids is null
                ? "SELECT id, name_enc, created_at FROM teams WHERE deleted_at IS NULL"
                : "SELECT id, name_enc, created_at FROM teams WHERE deleted_at IS NULL AND id IN @ids",
            new { ids });
        return rows.Select(r => new Team(r.Id, cipher.DecryptString(r.NameEnc, NameAad(r.Id)), r.CreatedAt))
            .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<Team?> GetAsync(string id) => (await ListAsync([id])).FirstOrDefault();

    public async Task<string> CreateAsync(MySqlConnection c, MySqlTransaction tx, string name, string createdBy, string managerId)
    {
        var id = Guid.NewGuid().ToString();
        var now = clock.GetUtcNow().UtcDateTime;
        await c.ExecuteAsync("INSERT INTO teams (id, name_enc, created_at, created_by) VALUES (@id, @enc, @now, @createdBy)",
            new { id, enc = cipher.EncryptString(name, NameAad(id)), now, createdBy }, tx);
        await c.ExecuteAsync("INSERT INTO team_members (team_id, user_id, role, added_at, added_by) VALUES (@id, @managerId, 'manager', @now, @createdBy)",
            new { id, managerId, now, createdBy }, tx);
        return id;
    }

    public async Task RenameAsync(MySqlConnection c, MySqlTransaction tx, string id, string name) =>
        await c.ExecuteAsync("UPDATE teams SET name_enc = @enc WHERE id = @id AND deleted_at IS NULL",
            new { id, enc = cipher.EncryptString(name, NameAad(id)) }, tx);

    /// <summary>Soft delete; refused while the team still owns live items or servers.</summary>
    public async Task<bool> DeleteAsync(MySqlConnection c, MySqlTransaction tx, string id)
    {
        var inUse = await c.ExecuteScalarAsync<bool>("""
            SELECT EXISTS (SELECT 1 FROM items WHERE team_id = @id AND deleted_at IS NULL)
                OR EXISTS (SELECT 1 FROM servers WHERE team_id = @id AND deleted_at IS NULL)
            """, new { id }, tx);
        if (inUse) return false;
        await c.ExecuteAsync("UPDATE teams SET deleted_at = @now WHERE id = @id", new { id, now = clock.GetUtcNow().UtcDateTime }, tx);
        return true;
    }

    public async Task<List<TeamMember>> MembersAsync(string teamId)
    {
        await using var c = await db.OpenAsync();
        var rows = await c.QueryAsync<(string UserId, string Role, DateTime AddedAt)>(
            "SELECT user_id, role, added_at FROM team_members WHERE team_id = @teamId", new { teamId });
        return rows.Select(r => new TeamMember(r.UserId, ParseRole(r.Role), r.AddedAt)).ToList();
    }

    public async Task SetMemberAsync(MySqlConnection c, MySqlTransaction tx, string teamId, string userId, TeamRole role, string by) =>
        await c.ExecuteAsync("""
            INSERT INTO team_members (team_id, user_id, role, added_at, added_by) VALUES (@teamId, @userId, @role, @now, @by)
            ON DUPLICATE KEY UPDATE role = VALUES(role)
            """, new { teamId, userId, role = RoleText(role), now = clock.GetUtcNow().UtcDateTime, by }, tx);

    public async Task<bool> RemoveMemberAsync(MySqlConnection c, MySqlTransaction tx, string teamId, string userId) =>
        await c.ExecuteAsync("DELETE FROM team_members WHERE team_id = @teamId AND user_id = @userId", new { teamId, userId }, tx) == 1;
}
