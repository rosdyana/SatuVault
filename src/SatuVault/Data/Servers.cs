using Dapper;
using MySqlConnector;
using SatuVault.Crypto;

namespace SatuVault.Data;

/// <summary>Inventory record. Not a secret (no code needed to view), but still encrypted at rest.</summary>
public sealed record ServerInfo(
    string Hostname,
    string? IpAddress = null,
    string? Os = null,
    string? Cpu = null,
    string? Ram = null,
    string? Disk = null,
    string? AssetId = null,
    string? Environment = null,
    string? Location = null,
    string? Notes = null);

public sealed record Server(
    string Id,
    string TeamId,
    ServerInfo Info,
    int Version,
    DateTime UpdatedAt,
    string UpdatedBy,
    DateTime? DeletedAt);

public sealed class Servers(Db db, FieldCipher cipher, TimeProvider clock)
{
    private static string Aad(string id, int v) => FieldCipher.Aad("servers", "data", $"{id}:v{v}");

    private sealed class Row
    {
        public string Id { get; set; } = "";
        public string TeamId { get; set; } = "";
        public byte[] DataEnc { get; set; } = [];
        public int Version { get; set; }
        public DateTime UpdatedAt { get; set; }
        public string UpdatedBy { get; set; } = "";
        public DateTime? DeletedAt { get; set; }
    }

    private const string Columns = "id AS Id, team_id AS TeamId, data_enc AS DataEnc, version AS Version, updated_at AS UpdatedAt, updated_by AS UpdatedBy, deleted_at AS DeletedAt";

    private Server Map(Row r) => new(r.Id, r.TeamId, cipher.DecryptJson<ServerInfo>(r.DataEnc, Aad(r.Id, r.Version)), r.Version, r.UpdatedAt, r.UpdatedBy, r.DeletedAt);

    public async Task<List<Server>> ListAsync(IEnumerable<string> teamIds, bool deleted = false)
    {
        var ids = teamIds.ToArray();
        if (ids.Length == 0) return [];
        await using var c = await db.OpenAsync();
        var rows = await c.QueryAsync<Row>(
            $"SELECT {Columns} FROM servers WHERE team_id IN @ids AND deleted_at IS {(deleted ? "NOT NULL" : "NULL")}", new { ids });
        return rows.Select(Map).OrderBy(s => s.Info.Hostname, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<Server?> GetAsync(string id)
    {
        await using var c = await db.OpenAsync();
        var r = await c.QuerySingleOrDefaultAsync<Row>($"SELECT {Columns} FROM servers WHERE id = @id", new { id });
        return r is null ? null : Map(r);
    }

    public async Task<string> CreateAsync(MySqlConnection c, MySqlTransaction tx, string teamId, ServerInfo info, string by)
    {
        var id = Guid.NewGuid().ToString();
        var now = clock.GetUtcNow().UtcDateTime;
        await c.ExecuteAsync("""
            INSERT INTO servers (id, team_id, data_enc, version, created_at, created_by, updated_at, updated_by)
            VALUES (@id, @teamId, @data, 1, @now, @by, @now, @by)
            """, new { id, teamId, data = cipher.EncryptJson(info, Aad(id, 1)), now, by }, tx);
        return id;
    }

    public async Task<int> UpdateAsync(MySqlConnection c, MySqlTransaction tx, string id, int expectedVersion, ServerInfo info, string by)
    {
        var next = expectedVersion + 1;
        var n = await c.ExecuteAsync("""
            UPDATE servers SET data_enc = @data, version = @next, updated_at = @now, updated_by = @by
            WHERE id = @id AND version = @expectedVersion AND deleted_at IS NULL
            """, new { id, expectedVersion, next, by, now = clock.GetUtcNow().UtcDateTime, data = cipher.EncryptJson(info, Aad(id, next)) }, tx);
        if (n != 1) throw new ConcurrencyException();
        return next;
    }

    /// <summary>Soft delete; linked credentials keep working but lose the link.</summary>
    public async Task<bool> SetDeletedAsync(MySqlConnection c, MySqlTransaction tx, string id, bool deleted, string by)
    {
        var n = await c.ExecuteAsync(
            deleted
                ? "UPDATE servers SET deleted_at = @now, updated_by = @by WHERE id = @id AND deleted_at IS NULL"
                : "UPDATE servers SET deleted_at = NULL, updated_by = @by WHERE id = @id AND deleted_at IS NOT NULL",
            new { id, by, now = clock.GetUtcNow().UtcDateTime }, tx);
        return n == 1;
    }
}
