using Dapper;
using MySqlConnector;
using SatuVault.Crypto;

namespace SatuVault.Data;

public enum ItemKind { Credential, Secret }

/// <summary>Shown in lists and detail pages without a code.</summary>
public sealed record ItemMeta(string Title, string? Username = null, string? Url = null, string? Tags = null);

/// <summary>Only ever decrypted by the reveal endpoint, after an authenticator code.</summary>
public sealed record ItemSecret(string? Password = null, string? SecretText = null, string? Notes = null)
{
    public string? Field(string name) => name switch
    {
        "password" => Password,
        "secret" => SecretText,
        "notes" => Notes,
        _ => null,
    };
}

public sealed record Item(
    string Id,
    string TeamId,
    ItemKind Kind,
    string? ServerId,
    ItemMeta Meta,
    int Version,
    DateTime CreatedAt,
    string CreatedBy,
    DateTime UpdatedAt,
    string UpdatedBy,
    DateTime? DeletedAt);

public sealed record ItemVersion(int Version, ItemMeta Meta, DateTime ChangedAt, string ChangedBy);

/// <summary>Thrown when an item changed since the editor loaded it.</summary>
public sealed class ConcurrencyException() : Exception("The item was changed by someone else. Reload and try again.");

public sealed class Items(Db db, FieldCipher cipher, TimeProvider clock)
{
    // The version is part of the associated data, so a blob only decrypts as the
    // version it was written for (and item_versions can store it unchanged).
    private static string MetaAad(string id, int v) => FieldCipher.Aad("items", "meta", $"{id}:v{v}");
    private static string SecretAad(string id, int v) => FieldCipher.Aad("items", "secret", $"{id}:v{v}");

    private sealed class Row
    {
        public string Id { get; set; } = "";
        public string TeamId { get; set; } = "";
        public string Kind { get; set; } = "";
        public string? ServerId { get; set; }
        public byte[] MetaEnc { get; set; } = [];
        public int Version { get; set; }
        public DateTime CreatedAt { get; set; }
        public string CreatedBy { get; set; } = "";
        public DateTime UpdatedAt { get; set; }
        public string UpdatedBy { get; set; } = "";
        public DateTime? DeletedAt { get; set; }
    }

    private const string Columns = """
        id AS Id, team_id AS TeamId, kind AS Kind, server_id AS ServerId, meta_enc AS MetaEnc, version AS Version,
        created_at AS CreatedAt, created_by AS CreatedBy, updated_at AS UpdatedAt, updated_by AS UpdatedBy, deleted_at AS DeletedAt
        """;

    private Item Map(Row r) => new(r.Id, r.TeamId, r.Kind == "secret" ? ItemKind.Secret : ItemKind.Credential, r.ServerId,
        cipher.DecryptJson<ItemMeta>(r.MetaEnc, MetaAad(r.Id, r.Version)), r.Version,
        r.CreatedAt, r.CreatedBy, r.UpdatedAt, r.UpdatedBy, r.DeletedAt);

    private static string KindText(ItemKind k) => k == ItemKind.Secret ? "secret" : "credential";

    public async Task<List<Item>> ListAsync(IEnumerable<string> teamIds, bool deleted = false, string? serverId = null)
    {
        var ids = teamIds.ToArray();
        if (ids.Length == 0) return [];
        await using var c = await db.OpenAsync();
        var rows = await c.QueryAsync<Row>($"""
            SELECT {Columns} FROM items
            WHERE team_id IN @ids AND deleted_at IS {(deleted ? "NOT NULL" : "NULL")}
              AND (@serverId IS NULL OR server_id = @serverId)
            """, new { ids, serverId });
        return rows.Select(Map).OrderBy(i => i.Meta.Title, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<Item?> GetAsync(string id)
    {
        await using var c = await db.OpenAsync();
        var r = await c.QuerySingleOrDefaultAsync<Row>($"SELECT {Columns} FROM items WHERE id = @id", new { id });
        return r is null ? null : Map(r);
    }

    /// <summary>Decrypt the secret part of the current item, or of an older version.</summary>
    public async Task<ItemSecret?> GetSecretAsync(string id, int? version = null)
    {
        await using var c = await db.OpenAsync();
        var current = await c.QuerySingleOrDefaultAsync<(byte[] Enc, int Version)?>(
            "SELECT secret_enc, version FROM items WHERE id = @id", new { id });
        if (current is null) return null;
        if (version is null || version == current.Value.Version)
            return cipher.DecryptJson<ItemSecret>(current.Value.Enc, SecretAad(id, current.Value.Version));
        var old = await c.QuerySingleOrDefaultAsync<byte[]?>(
            "SELECT secret_enc FROM item_versions WHERE item_id = @id AND version = @version", new { id, version });
        return old is null ? null : cipher.DecryptJson<ItemSecret>(old, SecretAad(id, version.Value));
    }

    public async Task<string> CreateAsync(MySqlConnection c, MySqlTransaction tx, string teamId, ItemKind kind, string? serverId, ItemMeta meta, ItemSecret secret, string by)
    {
        var id = Guid.NewGuid().ToString();
        var now = clock.GetUtcNow().UtcDateTime;
        await c.ExecuteAsync("""
            INSERT INTO items (id, team_id, kind, server_id, meta_enc, secret_enc, version, created_at, created_by, updated_at, updated_by)
            VALUES (@id, @teamId, @kind, @serverId, @meta, @secret, 1, @now, @by, @now, @by)
            """, new
        {
            id, teamId, kind = KindText(kind), serverId,
            meta = cipher.EncryptJson(meta, MetaAad(id, 1)),
            secret = cipher.EncryptJson(secret, SecretAad(id, 1)),
            now, by,
        }, tx);
        return id;
    }

    /// <summary>
    /// Saves a new version. <paramref name="secret"/> null keeps the current secret.
    /// The previous version is kept in item_versions.
    /// </summary>
    public async Task<int> UpdateAsync(MySqlConnection c, MySqlTransaction tx, string id, int expectedVersion, string? serverId, ItemMeta meta, ItemSecret? secret, string by)
    {
        var cur = await c.QuerySingleOrDefaultAsync<(byte[] Meta, byte[] Secret, int Version, DateTime UpdatedAt, string UpdatedBy)?>(
            "SELECT meta_enc, secret_enc, version, updated_at, updated_by FROM items WHERE id = @id AND deleted_at IS NULL FOR UPDATE",
            new { id }, tx);
        if (cur is null || cur.Value.Version != expectedVersion) throw new ConcurrencyException();
        var v = cur.Value.Version;
        await c.ExecuteAsync("""
            INSERT INTO item_versions (item_id, version, meta_enc, secret_enc, changed_at, changed_by)
            VALUES (@id, @v, @meta, @secret, @at, @by)
            """, new { id, v, meta = cur.Value.Meta, secret = cur.Value.Secret, at = cur.Value.UpdatedAt, by = cur.Value.UpdatedBy }, tx);

        var next = v + 1;
        secret ??= cipher.DecryptJson<ItemSecret>(cur.Value.Secret, SecretAad(id, v));
        await c.ExecuteAsync("""
            UPDATE items SET server_id = @serverId, meta_enc = @meta, secret_enc = @secret, version = @next,
                   updated_at = @now, updated_by = @by
            WHERE id = @id
            """, new
        {
            id, serverId, next, by, now = clock.GetUtcNow().UtcDateTime,
            meta = cipher.EncryptJson(meta, MetaAad(id, next)),
            secret = cipher.EncryptJson(secret, SecretAad(id, next)),
        }, tx);
        return next;
    }

    public async Task<bool> SetDeletedAsync(MySqlConnection c, MySqlTransaction tx, string id, bool deleted, string by) =>
        await c.ExecuteAsync(
            deleted
                ? "UPDATE items SET deleted_at = @now, updated_by = @by WHERE id = @id AND deleted_at IS NULL"
                : "UPDATE items SET deleted_at = NULL, updated_by = @by WHERE id = @id AND deleted_at IS NOT NULL",
            new { id, by, now = clock.GetUtcNow().UtcDateTime }, tx) == 1;

    public async Task<List<ItemVersion>> VersionsAsync(string id)
    {
        await using var c = await db.OpenAsync();
        var rows = await c.QueryAsync<(int Version, byte[] Meta, DateTime ChangedAt, string ChangedBy)>(
            "SELECT version, meta_enc, changed_at, changed_by FROM item_versions WHERE item_id = @id ORDER BY version DESC", new { id });
        return rows.Select(r => new ItemVersion(r.Version, cipher.DecryptJson<ItemMeta>(r.Meta, MetaAad(id, r.Version)), r.ChangedAt, r.ChangedBy)).ToList();
    }
}
