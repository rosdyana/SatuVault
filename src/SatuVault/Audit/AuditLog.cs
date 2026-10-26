using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using MySqlConnector;
using SatuVault.Crypto;
using SatuVault.Data;

namespace SatuVault.Audit;

/// <summary>Who/where a request came from; recorded (encrypted) with each event.</summary>
public sealed record RequestInfo(string? Ip, string? UserAgent);

public sealed record AuditEvent(
    long Seq,
    DateTime Ts,
    string? ActorId,
    string Action,
    string? TargetType,
    string? TargetId,
    Dictionary<string, JsonElement> Details);

public sealed record AuditFilter(
    string? ActorId = null,
    string? ActionPrefix = null,
    string? TargetType = null,
    string? TargetId = null,
    DateTime? From = null,
    DateTime? To = null,
    long? BeforeSeq = null,
    int Limit = 100);

public sealed record VerifyResult(bool Intact, long Checked, long? FirstBadSeq, string? Problem);

/// <summary>
/// Append-only audit trail. Each row's MAC covers the previous row's MAC, its own
/// fields and its encrypted details, keyed with a subkey MySQL never sees: rows
/// can't be edited, inserted or removed without <see cref="VerifyAsync"/> noticing.
/// </summary>
public sealed class AuditLog(Db db, FieldCipher cipher, KeyRing keys, ILogger<AuditLog> log)
{
    private readonly byte[] _macKey = keys.Subkey("audit");

    private static string Aad(long seq) => $"audit_events.details:{seq}";

    /// <summary>
    /// Writes one event. Pass the caller's transaction to make the event atomic with
    /// the change it describes; otherwise the event is committed on its own.
    /// Throws on failure: callers must not continue (e.g. must not return a secret).
    /// </summary>
    public async Task<long> WriteAsync(
        MySqlConnection c,
        MySqlTransaction? tx,
        string? actorId,
        RequestInfo? req,
        string action,
        string? targetType = null,
        string? targetId = null,
        object? details = null)
    {
        var ownTx = tx is null;
        tx ??= await c.BeginTransactionAsync();
        try
        {
            var head = await c.QuerySingleAsync<(long Seq, byte[] Mac)>(
                "SELECT seq, mac FROM audit_head WHERE id = 1 FOR UPDATE", transaction: tx);
            var seq = head.Seq + 1;
            var ts = Truncate(DateTime.UtcNow);

            var payload = new Dictionary<string, object?> { ["ip"] = req?.Ip, ["userAgent"] = req?.UserAgent };
            if (details is not null)
            {
                foreach (var p in JsonSerializer.SerializeToElement(details, JsonOpts).EnumerateObject())
                    payload[p.Name] = p.Value;
            }
            var detailsEnc = cipher.EncryptJson(payload, Aad(seq));
            var mac = Mac(head.Mac, seq, ts, actorId, action, targetType, targetId, detailsEnc);

            await c.ExecuteAsync("""
                INSERT INTO audit_events (seq, ts, actor_id, action, target_type, target_id, details_enc, mac)
                VALUES (@seq, @ts, @actorId, @action, @targetType, @targetId, @detailsEnc, @mac)
                """, new { seq, ts, actorId, action, targetType, targetId, detailsEnc, mac }, tx);
            await c.ExecuteAsync("UPDATE audit_head SET seq = @seq, mac = @mac WHERE id = 1", new { seq, mac }, tx);
            if (ownTx) await tx.CommitAsync();

            // External anchor: the newest seq/mac also lands in the app log, so truncating
            // the tail of the table is detectable against it.
            log.LogInformation("audit seq={Seq} action={Action} mac={Mac}", seq, action, Convert.ToHexString(mac));
            return seq;
        }
        catch
        {
            if (ownTx) await tx.RollbackAsync();
            throw;
        }
        finally
        {
            if (ownTx) await tx.DisposeAsync();
        }
    }

    public async Task<long> WriteAsync(string? actorId, RequestInfo? req, string action, string? targetType = null, string? targetId = null, object? details = null)
    {
        await using var c = await db.OpenAsync();
        return await WriteAsync(c, null, actorId, req, action, targetType, targetId, details);
    }

    private sealed record Row(long Seq, DateTime Ts, string? ActorId, string Action, string? TargetType, string? TargetId, byte[] DetailsEnc, byte[] Mac);

    private const string Columns = "seq AS Seq, ts AS Ts, actor_id AS ActorId, action AS Action, target_type AS TargetType, target_id AS TargetId, details_enc AS DetailsEnc, mac AS Mac";

    public async Task<List<AuditEvent>> QueryAsync(AuditFilter f)
    {
        var sql = new StringBuilder($"SELECT {Columns} FROM audit_events WHERE 1 = 1");
        if (f.ActorId is not null) sql.Append(" AND actor_id = @ActorId");
        if (f.ActionPrefix is not null) sql.Append(" AND action LIKE CONCAT(@ActionPrefix, '%')");
        if (f.TargetType is not null) sql.Append(" AND target_type = @TargetType");
        if (f.TargetId is not null) sql.Append(" AND target_id = @TargetId");
        if (f.From is not null) sql.Append(" AND ts >= @From");
        if (f.To is not null) sql.Append(" AND ts < @To");
        if (f.BeforeSeq is not null) sql.Append(" AND seq < @BeforeSeq");
        sql.Append(" ORDER BY seq DESC LIMIT @Limit");
        await using var c = await db.OpenAsync();
        var rows = await c.QueryAsync<Row>(sql.ToString(), f with { Limit = Math.Clamp(f.Limit, 1, 1000) });
        return rows.Select(r => new AuditEvent(r.Seq, r.Ts, r.ActorId, r.Action, r.TargetType, r.TargetId,
            cipher.DecryptJson<Dictionary<string, JsonElement>>(r.DetailsEnc, Aad(r.Seq)))).ToList();
    }

    public async Task<VerifyResult> VerifyAsync(CancellationToken ct = default)
    {
        await using var c = await db.OpenAsync();
        var prev = new byte[32];
        long expectedSeq = 1, last = 0;
        while (true)
        {
            var batch = (await c.QueryAsync<Row>(
                $"SELECT {Columns} FROM audit_events WHERE seq >= @from ORDER BY seq LIMIT 1000",
                new { from = expectedSeq })).ToList();
            if (batch.Count == 0) break;
            foreach (var r in batch)
            {
                ct.ThrowIfCancellationRequested();
                if (r.Seq != expectedSeq) return new VerifyResult(false, last, expectedSeq, $"row {expectedSeq} is missing");
                var mac = Mac(prev, r.Seq, r.Ts, r.ActorId, r.Action, r.TargetType, r.TargetId, r.DetailsEnc);
                if (!CryptographicOperations.FixedTimeEquals(mac, r.Mac)) return new VerifyResult(false, last, r.Seq, $"row {r.Seq} was modified");
                prev = r.Mac;
                last = r.Seq;
                expectedSeq++;
            }
        }
        var head = await c.QuerySingleAsync<(long Seq, byte[] Mac)>("SELECT seq, mac FROM audit_head WHERE id = 1");
        if (head.Seq != last || !CryptographicOperations.FixedTimeEquals(head.Mac, prev))
            return new VerifyResult(false, last, last + 1, $"chain head says {head.Seq} rows, table has {last}");
        return new VerifyResult(true, last, null, null);
    }

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    /// <summary>MySQL DATETIME(6) keeps microseconds; the MAC must use exactly what is stored.</summary>
    private static DateTime Truncate(DateTime t) => new(t.Ticks - t.Ticks % 10, DateTimeKind.Unspecified);

    private byte[] Mac(byte[] prevMac, long seq, DateTime ts, string? actor, string action, string? targetType, string? targetId, byte[] detailsEnc)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _macKey);
        Span<byte> num = stackalloc byte[8];
        h.AppendData(prevMac);
        BinaryPrimitives.WriteInt64BigEndian(num, seq);
        h.AppendData(num);
        BinaryPrimitives.WriteInt64BigEndian(num, ts.Ticks);
        h.AppendData(num);
        foreach (var s in new[] { actor, action, targetType, targetId })
        {
            var bytes = s is null ? [] : Encoding.UTF8.GetBytes(s);
            BinaryPrimitives.WriteInt32BigEndian(num, s is null ? -1 : bytes.Length);
            h.AppendData(num[..4]);
            h.AppendData(bytes);
        }
        h.AppendData(detailsEnc);
        return h.GetHashAndReset();
    }
}
