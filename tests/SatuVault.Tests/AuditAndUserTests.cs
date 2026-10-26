using System.Text;
using Dapper;
using MySqlConnector;
using SatuVault.Data;

namespace SatuVault.Tests;

public class AuditAndUserTests : IAsyncLifetime
{
    private Env _env = null!;

    public async Task InitializeAsync() => _env = await Env.CreateAsync();
    public async Task DisposeAsync() => await _env.DisposeAsync();

    [Fact]
    public async Task Audit_chain_verifies_and_details_are_encrypted_at_rest()
    {
        await _env.Audit.WriteAsync("u1", Env.Req, "item.reveal", "item", "i1", new { label = "YouTube B", field = "password" });
        await _env.Audit.WriteAsync("u2", Env.Req, "item.copy", "item", "i1", new { label = "YouTube B", field = "password" });

        var events = await _env.AuditAsync();
        Assert.Equal(["item.reveal", "item.copy"], events.Select(e => e.Action));
        Assert.Equal("YouTube B", events[0].Details["label"].GetString());
        Assert.Equal("10.1.2.3", events[0].Details["ip"].GetString());
        Assert.True((await _env.Audit.VerifyAsync()).Intact);

        await using var root = await _env.Db.RootAsync();
        var raw = await root.QueryAsync<byte[]>("SELECT details_enc FROM audit_events");
        Assert.All(raw, r => Assert.DoesNotContain("YouTube", Encoding.UTF8.GetString(r)));
    }

    [Fact]
    public async Task App_db_user_cannot_change_or_delete_audit_rows()
    {
        await _env.Audit.WriteAsync("u1", Env.Req, "auth.signin");
        await using var app = new MySqlConnection(_env.Db.AppConnectionString);
        await app.OpenAsync();
        var upd = await Assert.ThrowsAsync<MySqlException>(() => app.ExecuteAsync("UPDATE audit_events SET action = 'x'"));
        Assert.Equal(MySqlErrorCode.TableAccessDenied, upd.ErrorCode);
        await Assert.ThrowsAsync<MySqlException>(() => app.ExecuteAsync("DELETE FROM audit_events"));
    }

    [Fact]
    public async Task Tampering_by_a_dba_is_detected()
    {
        for (var i = 0; i < 4; i++) await _env.Audit.WriteAsync("u1", Env.Req, "item.reveal", "item", $"i{i}");
        await using var root = await _env.Db.RootAsync();

        await root.ExecuteAsync("UPDATE audit_events SET actor_id = 'someone-else' WHERE seq = 2");
        var r = await _env.Audit.VerifyAsync();
        Assert.False(r.Intact);
        Assert.Equal(2, r.FirstBadSeq);

        await root.ExecuteAsync("UPDATE audit_events SET actor_id = 'u1' WHERE seq = 2");
        Assert.True((await _env.Audit.VerifyAsync()).Intact);

        await root.ExecuteAsync("DELETE FROM audit_events WHERE seq = 3");
        r = await _env.Audit.VerifyAsync();
        Assert.False(r.Intact);
        Assert.Equal(3, r.FirstBadSeq);
    }

    [Fact]
    public async Task Removing_the_newest_rows_is_detected_through_the_head()
    {
        for (var i = 0; i < 3; i++) await _env.Audit.WriteAsync("u1", Env.Req, "x");
        await using var root = await _env.Db.RootAsync();
        await root.ExecuteAsync("DELETE FROM audit_events WHERE seq = 3");
        Assert.False((await _env.Audit.VerifyAsync()).Intact);
    }

    [Fact]
    public async Task Users_are_stored_encrypted_and_found_by_blind_index()
    {
        var (u, created) = await _env.Users.UpsertFromSignInAsync("t1", "oid-1", "UserB@corp.test", "User B");
        Assert.True(created);
        var (again, createdAgain) = await _env.Users.UpsertFromSignInAsync("t1", "oid-1", "userb@corp.test", "User B");
        Assert.False(createdAgain);
        Assert.Equal(u.Id, again.Id);
        Assert.Equal(u.Id, (await _env.Users.FindByEmailAsync("USERB@corp.test"))!.Id);

        await using var root = await _env.Db.RootAsync();
        var row = await root.QuerySingleAsync<(byte[] Email, byte[] Name)>("SELECT email_enc, name_enc FROM users");
        Assert.DoesNotContain("corp.test", Encoding.UTF8.GetString(row.Email));
        Assert.DoesNotContain("User B", Encoding.UTF8.GetString(row.Name));
    }

    [Fact]
    public async Task Totp_enrollment_needs_a_valid_first_code()
    {
        var (u, _) = await _env.Users.UpsertFromSignInAsync("t1", "oid-2", "a@corp.test", "A");
        var secret = await _env.Users.BeginEnrollmentAsync(u.Id);
        Assert.Equal(secret, await _env.Users.GetPendingSecretAsync(u.Id));
        Assert.Equal(TotpOutcome.NotEnrolled, (await _env.Users.VerifyCodeAsync(u.Id, _env.Code(secret))).Outcome);
        Assert.False((await _env.Users.ConfirmEnrollmentAsync(u.Id, "000000")).Ok);
        Assert.True((await _env.Users.ConfirmEnrollmentAsync(u.Id, _env.Code(secret))).Ok);
        Assert.True((await _env.Users.GetAsync(u.Id))!.TotpEnrolled);
        await Assert.ThrowsAsync<InvalidOperationException>(() => _env.Users.BeginEnrollmentAsync(u.Id));
    }

    [Fact]
    public async Task Each_code_works_once_and_five_failures_lock()
    {
        var (u, secret) = await _env.EnrolledUserAsync("b@corp.test");
        var code = _env.Code(secret);
        Assert.True((await _env.Users.VerifyCodeAsync(u.Id, code)).Ok);
        // A replayed code is a failed attempt too.
        var replay = await _env.Users.VerifyCodeAsync(u.Id, code);
        Assert.Equal(TotpOutcome.Invalid, replay.Outcome);
        Assert.Equal(4, replay.FailuresLeft);

        _env.NextStep();
        for (var i = 1; i <= 3; i++)
        {
            var r = await _env.Users.VerifyCodeAsync(u.Id, "000000");
            Assert.Equal(TotpOutcome.Invalid, r.Outcome);
            Assert.Equal(4 - i, r.FailuresLeft);
        }
        Assert.Equal(TotpOutcome.Locked, (await _env.Users.VerifyCodeAsync(u.Id, "000000")).Outcome);
        // Even the right code is refused while locked.
        Assert.Equal(TotpOutcome.Locked, (await _env.Users.VerifyCodeAsync(u.Id, _env.Code(secret))).Outcome);

        _env.Clock.Advance(TimeSpan.FromMinutes(16));
        Assert.True((await _env.Users.VerifyCodeAsync(u.Id, _env.Code(secret))).Ok);
    }

    [Fact]
    public async Task Reset_forces_reenrollment()
    {
        var (u, secret) = await _env.EnrolledUserAsync("c@corp.test");
        await _env.Users.ResetTotpAsync(u.Id);
        Assert.False((await _env.Users.GetAsync(u.Id))!.TotpEnrolled);
        Assert.Equal(TotpOutcome.NotEnrolled, (await _env.Users.VerifyCodeAsync(u.Id, _env.Code(secret))).Outcome);
    }
}
