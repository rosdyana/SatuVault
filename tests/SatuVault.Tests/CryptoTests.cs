using System.Security.Cryptography;
using System.Text;
using SatuVault.Crypto;

namespace SatuVault.Tests;

public class CryptoTests
{
    private static readonly KeyRing Ring = KeyRing.CreateNew(KeyProtection.None);

    [Fact]
    public void Field_cipher_round_trips_and_binds_to_its_row()
    {
        var c = new FieldCipher(Ring);
        var blob = c.EncryptString("pa55word", FieldCipher.Aad("items", "secret", "row-1"));

        Assert.DoesNotContain("pa55word", Encoding.UTF8.GetString(blob));
        Assert.Equal("pa55word", c.DecryptString(blob, FieldCipher.Aad("items", "secret", "row-1")));
        // Same ciphertext pasted into another row or column doesn't decrypt.
        Assert.ThrowsAny<CryptographicException>(() => c.DecryptString(blob, FieldCipher.Aad("items", "secret", "row-2")));
        Assert.ThrowsAny<CryptographicException>(() => c.DecryptString(blob, FieldCipher.Aad("items", "meta", "row-1")));
    }

    [Fact]
    public void Field_cipher_detects_tampering_and_uses_fresh_nonces()
    {
        var c = new FieldCipher(Ring);
        var a = c.EncryptString("same", "t.c:1");
        var b = c.EncryptString("same", "t.c:1");
        Assert.NotEqual(a, b);

        a[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => c.DecryptString(a, "t.c:1"));
    }

    [Fact]
    public void Different_master_keys_cannot_read_each_other()
    {
        var other = new FieldCipher(KeyRing.CreateNew(KeyProtection.None));
        var blob = new FieldCipher(Ring).EncryptString("x", "t.c:1");
        Assert.ThrowsAny<CryptographicException>(() => other.DecryptString(blob, "t.c:1"));
    }

    [Fact]
    public void Key_file_and_passphrase_backup_round_trip()
    {
        var dir = Directory.CreateTempSubdirectory();
        var path = Path.Combine(dir.FullName, "master.key");
        Ring.Save(path);
        var loaded = KeyRing.Load(path);
        Assert.Equal(Ring.Subkey("data"), loaded.Subkey("data"));

        var backup = Ring.ExportBackup("correct horse battery staple");
        Assert.Equal(Ring.Subkey("audit"), KeyRing.ImportBackup(backup, "correct horse battery staple", KeyProtection.None).Subkey("audit"));
        Assert.ThrowsAny<CryptographicException>(() => KeyRing.ImportBackup(backup, "wrong passphrase!!!!", KeyProtection.None));
        Assert.Throws<ArgumentException>(() => Ring.ExportBackup("short"));
    }

    [Fact]
    public void Subkeys_differ_by_purpose()
    {
        Assert.NotEqual(Ring.Subkey("data"), Ring.Subkey("audit"));
        Assert.NotEqual(Ring.Subkey("index"), Ring.Subkey("totp"));
    }

    [Fact]
    public void Blind_index_is_stable_and_case_insensitive()
    {
        var idx = new BlindIndex(Ring);
        Assert.Equal(idx.Compute("email", "UserB@Corp.test"), idx.Compute("email", " userb@corp.test "));
        Assert.NotEqual(idx.Compute("email", "a@corp.test"), idx.Compute("oid", "a@corp.test"));
    }

    // RFC 6238 appendix B, SHA-1 secret "12345678901234567890".
    [Theory]
    [InlineData(59, "94287082")]
    [InlineData(1111111109, "07081804")]
    [InlineData(1234567890, "89005924")]
    [InlineData(2000000000, "69279037")]
    public void Totp_matches_rfc_vectors(long unix, string expected)
    {
        var secret = "12345678901234567890"u8.ToArray();
        Assert.Equal(expected, Totp.Code(secret, unix / 30, digits: 8));
    }

    [Fact]
    public void Totp_accepts_drift_and_rejects_replay()
    {
        var secret = Totp.NewSecret();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.StepAt(now);

        Assert.Equal(step, Totp.Verify(secret, Totp.Code(secret, step), now, 0));
        Assert.Equal(step - 1, Totp.Verify(secret, Totp.Code(secret, step - 1), now, 0));
        Assert.Null(Totp.Verify(secret, Totp.Code(secret, step - 2), now, 0));
        // Already used this step (or a later one): rejected.
        Assert.Null(Totp.Verify(secret, Totp.Code(secret, step), now, step));
        Assert.Null(Totp.Verify(secret, "12345", now, 0));
        Assert.Null(Totp.Verify(secret, "abcdef", now, 0));
    }

    [Fact]
    public void Base32_round_trips_and_provisioning_uri_is_standard()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        Assert.Equal(bytes, Base32.Decode(Base32.Encode(bytes)));
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Base32.Encode("12345678901234567890"u8));

        var uri = Totp.ProvisioningUri(bytes, "SatuVault", "userb@corp.test");
        Assert.StartsWith("otpauth://totp/SatuVault:userb%40corp.test?secret=", uri);
        Assert.Contains("&issuer=SatuVault", uri);
    }
}
