using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SatuVault.Crypto;

/// <summary>RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) as used by Google/Microsoft Authenticator.</summary>
public static class Totp
{
    public const int Digits = 6;
    public const int StepSeconds = 30;
    /// <summary>Accept the previous and next step to tolerate clock drift.</summary>
    public const int Drift = 1;

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    public static long StepAt(DateTimeOffset time) => time.ToUnixTimeSeconds() / StepSeconds;

    public static string Code(byte[] secret, long step, int digits = Digits)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, hash);
        var offset = hash[^1] & 0x0f;
        var bin = (BinaryPrimitives.ReadInt32BigEndian(hash.Slice(offset, 4)) & 0x7fffffff) % (int)Math.Pow(10, digits);
        return bin.ToString().PadLeft(digits, '0');
    }

    /// <summary>
    /// Returns the matched step, or null. Steps at or before <paramref name="lastUsedStep"/>
    /// are rejected so a code can't be replayed.
    /// </summary>
    public static long? Verify(byte[] secret, string? code, DateTimeOffset now, long lastUsedStep)
    {
        code = code?.Replace(" ", "").Trim();
        if (code is null || code.Length != Digits || !code.All(char.IsAsciiDigit)) return null;
        var expected = Encoding.ASCII.GetBytes(code);
        var current = StepAt(now);
        long? match = null;
        // Check every candidate without early exit to keep timing uniform.
        for (var s = current - Drift; s <= current + Drift; s++)
        {
            var ok = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(secret, s)), expected);
            if (ok && s > lastUsedStep && match is null) match = s;
        }
        return match;
    }

    public static string ProvisioningUri(byte[] secret, string issuer, string account) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={Base32.Encode(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
}

public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] Decode(string s)
    {
        s = s.Trim().TrimEnd('=').Replace(" ", "").ToUpperInvariant();
        var output = new List<byte>(s.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var c in s)
        {
            var v = Alphabet.IndexOf(c);
            if (v < 0) throw new FormatException($"Invalid base32 character '{c}'");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return output.ToArray();
    }
}
