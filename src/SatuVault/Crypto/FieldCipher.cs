using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SatuVault.Crypto;

/// <summary>
/// AES-256-GCM for every value stored in MySQL.
/// Layout: version(1) | keyId(4, BE) | nonce(12) | tag(16) | ciphertext.
/// The associated data binds a ciphertext to its table, column and row, so it
/// can't be copied into another record.
/// </summary>
public sealed class FieldCipher(KeyRing keys)
{
    private const byte Version = 1;
    private const int Header = 1 + 4 + 12 + 16;

    private readonly Dictionary<int, byte[]> _dataKeys = keys.KeyIds.ToDictionary(id => id, id => keys.Subkey("data", id));

    public static string Aad(string table, string column, string rowId) => $"{table}.{column}:{rowId}";

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, string aad)
    {
        var output = new byte[Header + plaintext.Length];
        output[0] = Version;
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(1, 4), keys.CurrentId);
        var nonce = output.AsSpan(5, 12);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(_dataKeys[keys.CurrentId], 16);
        gcm.Encrypt(nonce, plaintext, output.AsSpan(Header), output.AsSpan(17, 16), Encoding.UTF8.GetBytes(aad));
        return output;
    }

    public byte[] Decrypt(byte[] blob, string aad)
    {
        if (blob.Length < Header || blob[0] != Version) throw new CryptographicException("Unknown ciphertext format");
        var keyId = BinaryPrimitives.ReadInt32BigEndian(blob.AsSpan(1, 4));
        if (!_dataKeys.TryGetValue(keyId, out var key)) throw new CryptographicException($"Unknown key id {keyId}");
        var plain = new byte[blob.Length - Header];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(blob.AsSpan(5, 12), blob.AsSpan(Header), blob.AsSpan(17, 16), plain, Encoding.UTF8.GetBytes(aad));
        return plain;
    }

    public byte[] EncryptString(string value, string aad) => Encrypt(Encoding.UTF8.GetBytes(value), aad);
    public string DecryptString(byte[] blob, string aad) => Encoding.UTF8.GetString(Decrypt(blob, aad));

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public byte[] EncryptJson<T>(T value, string aad) => Encrypt(JsonSerializer.SerializeToUtf8Bytes(value, Json), aad);

    public T DecryptJson<T>(byte[] blob, string aad)
    {
        var plain = Decrypt(blob, aad);
        try
        {
            return JsonSerializer.Deserialize<T>(plain, Json) ?? throw new CryptographicException("Empty payload");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}

/// <summary>Deterministic HMAC lookups (Entra object id, email) without storing the value.</summary>
public sealed class BlindIndex(KeyRing keys)
{
    private readonly byte[] _key = keys.Subkey("index");

    public byte[] Compute(string kind, string value) =>
        HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes($"{kind}\u001f{value.Trim().ToLowerInvariant()}"));
}
