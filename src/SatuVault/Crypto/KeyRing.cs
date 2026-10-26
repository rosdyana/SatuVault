using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SatuVault.Crypto;

public enum KeyProtection
{
    /// <summary>DPAPI bound to the Windows account running the app (the IIS app pool identity).</summary>
    DpapiUser,
    /// <summary>DPAPI bound to the machine: any process on this machine can unprotect it.</summary>
    DpapiMachine,
    /// <summary>Unprotected file. Development only; refused in Production.</summary>
    None,
}

/// <summary>
/// The master key(s) and the subkeys derived from them. Keys have ids so a later
/// rotation can add a key while old ciphertexts still decrypt.
/// </summary>
public sealed class KeyRing
{
    private readonly Dictionary<int, byte[]> _masters;

    public int CurrentId { get; }
    public KeyProtection Protection { get; }

    public KeyRing(Dictionary<int, byte[]> masters, int currentId, KeyProtection protection)
    {
        if (!masters.ContainsKey(currentId)) throw new ArgumentException("Current key id is missing", nameof(currentId));
        foreach (var k in masters.Values)
            if (k.Length != 32) throw new ArgumentException("Master keys must be 256-bit");
        _masters = masters;
        CurrentId = currentId;
        Protection = protection;
    }

    public static KeyRing CreateNew(KeyProtection protection) =>
        new(new Dictionary<int, byte[]> { [1] = RandomNumberGenerator.GetBytes(32) }, 1, protection);

    public IReadOnlyCollection<int> KeyIds => _masters.Keys;

    /// <summary>Purpose-specific 256-bit key (HKDF-SHA256). Purposes: data, index, audit, totp.</summary>
    public byte[] Subkey(string purpose, int? keyId = null)
    {
        var id = keyId ?? CurrentId;
        if (!_masters.TryGetValue(id, out var master)) throw new CryptographicException($"Unknown key id {id}");
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, info: Encoding.UTF8.GetBytes($"satuvault/{purpose}/v1"));
    }

    // ---- file format ----

    private sealed record KeyFile(int Version, string Protection, int Current, List<KeyEntry> Keys);
    private sealed record KeyEntry(int Id, DateTimeOffset Created, string Material);

    private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("SatuVault master key v1");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public void Save(string path)
    {
        var entries = _masters.Select(kv => new KeyEntry(kv.Key, DateTimeOffset.UtcNow, Convert.ToBase64String(Protect(kv.Value, Protection)))).ToList();
        var file = new KeyFile(1, Protection.ToString(), CurrentId, entries);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(file, Json));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, path, overwrite: true);
    }

    public static KeyRing Load(string path)
    {
        var file = JsonSerializer.Deserialize<KeyFile>(File.ReadAllText(path), Json)
                   ?? throw new CryptographicException("Empty key file");
        if (file.Version != 1) throw new CryptographicException($"Unsupported key file version {file.Version}");
        var protection = Enum.Parse<KeyProtection>(file.Protection);
        var keys = file.Keys.ToDictionary(k => k.Id, k => Unprotect(Convert.FromBase64String(k.Material), protection));
        return new KeyRing(keys, file.Current, protection);
    }

    private static byte[] Protect(byte[] key, KeyProtection p) => p switch
    {
        KeyProtection.None => key,
        _ => DpapiProtect(key, p),
    };

    private static byte[] Unprotect(byte[] data, KeyProtection p) => p switch
    {
        KeyProtection.None => data,
        _ => DpapiUnprotect(data, p),
    };

    private static byte[] DpapiProtect(byte[] key, KeyProtection p)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI key protection requires Windows");
        return ProtectedData.Protect(key, DpapiEntropy, p == KeyProtection.DpapiMachine ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser);
    }

    private static byte[] DpapiUnprotect(byte[] data, KeyProtection p)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI key protection requires Windows");
        return ProtectedData.Unprotect(data, DpapiEntropy, p == KeyProtection.DpapiMachine ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser);
    }

    // ---- passphrase backup ----

    private const int BackupIterations = 600_000;
    private sealed record BackupFile(int Version, int Iterations, string Salt, string Nonce, string Tag, string Data);

    /// <summary>Master keys encrypted with a passphrase (PBKDF2-SHA256 → AES-256-GCM), for disaster recovery.</summary>
    public string ExportBackup(string passphrase)
    {
        if (passphrase.Length < 16) throw new ArgumentException("Backup passphrase must be at least 16 characters");
        var plain = JsonSerializer.SerializeToUtf8Bytes(new { current = CurrentId, keys = _masters.ToDictionary(k => k.Key.ToString(), k => Convert.ToBase64String(k.Value)) });
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var kek = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, BackupIterations, HashAlgorithmName.SHA256, 32);
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(kek, 16)) gcm.Encrypt(nonce, plain, ct, tag, "satuvault-backup-v1"u8);
        CryptographicOperations.ZeroMemory(plain);
        var b = new BackupFile(1, BackupIterations, Convert.ToBase64String(salt), Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(ct));
        return JsonSerializer.Serialize(b, Json);
    }

    public static KeyRing ImportBackup(string backupJson, string passphrase, KeyProtection protection)
    {
        var b = JsonSerializer.Deserialize<BackupFile>(backupJson, Json) ?? throw new CryptographicException("Empty backup");
        var kek = Rfc2898DeriveBytes.Pbkdf2(passphrase, Convert.FromBase64String(b.Salt), b.Iterations, HashAlgorithmName.SHA256, 32);
        var ct = Convert.FromBase64String(b.Data);
        var plain = new byte[ct.Length];
        using (var gcm = new AesGcm(kek, 16))
            gcm.Decrypt(Convert.FromBase64String(b.Nonce), ct, Convert.FromBase64String(b.Tag), plain, "satuvault-backup-v1"u8);
        Dictionary<int, byte[]> keys;
        int current;
        // JsonDocument reads from `plain` directly, so finish with it before wiping.
        using (var doc = JsonDocument.Parse(plain))
        {
            keys = doc.RootElement.GetProperty("keys").EnumerateObject()
                .ToDictionary(p => int.Parse(p.Name), p => Convert.FromBase64String(p.Value.GetString()!));
            current = doc.RootElement.GetProperty("current").GetInt32();
        }
        CryptographicOperations.ZeroMemory(plain);
        return new KeyRing(keys, current, protection);
    }
}
