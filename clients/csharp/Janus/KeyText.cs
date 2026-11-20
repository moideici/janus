using System.Text;

namespace Janus;

/// <summary>Text encoding of keys (spec § 3.3) and identity files.</summary>
public static class KeyText
{
    public const string IdentityHrp = "janus-secret-key-";
    public const string PublicKeyHrp = "janus";

    public static string EncodeIdentity(ReadOnlySpan<byte> seed) =>
        Bech32m.Encode(IdentityHrp, Bech32m.ToFiveBit(seed)).ToUpperInvariant();

    public static string EncodePublicKey(ReadOnlySpan<byte> pk) =>
        Bech32m.Encode(PublicKeyHrp, Bech32m.ToFiveBit(pk));

    /// <summary>Decodes an identity string into its 32-byte seed; null if invalid.</summary>
    public static byte[]? DecodeIdentity(string text)
    {
        var decoded = Bech32m.Decode(text.Trim(), 90);
        if (decoded is null || decoded.Value.hrp != IdentityHrp) return null;
        var bytes = Bech32m.FromFiveBit(decoded.Value.data5);
        return bytes is { Length: 32 } ? bytes : null;
    }

    /// <summary>Decodes a public key string; null if invalid, including a failed ML-KEM key check.</summary>
    public static byte[]? DecodePublicKey(string text)
    {
        var decoded = Bech32m.Decode(text.Trim(), int.MaxValue);
        if (decoded is null || decoded.Value.hrp != PublicKeyHrp) return null;
        var bytes = Bech32m.FromFiveBit(decoded.Value.data5);
        if (bytes is null || !XWing.IsValidPublicKey(bytes)) return null;
        return bytes;
    }

    /// <summary>Identity file contents, as written by this client.</summary>
    public static string IdentityFile(Identity id) =>
        "# Janus identity (PROTOTYPE). Public key:\n" +
        $"# {EncodePublicKey(id.PublicKey)}\n" +
        $"{EncodeIdentity(id.Seed)}\n";

    /// <summary>
    /// Reads an identity file: '#' lines are comments; the first line starting with
    /// JANUS-SECRET-KEY-1 (any case) is the identity.
    /// </summary>
    public static Identity ReadIdentityFile(string path)
    {
        foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
        {
            var line = raw.Trim().TrimStart('﻿');
            if (line.StartsWith('#')) continue;
            if (line.StartsWith("JANUS-SECRET-KEY-1", StringComparison.OrdinalIgnoreCase))
            {
                var seed = DecodeIdentity(line) ?? throw new JanusException($"{path}: invalid identity");
                return new Identity(seed);
            }
        }
        throw new JanusException($"{path}: no identity found");
    }

    /// <summary>Reads a file of public keys: one per line, '#' comments and blank lines ignored.</summary>
    public static List<byte[]> ReadPublicKeyFile(string path)
    {
        var keys = new List<byte[]>();
        foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
        {
            var line = raw.Trim().TrimStart('﻿');
            if (line.Length == 0 || line.StartsWith('#')) continue;
            keys.Add(DecodePublicKey(line) ?? throw new JanusException($"{path}: invalid public key"));
        }
        return keys;
    }
}
