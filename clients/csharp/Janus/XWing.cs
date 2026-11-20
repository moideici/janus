using System.Numerics;
using System.Security.Cryptography;

namespace Janus;

/// <summary>An X-Wing key pair derived from a 32-byte seed (spec § 3.1).</summary>
public sealed class Identity
{
    public byte[] Seed { get; }
    public byte[] DecapsulationKeyM { get; }     // dk_M, 2400 bytes
    public byte[] SecretX { get; }               // sk_X, 32 bytes
    public byte[] PublicKey { get; }             // pk = ek_M ‖ pk_X, 1216 bytes

    public Identity(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 32) throw new ArgumentException("an identity seed is 32 bytes");
        Seed = seed.ToArray();
        var expanded = Keccak.Shake256(seed, 96);
        var (ek, dk) = MlKem768.KeyGenInternal(expanded.AsSpan(0, 32), expanded.AsSpan(32, 32));
        DecapsulationKeyM = dk;
        SecretX = expanded[64..96];
        PublicKey = new byte[XWing.PublicKeySize];
        ek.CopyTo(PublicKey, 0);
        Curve25519.X25519Base(SecretX).CopyTo(PublicKey, MlKem768.EncapsulationKeySize);
        CryptographicOperations.ZeroMemory(expanded);
    }

    public ReadOnlySpan<byte> PublicX => PublicKey.AsSpan(MlKem768.EncapsulationKeySize, 32);

    public static Identity Generate() => new(RandomNumberGenerator.GetBytes(32));
}

/// <summary>X-Wing combiner and the hidden encapsulation of spec § 5.2–5.3.</summary>
public static class XWing
{
    public const int PublicKeySize = MlKem768.EncapsulationKeySize + 32;   // 1216
    private static readonly byte[] Label = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };   // \.//^\
    private static readonly byte[] MaskLabel = "janus/v1/masque"u8.ToArray();
    private static readonly BigInteger EightL = 8 * Curve25519.L;

    public static byte[] Combine(ReadOnlySpan<byte> ssM, ReadOnlySpan<byte> ssX, ReadOnlySpan<byte> ctX, ReadOnlySpan<byte> pkX)
    {
        var input = new byte[32 * 4 + Label.Length];
        ssM.CopyTo(input);
        ssX.CopyTo(input.AsSpan(32));
        ctX.CopyTo(input.AsSpan(64));
        pkX.CopyTo(input.AsSpan(96));
        Label.CopyTo(input, 128);
        var ss = Keccak.Sha3_256(input);
        CryptographicOperations.ZeroMemory(input);
        return ss;
    }

    /// <summary>
    /// A public key is valid (spec § 3.1) if it has the right size, its ML-KEM part passes the FIPS 203
    /// check, and pk_X is canonical: bit 255 clear and value below p. Low-order points are accepted.
    /// </summary>
    public static bool IsValidPublicKey(ReadOnlySpan<byte> pk) =>
        pk.Length == PublicKeySize
        && MlKem768.CheckEncapsulationKey(pk[..MlKem768.EncapsulationKeySize])
        && Curve25519.IsCanonical(pk[MlKem768.EncapsulationKeySize..]);

    /// <summary>
    /// Standard X-Wing encapsulation (draft-11) with explicit randomness eseed (64 bytes), used only
    /// to check the draft's test vector. Returns (ss, ct_M, ct_X).
    /// </summary>
    public static (byte[] ss, byte[] ctM, byte[] ctX) EncapsulateDerand(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> eseed)
    {
        var ekM = pk[..MlKem768.EncapsulationKeySize];
        var pkX = pk[MlKem768.EncapsulationKeySize..];
        var (ssM, ctM) = MlKem768.EncapsInternal(ekM, eseed[..32]);
        var ekX = eseed[32..64];
        var ctX = Curve25519.X25519Base(ekX);
        var ssX = Curve25519.X25519(ekX, pkX);
        return (Combine(ssM, ssX, ctX, pkX), ctM, ctX);
    }

    /// <summary>Standard X-Wing decapsulation (draft-11).</summary>
    public static byte[] Decapsulate(Identity id, ReadOnlySpan<byte> ctM, ReadOnlySpan<byte> ctX)
    {
        var ssM = MlKem768.Decaps(id.DecapsulationKeyM, ctM);
        var ssX = Curve25519.X25519(id.SecretX, ctX);
        return Combine(ssM, ssX, ctX, id.PublicX);
    }

    /// <summary>
    /// Hidden encapsulation (spec § 5.2). Returns the shared secret ss and the first 1568 bytes of the
    /// slot: the Elligator 2 representative r and the masked Kemeleon encoding κ'.
    /// </summary>
    public static (byte[] ss, byte[] slotPrefix) EncapsulateHidden(ReadOnlySpan<byte> pk)
    {
        if (!IsValidPublicKey(pk)) throw new CryptographicException("invalid public key");
        var ekM = pk[..MlKem768.EncapsulationKeySize];
        var pkX = pk[MlKem768.EncapsulationKeySize..];

        // 1–2. A uniform point P = s·G of the full group, retried until it has a representative.
        BigInteger s;
        byte[] ctX;
        byte[]? r;
        do
        {
            s = RandomUniform.BigIntegerAtMost(EightL - 1);
            ctX = Curve25519.UnclampedLadder(s, Curve25519.FullGroupGenerator);
            r = Curve25519.ElligatorRepresentative(ctX);
        } while (r is null);

        // 3. X25519 secret, unclamped ladder on all 256 bits of s.
        var ssX = Curve25519.UnclampedLadder(s, pkX);

        // 4–5. ML-KEM and the combiner.
        var (ssM, ctM) = MlKem768.Encaps(ekM);
        var ss = Combine(ssM, ssX, ctX, pkX);

        // 6. Kemeleon encoding and mask.
        var kappa = Kemeleon.EncodeCiphertext(ctM);
        var mask = Mask(ssX, ctX);
        var prefix = new byte[32 + Kemeleon.EncodedSize];
        r.CopyTo(prefix, 0);
        for (int i = 0; i < Kemeleon.EncodedSize; i++) prefix[32 + i] = (byte)(kappa[i] ^ mask[i]);

        CryptographicOperations.ZeroMemory(ssM);
        CryptographicOperations.ZeroMemory(ssX);
        return (ss, prefix);
    }

    /// <summary>Hidden decapsulation (spec § 5.3). Never fails: a foreign slot gives an unrelated ss.</summary>
    public static byte[] DecapsulateHidden(Identity id, ReadOnlySpan<byte> slotPrefix)
    {
        var ctX = Curve25519.ElligatorMap(slotPrefix[..32]);
        var ssX = Curve25519.X25519(id.SecretX, ctX);
        var mask = Mask(ssX, ctX);
        var kappa = new byte[Kemeleon.EncodedSize];
        for (int i = 0; i < kappa.Length; i++) kappa[i] = (byte)(slotPrefix[32 + i] ^ mask[i]);
        var ctM = Kemeleon.DecodeCiphertext(kappa);
        var ssM = MlKem768.Decaps(id.DecapsulationKeyM, ctM);
        var ss = Combine(ssM, ssX, ctX, id.PublicX);
        CryptographicOperations.ZeroMemory(ssM);
        CryptographicOperations.ZeroMemory(ssX);
        return ss;
    }

    /// <summary>SHAKE256("janus/v1/masque" ‖ ss_X ‖ ct_X, 1536).</summary>
    private static byte[] Mask(ReadOnlySpan<byte> ssX, ReadOnlySpan<byte> ctX)
    {
        var xof = Keccak.NewShake256();
        xof.Absorb(MaskLabel);
        xof.Absorb(ssX);
        xof.Absorb(ctX);
        return xof.Squeeze(Kemeleon.EncodedSize);
    }
}
