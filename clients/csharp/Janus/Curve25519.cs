using System.Numerics;
using System.Security.Cryptography;

namespace Janus;

/// <summary>
/// Curve25519 arithmetic with System.Numerics.BigInteger: the RFC 7748 Montgomery ladder (clamped
/// X25519, and the unclamped ladder of spec § 5.2) and Elligator 2 (spec § 5.4).
/// BigInteger is not constant-time: this code is for interoperability, not for real secrets.
/// </summary>
public static class Curve25519
{
    public static readonly BigInteger P = (BigInteger.One << 255) - 19;
    public static readonly BigInteger A = 486662;
    private static readonly BigInteger A24 = 121665;
    private static readonly BigInteger HalfP = (P - 1) / 2;
    private static readonly BigInteger SqrtMinusOne = BigInteger.ModPow(2, (P - 1) / 4, P);

    /// <summary>ℓ, the order of the prime-order subgroup.</summary>
    public static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    /// <summary>u(G) of spec § 5.2: a generator of the full group of order 8ℓ.</summary>
    public static readonly byte[] FullGroupGenerator =
        Convert.FromHexString("bb72312170e8156f7a836313f85bee9b1fdce926ba9804a29e8d137ec67f2533");

    private static readonly byte[] BasePoint = Basepoint9();

    private static byte[] Basepoint9()
    {
        var b = new byte[32];
        b[0] = 9;
        return b;
    }

    // ---- Field helpers ----

    public static BigInteger Mod(BigInteger x)
    {
        var r = BigInteger.Remainder(x, P);
        return r.Sign < 0 ? r + P : r;
    }

    public static BigInteger FromLittleEndian(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: false);

    public static byte[] ToLittleEndian(BigInteger x)
    {
        var output = new byte[32];
        if (!x.TryWriteBytes(output, out _, isUnsigned: true, isBigEndian: false))
            throw new InvalidOperationException("field element too large");
        return output;
    }

    private static BigInteger Inverse(BigInteger x) => BigInteger.ModPow(x, P - 2, P);

    /// <summary>Euler's criterion; 0 counts as a square.</summary>
    public static bool IsSquare(BigInteger x)
    {
        x = Mod(x);
        return x.IsZero || BigInteger.ModPow(x, HalfP, P).IsOne;
    }

    /// <summary>A square root of a square x (p ≡ 5 mod 8).</summary>
    private static BigInteger Sqrt(BigInteger x)
    {
        x = Mod(x);
        var c = BigInteger.ModPow(x, (P + 3) / 8, P);
        if (Mod(c * c) == x) return c;
        c = Mod(c * SqrtMinusOne);
        if (Mod(c * c) != x) throw new InvalidOperationException("not a square");
        return c;
    }

    // ---- Montgomery ladder ----

    /// <summary>
    /// RFC 7748 ladder on the given number of scalar bits (most significant first), with no clamping.
    /// Returns u(k·P) as a canonical field element (0 for the point at infinity).
    /// </summary>
    public static BigInteger Ladder(BigInteger k, BigInteger u, int bits)
    {
        BigInteger x1 = Mod(u), x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        int swap = 0;
        for (int t = bits - 1; t >= 0; t--)
        {
            int kt = (int)((k >> t) & 1);
            swap ^= kt;
            if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
            swap = kt;

            var a = x2 + z2; var aa = Mod(a * a);
            var b = x2 - z2; var bb = Mod(b * b);
            var e = aa - bb;
            var c = x3 + z3; var d = x3 - z3;
            var da = Mod(d * a); var cb = Mod(c * b);
            var sum = da + cb; var diff = da - cb;
            x3 = Mod(sum * sum);
            z3 = Mod(x1 * Mod(diff * diff));
            x2 = Mod(aa * bb);
            z2 = Mod(e * (aa + A24 * e));
        }
        if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
        return Mod(x2 * Inverse(z2));
    }

    /// <summary>True if the 32 bytes encode a field element below p with bit 255 clear.</summary>
    public static bool IsCanonical(ReadOnlySpan<byte> u32) => u32.Length == 32 && FromLittleEndian(u32) < P;

    /// <summary>Decodes a u-coordinate as RFC 7748: the top bit is masked, the value reduced mod p.</summary>
    public static BigInteger DecodeU(ReadOnlySpan<byte> u32)
    {
        Span<byte> copy = stackalloc byte[32];
        u32.CopyTo(copy);
        copy[31] &= 0x7f;
        return Mod(FromLittleEndian(copy));
    }

    /// <summary>X25519(k, u) of RFC 7748, with scalar clamping.</summary>
    public static byte[] X25519(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> u)
    {
        Span<byte> k = stackalloc byte[32];
        scalar.CopyTo(k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        var result = Ladder(FromLittleEndian(k), DecodeU(u), 255);
        CryptographicOperations.ZeroMemory(k);
        return ToLittleEndian(result);
    }

    public static byte[] X25519Base(ReadOnlySpan<byte> scalar) => X25519(scalar, BasePoint);

    /// <summary>The unclamped ladder of spec § 5.2, on all 256 bits of s.</summary>
    public static byte[] UnclampedLadder(BigInteger s, ReadOnlySpan<byte> u) =>
        ToLittleEndian(Ladder(s, DecodeU(u), 256));

    // ---- Elligator 2 (spec § 5.4) ----

    /// <summary>Map: representative (32 bytes) → canonical u (32 bytes). Never fails.</summary>
    public static byte[] ElligatorMap(ReadOnlySpan<byte> r32)
    {
        Span<byte> copy = stackalloc byte[32];
        r32.CopyTo(copy);
        copy[31] &= 0x3f;                                  // clear bits 254 and 255
        var r = FromLittleEndian(copy);

        var denominator = Mod(1 + 2 * r * r);
        var x1 = denominator.IsZero ? Mod(-A) : Mod(-A * Inverse(denominator));
        var g = Mod(x1 * x1 * x1 + A * x1 * x1 + x1);
        var u = IsSquare(g) ? x1 : Mod(-x1 - A);
        return ToLittleEndian(u);
    }

    /// <summary>
    /// Representative of u, with the three random choices of § 5.4 (t, root sign, top two bits);
    /// null when u has none.
    /// </summary>
    public static byte[]? ElligatorRepresentative(ReadOnlySpan<byte> u32)
    {
        var u = FromLittleEndian(u32);
        if (u >= P) return null;
        var den = Mod(-2 * u * (u + A));
        if (den.IsZero || !IsSquare(den)) return null;

        Span<byte> random = stackalloc byte[1];
        RandomNumberGenerator.Fill(random);
        var t = (random[0] & 1) == 0 ? u : Mod(u + A);
        var r = Mod(t * Inverse(Sqrt(den)));
        if (r > HalfP) r = P - r;

        var r32 = ToLittleEndian(r);
        r32[31] |= (byte)(random[0] & 0xc0);              // two uniform random top bits
        return r32;
    }
}
