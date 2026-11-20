using System.Security.Cryptography;

namespace Janus;

/// <summary>
/// ML-KEM-768 (FIPS 203): KeyGen_internal, Encaps (and the deterministic Encaps_internal),
/// Decaps with implicit rejection, and the encapsulation-key check. Plain modular arithmetic
/// on ints, written for clarity rather than speed.
/// </summary>
public static class MlKem768
{
    public const int N = 256;
    public const int Q = 3329;
    public const int K = 3;
    private const int Eta1 = 2, Eta2 = 2, Du = 10, Dv = 4;

    public const int EncapsulationKeySize = 384 * K + 32;                  // 1184
    public const int DecapsulationKeySize = 768 * K + 96;                  // 2400
    public const int CiphertextSize = 32 * (Du * K + Dv);                  // 1088
    public const int SharedSecretSize = 32;

    // ζ^BitRev7(i) and ζ^(2·BitRev7(i)+1), ζ = 17.
    private static readonly int[] Zetas = new int[128];
    private static readonly int[] Gammas = new int[128];

    static MlKem768()
    {
        for (int i = 0; i < 128; i++)
        {
            int rev = 0;
            for (int b = 0; b < 7; b++) rev |= ((i >> b) & 1) << (6 - b);
            Zetas[i] = PowMod(17, rev);
            Gammas[i] = PowMod(17, 2 * rev + 1);
        }
    }

    private static int PowMod(int b, int e)
    {
        long r = 1, x = b;
        while (e > 0)
        {
            if ((e & 1) != 0) r = r * x % Q;
            x = x * x % Q;
            e >>= 1;
        }
        return (int)r;
    }

    // ---- Public API ----

    public static (byte[] ek, byte[] dk) KeyGenInternal(ReadOnlySpan<byte> d, ReadOnlySpan<byte> z)
    {
        var (ekPke, dkPke) = PkeKeyGen(d);
        var dk = new byte[DecapsulationKeySize];
        dkPke.CopyTo(dk, 0);
        ekPke.CopyTo(dk, 384 * K);
        Keccak.Sha3_256(ekPke).CopyTo(dk, 768 * K + 32);
        z.CopyTo(dk.AsSpan(768 * K + 64));
        CryptographicOperations.ZeroMemory(dkPke);
        return (ekPke, dk);
    }

    /// <summary>The FIPS 203 encapsulation-key check: every coefficient of ek decodes below q.</summary>
    public static bool CheckEncapsulationKey(ReadOnlySpan<byte> ek)
    {
        if (ek.Length != EncapsulationKeySize) return false;
        for (int i = 0; i < K; i++)
        {
            var poly = ByteDecode(ek.Slice(384 * i, 384), 12, reduce: false);
            foreach (int c in poly) if (c >= Q) return false;
        }
        return true;
    }

    public static (byte[] sharedSecret, byte[] ciphertext) Encaps(ReadOnlySpan<byte> ek)
    {
        Span<byte> m = stackalloc byte[32];
        RandomNumberGenerator.Fill(m);
        var result = EncapsInternal(ek, m);
        CryptographicOperations.ZeroMemory(m);
        return result;
    }

    public static (byte[] sharedSecret, byte[] ciphertext) EncapsInternal(ReadOnlySpan<byte> ek, ReadOnlySpan<byte> m)
    {
        if (!CheckEncapsulationKey(ek)) throw new CryptographicException("invalid ML-KEM encapsulation key");
        var gInput = new byte[64];
        m.CopyTo(gInput);
        Keccak.Sha3_256(ek).CopyTo(gInput, 32);
        var kr = Keccak.Sha3_512(gInput);
        var c = PkeEncrypt(ek, m, kr.AsSpan(32, 32));
        var sharedSecret = kr[..32];
        CryptographicOperations.ZeroMemory(kr);
        CryptographicOperations.ZeroMemory(gInput);
        return (sharedSecret, c);
    }

    /// <summary>Decapsulation with implicit rejection: never fails.</summary>
    public static byte[] Decaps(ReadOnlySpan<byte> dk, ReadOnlySpan<byte> c)
    {
        var dkPke = dk[..(384 * K)];
        var ek = dk.Slice(384 * K, EncapsulationKeySize);
        var h = dk.Slice(768 * K + 32, 32);
        var z = dk.Slice(768 * K + 64, 32);

        var m = PkeDecrypt(dkPke, c);
        var gInput = new byte[64];
        m.CopyTo(gInput, 0);
        h.CopyTo(gInput.AsSpan(32));
        var kr = Keccak.Sha3_512(gInput);

        var jInput = new byte[32 + c.Length];
        z.CopyTo(jInput);
        c.CopyTo(jInput.AsSpan(32));
        var kBar = Keccak.Shake256(jInput, 32);

        var cPrime = PkeEncrypt(ek, m, kr.AsSpan(32, 32));
        bool equal = CryptographicOperations.FixedTimeEquals(c, cPrime);

        var result = new byte[32];
        // Constant-time select between K' and K̄.
        byte mask = (byte)(equal ? 0xff : 0x00);
        for (int i = 0; i < 32; i++) result[i] = (byte)((kr[i] & mask) | (kBar[i] & ~mask));

        CryptographicOperations.ZeroMemory(m);
        CryptographicOperations.ZeroMemory(kr);
        CryptographicOperations.ZeroMemory(gInput);
        CryptographicOperations.ZeroMemory(kBar);
        return result;
    }

    // ---- K-PKE ----

    private static (byte[] ek, byte[] dk) PkeKeyGen(ReadOnlySpan<byte> d)
    {
        var gInput = new byte[33];
        d.CopyTo(gInput);
        gInput[32] = K;
        var rhoSigma = Keccak.Sha3_512(gInput);
        var rho = rhoSigma.AsSpan(0, 32);
        var sigma = rhoSigma.AsSpan(32, 32);

        var aHat = SampleMatrix(rho);
        byte counter = 0;
        var s = new int[K][];
        var e = new int[K][];
        for (int i = 0; i < K; i++) s[i] = SamplePolyCbd(Prf(sigma, counter++, Eta1), Eta1);
        for (int i = 0; i < K; i++) e[i] = SamplePolyCbd(Prf(sigma, counter++, Eta1), Eta1);
        for (int i = 0; i < K; i++) { Ntt(s[i]); Ntt(e[i]); }

        var ek = new byte[EncapsulationKeySize];
        var dk = new byte[384 * K];
        for (int i = 0; i < K; i++)
        {
            var t = new int[N];
            for (int j = 0; j < K; j++) AddInPlace(t, MultiplyNtts(aHat[i, j], s[j]));
            AddInPlace(t, e[i]);
            ByteEncode(t, 12, ek.AsSpan(384 * i, 384));
            ByteEncode(s[i], 12, dk.AsSpan(384 * i, 384));
        }
        rho.CopyTo(ek.AsSpan(384 * K));
        CryptographicOperations.ZeroMemory(rhoSigma);
        return (ek, dk);
    }

    private static byte[] PkeEncrypt(ReadOnlySpan<byte> ek, ReadOnlySpan<byte> m, ReadOnlySpan<byte> r)
    {
        var tHat = new int[K][];
        for (int i = 0; i < K; i++) tHat[i] = ByteDecode(ek.Slice(384 * i, 384), 12, reduce: true);
        var aHat = SampleMatrix(ek.Slice(384 * K, 32));

        byte counter = 0;
        var y = new int[K][];
        var e1 = new int[K][];
        for (int i = 0; i < K; i++) y[i] = SamplePolyCbd(Prf(r, counter++, Eta1), Eta1);
        for (int i = 0; i < K; i++) e1[i] = SamplePolyCbd(Prf(r, counter++, Eta2), Eta2);
        var e2 = SamplePolyCbd(Prf(r, counter, Eta2), Eta2);
        for (int i = 0; i < K; i++) Ntt(y[i]);

        var c = new byte[CiphertextSize];
        for (int i = 0; i < K; i++)
        {
            // u = NTT⁻¹(Âᵀ ∘ ŷ) + e1
            var u = new int[N];
            for (int j = 0; j < K; j++) AddInPlace(u, MultiplyNtts(aHat[j, i], y[j]));
            InverseNtt(u);
            AddInPlace(u, e1[i]);
            ByteEncode(Compress(u, Du), Du, c.AsSpan(32 * Du * i, 32 * Du));
        }

        var mu = Decompress(ByteDecode(m, 1, reduce: false), 1);
        var v = new int[N];
        for (int j = 0; j < K; j++) AddInPlace(v, MultiplyNtts(tHat[j], y[j]));
        InverseNtt(v);
        AddInPlace(v, e2);
        AddInPlace(v, mu);
        ByteEncode(Compress(v, Dv), Dv, c.AsSpan(32 * Du * K, 32 * Dv));
        return c;
    }

    private static byte[] PkeDecrypt(ReadOnlySpan<byte> dk, ReadOnlySpan<byte> c)
    {
        var w = new int[N];
        for (int i = 0; i < K; i++)
        {
            var u = Decompress(ByteDecode(c.Slice(32 * Du * i, 32 * Du), Du, reduce: false), Du);
            Ntt(u);
            var s = ByteDecode(dk.Slice(384 * i, 384), 12, reduce: true);
            AddInPlace(w, MultiplyNtts(s, u));
        }
        InverseNtt(w);
        var v = Decompress(ByteDecode(c.Slice(32 * Du * K, 32 * Dv), Dv, reduce: false), Dv);
        for (int i = 0; i < N; i++) w[i] = ModQ(v[i] - w[i]);
        var m = new byte[32];
        ByteEncode(Compress(w, 1), 1, m);
        return m;
    }

    // ---- Sampling ----

    private static int[,][] SampleMatrix(ReadOnlySpan<byte> rho)
    {
        var a = new int[K, K][];
        var seed = new byte[34];
        rho.CopyTo(seed);
        for (int i = 0; i < K; i++)
            for (int j = 0; j < K; j++)
            {
                seed[32] = (byte)j;
                seed[33] = (byte)i;
                a[i, j] = SampleNtt(seed);
            }
        return a;
    }

    private static int[] SampleNtt(byte[] seed)
    {
        var xof = Keccak.NewShake128();
        xof.Absorb(seed);
        var a = new int[N];
        Span<byte> buf = stackalloc byte[3];
        int j = 0;
        while (j < N)
        {
            xof.Squeeze(buf);
            int d1 = buf[0] + 256 * (buf[1] & 0x0f);
            int d2 = (buf[1] >> 4) + 16 * buf[2];
            if (d1 < Q) a[j++] = d1;
            if (d2 < Q && j < N) a[j++] = d2;
        }
        return a;
    }

    private static byte[] Prf(ReadOnlySpan<byte> seed, byte b, int eta)
    {
        var input = new byte[33];
        seed.CopyTo(input);
        input[32] = b;
        return Keccak.Shake256(input, 64 * eta);
    }

    private static int[] SamplePolyCbd(byte[] bytes, int eta)
    {
        var f = new int[N];
        for (int i = 0; i < N; i++)
        {
            int x = 0, y = 0;
            for (int j = 0; j < eta; j++)
            {
                x += Bit(bytes, 2 * i * eta + j);
                y += Bit(bytes, 2 * i * eta + eta + j);
            }
            f[i] = ModQ(x - y);
        }
        CryptographicOperations.ZeroMemory(bytes);
        return f;
    }

    private static int Bit(byte[] b, int i) => (b[i >> 3] >> (i & 7)) & 1;

    // ---- NTT ----

    private static void Ntt(int[] f)
    {
        int k = 1;
        for (int len = 128; len >= 2; len >>= 1)
            for (int start = 0; start < N; start += 2 * len)
            {
                long zeta = Zetas[k++];
                for (int j = start; j < start + len; j++)
                {
                    int t = (int)(zeta * f[j + len] % Q);
                    f[j + len] = ModQ(f[j] - t);
                    f[j] = ModQ(f[j] + t);
                }
            }
    }

    private static void InverseNtt(int[] f)
    {
        int k = 127;
        for (int len = 2; len <= 128; len <<= 1)
            for (int start = 0; start < N; start += 2 * len)
            {
                long zeta = Zetas[k--];
                for (int j = start; j < start + len; j++)
                {
                    int t = f[j];
                    f[j] = ModQ(t + f[j + len]);
                    f[j + len] = (int)(zeta * ModQ(f[j + len] - t) % Q);
                }
            }
        for (int i = 0; i < N; i++) f[i] = (int)((long)f[i] * 3303 % Q);
    }

    private static int[] MultiplyNtts(int[] f, int[] g)
    {
        var h = new int[N];
        for (int i = 0; i < 128; i++)
        {
            long a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
            h[2 * i] = (int)((a0 * b0 + a1 * b1 % Q * Gammas[i]) % Q);
            h[2 * i + 1] = (int)((a0 * b1 + a1 * b0) % Q);
        }
        return h;
    }

    private static void AddInPlace(int[] f, int[] g)
    {
        for (int i = 0; i < N; i++) f[i] = ModQ(f[i] + g[i]);
    }

    private static int ModQ(int x)
    {
        int r = x % Q;
        return r < 0 ? r + Q : r;
    }

    // ---- Encoding and compression (shared with Kemeleon) ----

    /// <summary>Compress_d(x) = ⌊(x·2^d + 1664) / q⌋ mod 2^d.</summary>
    public static int Compress(int x, int d) => (int)((((long)x << d) + (Q - 1) / 2) / Q) & ((1 << d) - 1);

    /// <summary>Decompress_d(y) = ⌊(q·y + 2^(d−1)) / 2^d⌋.</summary>
    public static int Decompress(int y, int d) => (int)(((long)Q * y + (1L << (d - 1))) >> d);

    private static int[] Compress(int[] f, int d)
    {
        var r = new int[N];
        for (int i = 0; i < N; i++) r[i] = Compress(f[i], d);
        return r;
    }

    private static int[] Decompress(int[] f, int d)
    {
        var r = new int[N];
        for (int i = 0; i < N; i++) r[i] = Decompress(f[i], d);
        return r;
    }

    /// <summary>ByteEncode_d: 256 d-bit integers, least significant bit first.</summary>
    public static void ByteEncode(ReadOnlySpan<int> f, int d, Span<byte> output)
    {
        output[..(32 * d)].Clear();
        int bit = 0;
        for (int i = 0; i < N; i++)
            for (int b = 0; b < d; b++, bit++)
                output[bit >> 3] |= (byte)(((f[i] >> b) & 1) << (bit & 7));
    }

    /// <summary>ByteDecode_d; for d = 12 with reduce, coefficients are taken mod q (FIPS 203).</summary>
    public static int[] ByteDecode(ReadOnlySpan<byte> input, int d, bool reduce)
    {
        var f = new int[N];
        int bit = 0;
        for (int i = 0; i < N; i++)
        {
            int x = 0;
            for (int b = 0; b < d; b++, bit++) x |= ((input[bit >> 3] >> (bit & 7)) & 1) << b;
            f[i] = reduce && d == 12 ? x % Q : x;
        }
        return f;
    }
}
