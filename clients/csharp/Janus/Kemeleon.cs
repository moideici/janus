using System.Numerics;

namespace Janus;

/// <summary>
/// Kemeleon encoding of ML-KEM-768 ciphertexts (spec § 5.5; draft-irtf-cfrg-kemeleon-02,
/// non-rejecting variant, vectors as 384-byte big-endian integers).
/// </summary>
public static class Kemeleon
{
    public const int EncodedSize = 4 * VectorBytes;     // 1536
    private const int VectorBytes = 384;
    private const int N = MlKem768.N;
    private const int Q = MlKem768.Q;

    private static readonly BigInteger QPowN = BigInteger.Pow(Q, N);
    private static readonly BigInteger MaxValue = (BigInteger.One << (8 * VectorBytes)) - 1;

    // Preimages of Compress_10 and Compress_4: Preimages[d][c] lists every x in [0, q−1] with Compress_d(x) = c.
    private static readonly int[][] Preimages10 = BuildPreimages(10);
    private static readonly int[][] Preimages4 = BuildPreimages(4);

    private static int[][] BuildPreimages(int d)
    {
        var lists = new List<int>[1 << d];
        for (int c = 0; c < lists.Length; c++) lists[c] = new List<int>();
        for (int x = 0; x < Q; x++) lists[MlKem768.Compress(x, d)].Add(x);
        return lists.Select(l => l.ToArray()).ToArray();
    }

    /// <summary>EncodeCtxt: 1088-byte ciphertext → 1536 uniform-looking bytes.</summary>
    public static byte[] EncodeCiphertext(ReadOnlySpan<byte> ct)
    {
        if (ct.Length != MlKem768.CiphertextSize) throw new ArgumentException("bad ML-KEM ciphertext size");
        var output = new byte[EncodedSize];
        var values = new int[N];
        for (int j = 0; j < 4; j++)
        {
            bool isV = j == 3;
            var coefficients = isV
                ? MlKem768.ByteDecode(ct.Slice(320 * 3, 128), 4, reduce: false)
                : MlKem768.ByteDecode(ct.Slice(320 * j, 320), 10, reduce: false);
            var table = isV ? Preimages4 : Preimages10;
            for (int i = 0; i < N; i++)
            {
                var candidates = table[coefficients[i]];
                values[i] = candidates[RandomUniform.Int32(candidates.Length)];
            }
            VectorEncode(values, output.AsSpan(VectorBytes * j, VectorBytes));
        }
        Array.Clear(values);
        return output;
    }

    /// <summary>DecodeCtxt: 1536 bytes → 1088-byte ciphertext. Never fails.</summary>
    public static byte[] DecodeCiphertext(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedSize) throw new ArgumentException("bad Kemeleon size");
        var ct = new byte[MlKem768.CiphertextSize];
        var compressed = new int[N];
        for (int j = 0; j < 4; j++)
        {
            var r = new BigInteger(encoded.Slice(VectorBytes * j, VectorBytes), isUnsigned: true, isBigEndian: true);
            int d = j == 3 ? 4 : 10;
            for (int i = 0; i < N; i++)
            {
                r = BigInteger.DivRem(r, Q, out var digit);
                compressed[i] = MlKem768.Compress((int)digit, d);
            }
            if (j < 3) MlKem768.ByteEncode(compressed, 10, ct.AsSpan(320 * j, 320));
            else MlKem768.ByteEncode(compressed, 4, ct.AsSpan(320 * 3, 128));
        }
        return ct;
    }

    /// <summary>VectorEncode: R = Σ a[i]·q^i, plus a uniform multiple of q^256 that keeps it below 2^3072.</summary>
    private static void VectorEncode(int[] a, Span<byte> output)
    {
        BigInteger r = BigInteger.Zero;
        for (int i = N - 1; i >= 0; i--) r = r * Q + a[i];
        var mMax = (MaxValue - r) / QPowN;
        var m = RandomUniform.BigIntegerAtMost(mMax);
        r += m * QPowN;
        output.Clear();
        int length = r.GetByteCount(isUnsigned: true);
        r.TryWriteBytes(output[(VectorBytes - length)..], out _, isUnsigned: true, isBigEndian: true);
    }
}
