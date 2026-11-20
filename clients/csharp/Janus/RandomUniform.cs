using System.Numerics;
using System.Security.Cryptography;

namespace Janus;

/// <summary>Unbiased random integers, by rejection sampling (spec § 2: "uniform in [a, b]").</summary>
public static class RandomUniform
{
    public static byte[] Bytes(int n) => RandomNumberGenerator.GetBytes(n);

    /// <summary>Uniform in [0, n − 1].</summary>
    public static int Int32(int n) => RandomNumberGenerator.GetInt32(n);

    /// <summary>Uniform in [low, high], both included.</summary>
    public static ulong UInt64InRange(ulong low, ulong high)
    {
        if (high < low) throw new ArgumentException("empty range");
        ulong span = high - low;
        if (span == ulong.MaxValue) return BitConverter.ToUInt64(Bytes(8));
        ulong count = span + 1;
        int bits = 64 - BitOperations.LeadingZeroCount(span);
        ulong mask = bits == 64 ? ulong.MaxValue : (1UL << bits) - 1;
        Span<byte> b = stackalloc byte[8];
        while (true)
        {
            RandomNumberGenerator.Fill(b);
            ulong x = BitConverter.ToUInt64(b) & mask;
            if (x < count) return low + x;
        }
    }

    /// <summary>Uniform in [0, max], max ≥ 0.</summary>
    public static BigInteger BigIntegerAtMost(BigInteger max)
    {
        if (max.Sign < 0) throw new ArgumentException("negative bound");
        if (max.IsZero) return BigInteger.Zero;
        long bits = (long)max.GetBitLength();
        int bytes = (int)((bits + 7) / 8);
        int excess = (int)(8 * bytes - bits);
        var buffer = new byte[bytes];
        while (true)
        {
            RandomNumberGenerator.Fill(buffer);
            buffer[^1] &= (byte)(0xff >> excess);          // little-endian: top byte last
            var x = new BigInteger(buffer, isUnsigned: true, isBigEndian: false);
            if (x <= max) return x;
        }
    }

    /// <summary>A uniform random permutation of 0 … n − 1 (Fisher–Yates).</summary>
    public static int[] Permutation(int n)
    {
        var p = Enumerable.Range(0, n).ToArray();
        for (int i = n - 1; i > 0; i--)
        {
            int j = Int32(i + 1);
            (p[i], p[j]) = (p[j], p[i]);
        }
        return p;
    }
}
