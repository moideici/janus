using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Janus;

/// <summary>
/// Argon2id, version 0x13 (RFC 9106). Lanes of one slice are filled in parallel; the result
/// does not depend on scheduling, since a segment only reads finished slices of other lanes.
/// </summary>
public static class Argon2id
{
    private const int BlockWords = 128;        // 1024-byte block = 128 × 64-bit words
    private const int SyncPoints = 4;
    private const uint Version = 0x13;
    private const uint TypeId = 2;

    /// <summary>The Janus parameters (spec § 2.1): 64 MiB, 3 passes, 4 lanes, 32-byte output.</summary>
    public static byte[] Janus(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt) =>
        Hash(password, salt, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 65536, 3, 4, 32);

    public static byte[] Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret,
                              ReadOnlySpan<byte> associatedData, int memoryKiB, int passes, int lanes, int tagLength)
    {
        // H0 = BLAKE2b-512 of the parameters and inputs, each length-prefixed (32-bit little-endian).
        var h = new Blake2b(64);
        var le = new byte[4];
        void U32(uint x) { BinaryPrimitives.WriteUInt32LittleEndian(le, x); h.Update(le); }
        U32((uint)lanes); U32((uint)tagLength); U32((uint)memoryKiB); U32((uint)passes); U32(Version); U32(TypeId);
        U32((uint)password.Length); h.Update(password);
        U32((uint)salt.Length); h.Update(salt);
        U32((uint)secret.Length); h.Update(secret);
        U32((uint)associatedData.Length); h.Update(associatedData);
        byte[] h0 = h.Final();

        int segmentLength = memoryKiB / (SyncPoints * lanes);
        int laneLength = segmentLength * SyncPoints;
        int blockCount = laneLength * lanes;
        var memory = new ulong[blockCount * BlockWords];

        try
        {
            // First two blocks of each lane: H'(H0 ‖ LE32(j) ‖ LE32(lane)).
            var seed = new byte[72];
            h0.CopyTo(seed, 0);
            for (int lane = 0; lane < lanes; lane++)
            {
                for (int j = 0; j < 2; j++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(64), (uint)j);
                    BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(68), (uint)lane);
                    byte[] block = HPrime(seed, 1024);
                    LoadBlock(memory.AsSpan((lane * laneLength + j) * BlockWords, BlockWords), block);
                }
            }
            CryptographicOperations.ZeroMemory(seed);

            var ctx = new Context(memory, lanes, laneLength, segmentLength, passes, blockCount);
            for (int pass = 0; pass < passes; pass++)
                for (int slice = 0; slice < SyncPoints; slice++)
                {
                    int p = pass, s = slice;
                    Parallel.For(0, lanes, lane => FillSegment(ctx, p, lane, s));
                }

            // Final block: XOR of the last block of every lane.
            var final = new ulong[BlockWords];
            for (int lane = 0; lane < lanes; lane++)
            {
                var last = memory.AsSpan((lane * laneLength + laneLength - 1) * BlockWords, BlockWords);
                for (int i = 0; i < BlockWords; i++) final[i] ^= last[i];
            }
            var finalBytes = new byte[1024];
            for (int i = 0; i < BlockWords; i++) BinaryPrimitives.WriteUInt64LittleEndian(finalBytes.AsSpan(8 * i), final[i]);
            byte[] tag = HPrime(finalBytes, tagLength);
            CryptographicOperations.ZeroMemory(finalBytes);
            return tag;
        }
        finally
        {
            Array.Clear(memory);
        }
    }

    private sealed record Context(ulong[] Memory, int Lanes, int LaneLength, int SegmentLength, int Passes, int BlockCount);

    private static void FillSegment(Context ctx, int pass, int lane, int slice)
    {
        bool independent = pass == 0 && slice < SyncPoints / 2;    // Argon2id
        Span<ulong> address = stackalloc ulong[BlockWords];
        Span<ulong> input = stackalloc ulong[BlockWords];
        Span<ulong> zero = stackalloc ulong[BlockWords];
        Span<ulong> scratchR = stackalloc ulong[BlockWords];
        Span<ulong> scratchT = stackalloc ulong[BlockWords];
        zero.Clear();
        input.Clear();

        if (independent)
        {
            input[0] = (ulong)pass; input[1] = (ulong)lane; input[2] = (ulong)slice;
            input[3] = (ulong)ctx.BlockCount; input[4] = (ulong)ctx.Passes; input[5] = TypeId;
        }

        int start = 0;
        if (pass == 0 && slice == 0)
        {
            start = 2;
            if (independent) NextAddresses(address, input, zero, scratchR, scratchT);
        }

        var memory = ctx.Memory.AsSpan();
        int laneLength = ctx.LaneLength;
        int current = lane * laneLength + slice * ctx.SegmentLength + start;
        int previous = current % laneLength == 0 ? current + laneLength - 1 : current - 1;

        for (int i = start; i < ctx.SegmentLength; i++, current++, previous++)
        {
            if (current % laneLength == 1) previous = current - 1;

            ulong pseudoRandom;
            if (independent)
            {
                if (i % BlockWords == 0) NextAddresses(address, input, zero, scratchR, scratchT);
                pseudoRandom = address[i % BlockWords];
            }
            else
            {
                pseudoRandom = memory[previous * BlockWords];
            }

            int refLane = (int)((pseudoRandom >> 32) % (ulong)ctx.Lanes);
            if (pass == 0 && slice == 0) refLane = lane;
            int refIndex = IndexAlpha(ctx, pass, slice, i, (uint)pseudoRandom, refLane == lane);

            var prevBlock = memory.Slice(previous * BlockWords, BlockWords);
            var refBlock = memory.Slice((refLane * laneLength + refIndex) * BlockWords, BlockWords);
            var curBlock = memory.Slice(current * BlockWords, BlockWords);
            FillBlock(prevBlock, refBlock, curBlock, pass != 0, scratchR, scratchT);
        }
    }

    private static int IndexAlpha(Context ctx, int pass, int slice, int index, uint pseudoRandom, bool sameLane)
    {
        long areaSize;
        if (pass == 0)
        {
            if (slice == 0) areaSize = index - 1;
            else if (sameLane) areaSize = (long)slice * ctx.SegmentLength + index - 1;
            else areaSize = (long)slice * ctx.SegmentLength + (index == 0 ? -1 : 0);
        }
        else
        {
            if (sameLane) areaSize = ctx.LaneLength - ctx.SegmentLength + index - 1;
            else areaSize = ctx.LaneLength - ctx.SegmentLength + (index == 0 ? -1 : 0);
        }

        ulong x = pseudoRandom;
        x = (x * x) >> 32;
        ulong relative = (ulong)areaSize - 1 - (((ulong)areaSize * x) >> 32);
        ulong startPosition = pass != 0 && slice != SyncPoints - 1 ? (ulong)((slice + 1) * ctx.SegmentLength) : 0;
        return (int)((startPosition + relative) % (ulong)ctx.LaneLength);
    }

    private static void NextAddresses(Span<ulong> address, Span<ulong> input, Span<ulong> zero,
                                      Span<ulong> scratchR, Span<ulong> scratchT)
    {
        input[6]++;
        FillBlock(zero, input, address, false, scratchR, scratchT);
        FillBlock(zero, address, address, false, scratchR, scratchT);
    }

    /// <summary>next = G(prev, ref), XORed into the old value of next when withXor (passes after the first).</summary>
    private static void FillBlock(ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next, bool withXor,
                                  Span<ulong> r, Span<ulong> t)
    {
        for (int i = 0; i < BlockWords; i++) r[i] = prev[i] ^ refBlock[i];
        r.CopyTo(t);
        if (withXor) for (int i = 0; i < BlockWords; i++) t[i] ^= next[i];

        // Rows: 8 rows of 16 consecutive words.
        for (int row = 0; row < 8; row++)
        {
            int b = 16 * row;
            Round(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                  b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }
        // Columns: 8 columns of 8 two-word registers.
        for (int col = 0; col < 8; col++)
        {
            int b = 2 * col;
            Round(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                  b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
        }

        for (int i = 0; i < BlockWords; i++) next[i] = t[i] ^ r[i];
    }

    private static void Round(Span<ulong> v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
                              int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
    {
        GB(v, v0, v4, v8, v12);
        GB(v, v1, v5, v9, v13);
        GB(v, v2, v6, v10, v14);
        GB(v, v3, v7, v11, v15);
        GB(v, v0, v5, v10, v15);
        GB(v, v1, v6, v11, v12);
        GB(v, v2, v7, v8, v13);
        GB(v, v3, v4, v9, v14);
    }

    private static void GB(Span<ulong> v, int a, int b, int c, int d)
    {
        v[a] = v[a] + v[b] + 2 * (ulong)(uint)v[a] * (uint)v[b]; v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + 2 * (ulong)(uint)v[c] * (uint)v[d]; v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + 2 * (ulong)(uint)v[a] * (uint)v[b]; v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + 2 * (ulong)(uint)v[c] * (uint)v[d]; v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
    }

    /// <summary>The variable-length hash H' of RFC 9106 § 3.3.</summary>
    private static byte[] HPrime(ReadOnlySpan<byte> x, int length)
    {
        Span<byte> prefix = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, (uint)length);
        if (length <= 64)
        {
            var b = new Blake2b(length);
            b.Update(prefix); b.Update(x);
            return b.Final();
        }

        var output = new byte[length];
        int r = (length + 31) / 32 - 2;
        var first = new Blake2b(64);
        first.Update(prefix); first.Update(x);
        byte[] v = first.Final();
        v.AsSpan(0, 32).CopyTo(output);
        for (int i = 1; i < r; i++)
        {
            v = Blake2b.Hash(v, 64);
            v.AsSpan(0, 32).CopyTo(output.AsSpan(32 * i));
        }
        byte[] tail = Blake2b.Hash(v, length - 32 * r);
        tail.CopyTo(output, 32 * r);
        return output;
    }

    private static void LoadBlock(Span<ulong> dst, ReadOnlySpan<byte> src)
    {
        for (int i = 0; i < BlockWords; i++) dst[i] = BinaryPrimitives.ReadUInt64LittleEndian(src[(8 * i)..]);
    }
}
