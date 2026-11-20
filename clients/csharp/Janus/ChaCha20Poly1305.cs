using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Janus;

/// <summary>ChaCha20-Poly1305 AEAD (RFC 8439): 32-byte key, 12-byte nonce, 16-byte tag.</summary>
public static class ChaCha20Poly1305Aead
{
    public const int TagSize = 16;

    /// <summary>Returns ciphertext ‖ tag.</summary>
    public static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
                              ReadOnlySpan<byte> aad = default)
    {
        var output = new byte[plaintext.Length + TagSize];
        Seal(key, nonce, plaintext, aad, output);
        return output;
    }

    public static void Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
                            ReadOnlySpan<byte> aad, Span<byte> output)
    {
        var ciphertext = output[..plaintext.Length];
        ChaCha20.Xor(key, nonce, 1, plaintext, ciphertext);
        ComputeTag(key, nonce, aad, ciphertext, output.Slice(plaintext.Length, TagSize));
    }

    /// <summary>Opens ciphertext ‖ tag into plaintext; returns false (and writes nothing useful) on failure.</summary>
    public static bool Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> sealedData,
                            ReadOnlySpan<byte> aad, Span<byte> plaintext)
    {
        if (sealedData.Length < TagSize) return false;
        var ciphertext = sealedData[..^TagSize];
        Span<byte> tag = stackalloc byte[TagSize];
        ComputeTag(key, nonce, aad, ciphertext, tag);
        bool ok = CryptographicOperations.FixedTimeEquals(tag, sealedData[^TagSize..]);
        if (!ok) return false;
        ChaCha20.Xor(key, nonce, 1, ciphertext, plaintext[..ciphertext.Length]);
        return true;
    }

    private static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                                   ReadOnlySpan<byte> ciphertext, Span<byte> tag)
    {
        Span<byte> block = stackalloc byte[64];
        ChaCha20.Block(key, nonce, 0, block);
        var mac = new Poly1305(block[..32]);
        CryptographicOperations.ZeroMemory(block);
        Span<byte> zeros = stackalloc byte[16];
        zeros.Clear();
        mac.Update(aad);
        mac.Update(zeros[..((16 - aad.Length % 16) % 16)]);
        mac.Update(ciphertext);
        mac.Update(zeros[..((16 - ciphertext.Length % 16) % 16)]);
        Span<byte> lengths = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertext.Length);
        mac.Update(lengths);
        mac.Final(tag);
    }
}

/// <summary>The ChaCha20 stream cipher (RFC 8439 § 2.3–2.4).</summary>
public static class ChaCha20
{
    public static void Block(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> output)
    {
        Span<uint> state = stackalloc uint[16];
        Span<uint> x = stackalloc uint[16];
        Init(state, key, nonce, counter);
        Core(state, x);
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], x[i]);
    }

    public static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter,
                           ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<uint> state = stackalloc uint[16];
        Span<uint> x = stackalloc uint[16];
        Span<byte> stream = stackalloc byte[64];
        Init(state, key, nonce, counter);
        for (int offset = 0; offset < input.Length; offset += 64)
        {
            Core(state, x);
            for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(stream[(4 * i)..], x[i]);
            int n = Math.Min(64, input.Length - offset);
            for (int i = 0; i < n; i++) output[offset + i] = (byte)(input[offset + i] ^ stream[i]);
            state[12]++;
        }
        CryptographicOperations.ZeroMemory(stream);
        state.Clear();
        x.Clear();
    }

    private static void Init(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
    {
        if (key.Length != 32 || nonce.Length != 12) throw new ArgumentException("ChaCha20: bad key or nonce size");
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        state[12] = counter;
        for (int i = 0; i < 3; i++) state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(4 * i)..]);
    }

    private static void Core(ReadOnlySpan<uint> state, Span<uint> x)
    {
        state.CopyTo(x);
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(x, 0, 4, 8, 12); QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14); QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15); QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13); QuarterRound(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) x[i] += state[i];
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}

/// <summary>Poly1305 one-time authenticator (RFC 8439 § 2.5), 26-bit limbs.</summary>
public sealed class Poly1305
{
    private const uint Mask26 = 0x3ffffff;
    private readonly uint _r0, _r1, _r2, _r3, _r4;
    private readonly uint _s1, _s2, _s3, _s4;
    private readonly uint[] _pad = new uint[4];
    private uint _h0, _h1, _h2, _h3, _h4;
    private readonly byte[] _buffer = new byte[16];
    private int _filled;

    public Poly1305(ReadOnlySpan<byte> key)
    {
        // r is clamped as required by RFC 8439.
        _r0 = BinaryPrimitives.ReadUInt32LittleEndian(key) & 0x3ffffff;
        _r1 = (BinaryPrimitives.ReadUInt32LittleEndian(key[3..]) >> 2) & 0x3ffff03;
        _r2 = (BinaryPrimitives.ReadUInt32LittleEndian(key[6..]) >> 4) & 0x3ffc0ff;
        _r3 = (BinaryPrimitives.ReadUInt32LittleEndian(key[9..]) >> 6) & 0x3f03fff;
        _r4 = (BinaryPrimitives.ReadUInt32LittleEndian(key[12..]) >> 8) & 0x00fffff;
        _s1 = _r1 * 5; _s2 = _r2 * 5; _s3 = _r3 * 5; _s4 = _r4 * 5;
        for (int i = 0; i < 4; i++) _pad[i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(16 + 4 * i)..]);
    }

    public void Update(ReadOnlySpan<byte> data)
    {
        if (_filled > 0)
        {
            int n = Math.Min(16 - _filled, data.Length);
            data[..n].CopyTo(_buffer.AsSpan(_filled));
            _filled += n;
            data = data[n..];
            if (_filled < 16) return;
            ProcessBlock(_buffer, 1u << 24);
            _filled = 0;
        }
        while (data.Length >= 16)
        {
            ProcessBlock(data[..16], 1u << 24);
            data = data[16..];
        }
        data.CopyTo(_buffer);
        _filled = data.Length;
    }

    public void Final(Span<byte> tag)
    {
        if (_filled > 0)
        {
            _buffer[_filled] = 1;
            _buffer.AsSpan(_filled + 1).Clear();
            ProcessBlock(_buffer, 0);
        }

        uint h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4, c;
        c = h1 >> 26; h1 &= Mask26; h2 += c;
        c = h2 >> 26; h2 &= Mask26; h3 += c;
        c = h3 >> 26; h3 &= Mask26; h4 += c;
        c = h4 >> 26; h4 &= Mask26; h0 += c * 5;
        c = h0 >> 26; h0 &= Mask26; h1 += c;

        // g = h + 5 - 2^130; keep g if it does not underflow.
        uint g0 = h0 + 5; c = g0 >> 26; g0 &= Mask26;
        uint g1 = h1 + c; c = g1 >> 26; g1 &= Mask26;
        uint g2 = h2 + c; c = g2 >> 26; g2 &= Mask26;
        uint g3 = h3 + c; c = g3 >> 26; g3 &= Mask26;
        uint g4 = h4 + c - (1u << 26);
        uint mask = (g4 >> 31) - 1;            // all ones if g4 did not underflow
        h0 = (h0 & ~mask) | (g0 & mask);
        h1 = (h1 & ~mask) | (g1 & mask);
        h2 = (h2 & ~mask) | (g2 & mask);
        h3 = (h3 & ~mask) | (g3 & mask);
        h4 = (h4 & ~mask) | (g4 & mask);

        // h mod 2^128, plus the pad.
        ulong f0 = (h0 | (h1 << 26)) & 0xffffffffUL;
        ulong f1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffUL;
        ulong f2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffUL;
        ulong f3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffUL;
        ulong f = f0 + _pad[0]; BinaryPrimitives.WriteUInt32LittleEndian(tag, (uint)f);
        f = f1 + _pad[1] + (f >> 32); BinaryPrimitives.WriteUInt32LittleEndian(tag[4..], (uint)f);
        f = f2 + _pad[2] + (f >> 32); BinaryPrimitives.WriteUInt32LittleEndian(tag[8..], (uint)f);
        f = f3 + _pad[3] + (f >> 32); BinaryPrimitives.WriteUInt32LittleEndian(tag[12..], (uint)f);
    }

    private void ProcessBlock(ReadOnlySpan<byte> m, uint hibit)
    {
        _h0 += BinaryPrimitives.ReadUInt32LittleEndian(m) & Mask26;
        _h1 += (BinaryPrimitives.ReadUInt32LittleEndian(m[3..]) >> 2) & Mask26;
        _h2 += (BinaryPrimitives.ReadUInt32LittleEndian(m[6..]) >> 4) & Mask26;
        _h3 += (BinaryPrimitives.ReadUInt32LittleEndian(m[9..]) >> 6) & Mask26;
        _h4 += (BinaryPrimitives.ReadUInt32LittleEndian(m[12..]) >> 8) | hibit;

        ulong d0 = (ulong)_h0 * _r0 + (ulong)_h1 * _s4 + (ulong)_h2 * _s3 + (ulong)_h3 * _s2 + (ulong)_h4 * _s1;
        ulong d1 = (ulong)_h0 * _r1 + (ulong)_h1 * _r0 + (ulong)_h2 * _s4 + (ulong)_h3 * _s3 + (ulong)_h4 * _s2;
        ulong d2 = (ulong)_h0 * _r2 + (ulong)_h1 * _r1 + (ulong)_h2 * _r0 + (ulong)_h3 * _s4 + (ulong)_h4 * _s3;
        ulong d3 = (ulong)_h0 * _r3 + (ulong)_h1 * _r2 + (ulong)_h2 * _r1 + (ulong)_h3 * _r0 + (ulong)_h4 * _s4;
        ulong d4 = (ulong)_h0 * _r4 + (ulong)_h1 * _r3 + (ulong)_h2 * _r2 + (ulong)_h3 * _r1 + (ulong)_h4 * _r0;

        ulong c = d0 >> 26; _h0 = (uint)d0 & Mask26;
        d1 += c; c = d1 >> 26; _h1 = (uint)d1 & Mask26;
        d2 += c; c = d2 >> 26; _h2 = (uint)d2 & Mask26;
        d3 += c; c = d3 >> 26; _h3 = (uint)d3 & Mask26;
        d4 += c; c = d4 >> 26; _h4 = (uint)d4 & Mask26;
        _h0 += (uint)c * 5; c = _h0 >> 26; _h0 &= Mask26; _h1 += (uint)c;
    }
}
