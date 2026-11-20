using System.Buffers.Binary;
using System.Numerics;

namespace Janus;

/// <summary>
/// Keccak-f[1600] sponge and the FIPS 202 functions used by Janus and ML-KEM:
/// SHA3-256, SHA3-512, SHAKE128 and SHAKE256.
/// </summary>
public sealed class Keccak
{
    private static readonly ulong[] RoundConstants =
    {
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
    };

    // Rotation offsets and lane permutation of rho and pi, in the order of the pi walk.
    private static readonly int[] Rho =
        { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
    private static readonly int[] Pi =
        { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

    private readonly ulong[] _state = new ulong[25];
    private readonly byte[] _buffer;
    private readonly int _rate;
    private readonly byte _domain;
    private int _position;
    private bool _squeezing;

    private Keccak(int rate, byte domain)
    {
        _rate = rate;
        _domain = domain;
        _buffer = new byte[rate];
    }

    public static Keccak NewShake128() => new(168, 0x1f);
    public static Keccak NewShake256() => new(136, 0x1f);
    public static Keccak NewSha3_256() => new(136, 0x06);
    public static Keccak NewSha3_512() => new(72, 0x06);

    public static byte[] Sha3_256(ReadOnlySpan<byte> data)
    {
        var k = NewSha3_256();
        k.Absorb(data);
        return k.Squeeze(32);
    }

    public static byte[] Sha3_512(ReadOnlySpan<byte> data)
    {
        var k = NewSha3_512();
        k.Absorb(data);
        return k.Squeeze(64);
    }

    public static byte[] Shake128(ReadOnlySpan<byte> data, int length)
    {
        var k = NewShake128();
        k.Absorb(data);
        return k.Squeeze(length);
    }

    public static byte[] Shake256(ReadOnlySpan<byte> data, int length)
    {
        var k = NewShake256();
        k.Absorb(data);
        return k.Squeeze(length);
    }

    public void Absorb(ReadOnlySpan<byte> data)
    {
        if (_squeezing) throw new InvalidOperationException("Keccak: absorb after squeeze");
        while (!data.IsEmpty)
        {
            int n = Math.Min(_rate - _position, data.Length);
            data[..n].CopyTo(_buffer.AsSpan(_position));
            _position += n;
            data = data[n..];
            if (_position == _rate)
            {
                XorBlock();
                Permute(_state);
                _position = 0;
            }
        }
    }

    public byte[] Squeeze(int length)
    {
        var output = new byte[length];
        Squeeze(output);
        return output;
    }

    public void Squeeze(Span<byte> output)
    {
        if (!_squeezing)
        {
            // Pad: domain bits, then pad10*1.
            _buffer.AsSpan(_position).Clear();
            _buffer[_position] ^= _domain;
            _buffer[_rate - 1] ^= 0x80;
            XorBlock();
            Permute(_state);
            ExtractBlock();
            _position = 0;
            _squeezing = true;
        }
        while (!output.IsEmpty)
        {
            if (_position == _rate)
            {
                Permute(_state);
                ExtractBlock();
                _position = 0;
            }
            int n = Math.Min(_rate - _position, output.Length);
            _buffer.AsSpan(_position, n).CopyTo(output);
            _position += n;
            output = output[n..];
        }
    }

    private void XorBlock()
    {
        for (int i = 0; i < _rate / 8; i++)
            _state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(_buffer.AsSpan(8 * i));
    }

    private void ExtractBlock()
    {
        for (int i = 0; i < _rate / 8; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(8 * i), _state[i]);
    }

    /// <summary>Keccak-f[1600], 24 rounds.</summary>
    public static void Permute(ulong[] a)
    {
        Span<ulong> c = stackalloc ulong[5];
        for (int round = 0; round < 24; round++)
        {
            // theta
            for (int x = 0; x < 5; x++)
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++)
            {
                ulong d = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[y + x] ^= d;
            }
            // rho and pi
            ulong current = a[1];
            for (int i = 0; i < 24; i++)
            {
                int j = Pi[i];
                ulong next = a[j];
                a[j] = BitOperations.RotateLeft(current, Rho[i]);
                current = next;
            }
            // chi
            for (int y = 0; y < 25; y += 5)
            {
                for (int x = 0; x < 5; x++) c[x] = a[y + x];
                for (int x = 0; x < 5; x++) a[y + x] = c[x] ^ (~c[(x + 1) % 5] & c[(x + 2) % 5]);
            }
            // iota
            a[0] ^= RoundConstants[round];
        }
    }
}
