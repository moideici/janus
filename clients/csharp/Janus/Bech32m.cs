namespace Janus;

/// <summary>Bech32m (BIP 350) encoding and decoding, with a configurable length limit.</summary>
public static class Bech32m
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const uint Constant = 0x2bc830a3;

    private static uint Polymod(ReadOnlySpan<byte> values)
    {
        uint chk = 1;
        foreach (byte v in values)
        {
            uint top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            if ((top & 1) != 0) chk ^= 0x3b6a57b2;
            if ((top & 2) != 0) chk ^= 0x26508e6d;
            if ((top & 4) != 0) chk ^= 0x1ea119fa;
            if ((top & 8) != 0) chk ^= 0x3d4233dd;
            if ((top & 16) != 0) chk ^= 0x2a1462b3;
        }
        return chk;
    }

    private static byte[] HrpExpand(string hrp)
    {
        var r = new byte[2 * hrp.Length + 1];
        for (int i = 0; i < hrp.Length; i++)
        {
            r[i] = (byte)(hrp[i] >> 5);
            r[hrp.Length + 1 + i] = (byte)(hrp[i] & 31);
        }
        return r;
    }

    /// <summary>Encodes 5-bit groups under a lowercase human-readable part; the result is lowercase.</summary>
    public static string Encode(string hrp, ReadOnlySpan<byte> data5)
    {
        hrp = hrp.ToLowerInvariant();
        var expanded = HrpExpand(hrp);
        var values = new byte[expanded.Length + data5.Length + 6];
        expanded.CopyTo(values, 0);
        data5.CopyTo(values.AsSpan(expanded.Length));
        uint mod = Polymod(values) ^ Constant;
        var sb = new System.Text.StringBuilder(hrp.Length + 1 + data5.Length + 6);
        sb.Append(hrp).Append('1');
        foreach (byte b in data5) sb.Append(Charset[b]);
        for (int i = 0; i < 6; i++) sb.Append(Charset[(int)((mod >> (5 * (5 - i))) & 31)]);
        return sb.ToString();
    }

    /// <summary>
    /// Decodes a Bech32m string: returns the lowercase human-readable part and the 5-bit data
    /// (checksum removed), or null if the string is invalid (mixed case, bad character, bad checksum,
    /// or longer than maxLength).
    /// </summary>
    public static (string hrp, byte[] data5)? Decode(string s, int maxLength = 90)
    {
        if (s.Length > maxLength) return null;
        bool lower = false, upper = false;
        foreach (char ch in s)
        {
            if (ch < 33 || ch > 126) return null;
            if (ch is >= 'a' and <= 'z') lower = true;
            if (ch is >= 'A' and <= 'Z') upper = true;
        }
        if (lower && upper) return null;
        s = s.ToLowerInvariant();
        int separator = s.LastIndexOf('1');
        if (separator < 1 || separator + 7 > s.Length) return null;
        string hrp = s[..separator];
        int dataLength = s.Length - separator - 1;
        var data = new byte[dataLength];
        for (int i = 0; i < dataLength; i++)
        {
            int v = CharValue(s[separator + 1 + i]);
            if (v < 0) return null;
            data[i] = (byte)v;
        }
        var expanded = HrpExpand(hrp);
        var values = new byte[expanded.Length + data.Length];
        expanded.CopyTo(values, 0);
        data.CopyTo(values, expanded.Length);
        if (Polymod(values) != Constant) return null;
        return (hrp, data[..^6]);
    }

    /// <summary>
    /// Value of a lowercase Bech32 character, or −1. Scans the whole charset without data-dependent
    /// branches or table lookups (spec § 3.3 SHOULD, for identities).
    /// </summary>
    private static int CharValue(char ch)
    {
        int result = -1;
        for (int i = 0; i < 32; i++)
        {
            int diff = Charset[i] ^ ch;                       // 0 iff equal
            int isEqual = ((diff - 1) >> 31) & 1;             // 1 iff diff == 0 (diff < 2^16)
            result += isEqual * (i + 1);
        }
        return result;
    }

    /// <summary>8-bit bytes → 5-bit groups, zero-padded.</summary>
    public static byte[] ToFiveBit(ReadOnlySpan<byte> data)
    {
        var output = new List<byte>((data.Length * 8 + 4) / 5);
        int acc = 0, bits = 0;
        foreach (byte b in data)
        {
            acc = (acc << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                output.Add((byte)((acc >> bits) & 31));
            }
            acc &= (1 << bits) - 1;
        }
        if (bits > 0) output.Add((byte)((acc << (5 - bits)) & 31));
        return output.ToArray();
    }

    /// <summary>5-bit groups → bytes; null on over-long (≥ 5 bits) or non-zero padding.</summary>
    public static byte[]? FromFiveBit(ReadOnlySpan<byte> data5)
    {
        var output = new List<byte>(data5.Length * 5 / 8);
        int acc = 0, bits = 0;
        foreach (byte v in data5)
        {
            if (v > 31) return null;
            acc = (acc << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)((acc >> bits) & 0xff));
            }
            acc &= (1 << bits) - 1;
        }
        if (bits >= 5 || acc != 0) return null;
        return output.ToArray();
    }
}
