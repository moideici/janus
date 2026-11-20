package org.janus;

import java.io.ByteArrayOutputStream;

/**
 * Bech32m (BIP 350). Character decoding and the checksum avoid data-dependent table
 * lookups and branches, as spec 3.3 recommends for identities (the JIT gives no guarantee).
 */
final class Bech32m {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int CONST = 0x2bc830a3;
    private static final int[] GEN = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    /** A decoded string: lower-case human-readable part and 5-bit data (checksum removed). */
    record Decoded(String hrp, byte[] data) {
    }

    private Bech32m() {
    }

    private static int polymod(int chk, int v) {
        int b = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; i++) {
            chk ^= -((b >>> i) & 1) & GEN[i];
        }
        return chk;
    }

    private static int hrpChecksum(String hrp) {
        int chk = 1;
        for (int i = 0; i < hrp.length(); i++) {
            chk = polymod(chk, hrp.charAt(i) >>> 5);
        }
        chk = polymod(chk, 0);
        for (int i = 0; i < hrp.length(); i++) {
            chk = polymod(chk, hrp.charAt(i) & 31);
        }
        return chk;
    }

    /** Encodes 5-bit {@code data} with a lower-case {@code hrp}; the result is lower-case. */
    static String encode(String hrp, byte[] data) {
        int chk = hrpChecksum(hrp);
        for (byte d : data) {
            chk = polymod(chk, d);
        }
        for (int i = 0; i < 6; i++) {
            chk = polymod(chk, 0);
        }
        chk ^= CONST;
        StringBuilder sb = new StringBuilder(hrp).append('1');
        for (byte d : data) {
            sb.append(CHARSET.charAt(d));
        }
        for (int i = 0; i < 6; i++) {
            sb.append(CHARSET.charAt((chk >>> (5 * (5 - i))) & 31));
        }
        return sb.toString();
    }

    /** Value of a lower-case data character, or -1; scans the whole alphabet every time. */
    private static int charValue(int c) {
        int v = -1;
        for (int k = 0; k < 32; k++) {
            int diff = c ^ CHARSET.charAt(k);
            int eq = ((diff - 1) >>> 31) & ((~diff) >>> 31);   // 1 iff diff == 0
            v ^= -eq & (v ^ k);
        }
        return v;
    }

    /**
     * Decodes and checks a Bech32m string; {@code maxLength} is 90 for BIP 173 strings.
     * Returns null on any error.
     */
    static Decoded decode(String s, int maxLength) {
        if (s.length() > maxLength || s.length() < 8) {
            return null;
        }
        boolean lower = false, upper = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 33 || c > 126) {
                return null;
            }
            lower |= c >= 'a' && c <= 'z';
            upper |= c >= 'A' && c <= 'Z';
        }
        if (lower && upper) {
            return null;
        }
        String low = s.toLowerCase(java.util.Locale.ROOT);
        int sep = low.lastIndexOf('1');
        if (sep < 1 || sep + 7 > low.length()) {
            return null;
        }
        String hrp = low.substring(0, sep);
        int n = low.length() - sep - 1;
        byte[] values = new byte[n];
        int bad = 0;
        for (int i = 0; i < n; i++) {
            int v = charValue(low.charAt(sep + 1 + i));
            bad |= v >>> 31;
            values[i] = (byte) (v & 31);
        }
        int chk = hrpChecksum(hrp);
        for (byte v : values) {
            chk = polymod(chk, v);
        }
        if ((bad | (chk ^ CONST)) != 0) {
            return null;
        }
        return new Decoded(hrp, java.util.Arrays.copyOf(values, n - 6));
    }

    /** 8-bit bytes to 5-bit groups, zero-padded. */
    static byte[] toFiveBits(byte[] in) {
        int outLen = (in.length * 8 + 4) / 5;
        byte[] out = new byte[outLen];
        int acc = 0, bits = 0, j = 0;
        for (byte b : in) {
            acc = (acc << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out[j++] = (byte) ((acc >>> bits) & 31);
            }
            acc &= (1 << bits) - 1;
        }
        if (bits > 0) {
            out[j] = (byte) ((acc << (5 - bits)) & 31);
        }
        return out;
    }

    /** 5-bit groups to bytes; null if the padding is over-long or non-zero. */
    static byte[] fromFiveBits(byte[] in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int acc = 0, bits = 0;
        for (byte v : in) {
            acc = (acc << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >>> bits) & 0xFF);
            }
            acc &= (1 << bits) - 1;
        }
        if (bits >= 5 || acc != 0) {
            return null;
        }
        return out.toByteArray();
    }
}
