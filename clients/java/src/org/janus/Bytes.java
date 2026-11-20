package org.janus;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Small byte-array helpers and the JDK hash functions. */
final class Bytes {

    private Bytes() {
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    static byte[] slice(byte[] a, int from, int to) {
        return java.util.Arrays.copyOfRange(a, from, to);
    }

    static byte[] be64(long x) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (x >>> (56 - 8 * i));
        }
        return out;
    }

    static long readBe64(byte[] a, int off) {
        long x = 0;
        for (int i = 0; i < 8; i++) {
            x = (x << 8) | (a[off + i] & 0xFF);
        }
        return x;
    }

    static byte[] ascii(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    static String hex(byte[] a) {
        return HexFormat.of().formatHex(a);
    }

    static byte[] sha256(byte[] in) {
        return digest("SHA-256", in);
    }

    static byte[] sha3_256(byte[] in) {
        return digest("SHA3-256", in);
    }

    static byte[] sha3_512(byte[] in) {
        return digest("SHA3-512", in);
    }

    private static byte[] digest(String alg, byte[] in) {
        try {
            return MessageDigest.getInstance(alg).digest(in);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(alg + " unavailable", e);
        }
    }
}
