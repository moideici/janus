package org.janus;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * ML-KEM-768 (FIPS 203): KeyGen_internal, Encaps_internal, Decaps (implicit rejection)
 * and the encapsulation-key check. Polynomials are {@code int[256]} with coefficients in [0, q).
 */
final class MlKem768 {

    static final int N = 256;
    static final int Q = 3329;
    static final int K = 3;
    static final int ETA1 = 2;
    static final int ETA2 = 2;
    static final int DU = 10;
    static final int DV = 4;

    static final int EK_BYTES = 384 * K + 32;                // 1184
    static final int DK_BYTES = 768 * K + 96;                // 2400
    static final int CT_BYTES = 32 * (DU * K + DV);          // 1088

    private static final int[] ZETAS = new int[128];
    private static final int[] GAMMAS = new int[128];

    static {
        for (int i = 0; i < 128; i++) {
            int br = Integer.reverse(i) >>> 25;
            ZETAS[i] = powMod(17, br);
            GAMMAS[i] = powMod(17, 2 * br + 1);
        }
    }

    record KeyPair(byte[] ek, byte[] dk) {
    }

    record Encapsulation(byte[] sharedKey, byte[] ciphertext) {
    }

    private MlKem768() {
    }

    // ---- ML-KEM ---------------------------------------------------------------

    static KeyPair keyGenInternal(byte[] d, byte[] z) {
        byte[][] pke = pkeKeyGen(d);
        byte[] ek = pke[0];
        byte[] dk = Bytes.concat(pke[1], ek, Bytes.sha3_256(ek), z);
        Arrays.fill(pke[1], (byte) 0);
        return new KeyPair(ek, dk);
    }

    /** FIPS 203 encapsulation-key check: right length, every coefficient below q. */
    static boolean checkEncapsulationKey(byte[] ek) {
        if (ek.length != EK_BYTES) {
            return false;
        }
        for (int i = 0; i < K; i++) {
            int[] f = byteDecode(ek, 384 * i, 12);
            for (int c : f) {
                if (c >= Q) {
                    return false;
                }
            }
        }
        return true;
    }

    static Encapsulation encapsInternal(byte[] ek, byte[] m) {
        byte[] g = Bytes.sha3_512(Bytes.concat(m, Bytes.sha3_256(ek)));
        byte[] key = Bytes.slice(g, 0, 32);
        byte[] r = Bytes.slice(g, 32, 64);
        byte[] c = pkeEncrypt(ek, m, r);
        Arrays.fill(g, (byte) 0);
        Arrays.fill(r, (byte) 0);
        return new Encapsulation(key, c);
    }

    static Encapsulation encaps(byte[] ek, java.security.SecureRandom rng) {
        if (!checkEncapsulationKey(ek)) {
            throw new IllegalArgumentException("invalid ML-KEM encapsulation key");
        }
        byte[] m = new byte[32];
        rng.nextBytes(m);
        try {
            return encapsInternal(ek, m);
        } finally {
            Arrays.fill(m, (byte) 0);
        }
    }

    /** Decapsulation with implicit rejection: never fails. */
    static byte[] decaps(byte[] dk, byte[] c) {
        byte[] dkPke = Bytes.slice(dk, 0, 384 * K);
        byte[] ekPke = Bytes.slice(dk, 384 * K, 768 * K + 32);
        byte[] h = Bytes.slice(dk, 768 * K + 32, 768 * K + 64);
        byte[] z = Bytes.slice(dk, 768 * K + 64, 768 * K + 96);
        byte[] m = pkeDecrypt(dkPke, c);
        byte[] g = Bytes.sha3_512(Bytes.concat(m, h));
        byte[] key = Bytes.slice(g, 0, 32);
        byte[] r = Bytes.slice(g, 32, 64);
        byte[] rejected = Keccak.shake256(Bytes.concat(z, c), 32);
        byte[] c2 = pkeEncrypt(ekPke, m, r);
        // Constant-time selection between the real and the rejection key.
        int mask = MessageDigest.isEqual(c, c2) ? 0 : 0xFF;
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (key[i] ^ (mask & (key[i] ^ rejected[i])));
        }
        Arrays.fill(dkPke, (byte) 0);
        Arrays.fill(z, (byte) 0);
        Arrays.fill(m, (byte) 0);
        Arrays.fill(g, (byte) 0);
        Arrays.fill(r, (byte) 0);
        Arrays.fill(rejected, (byte) 0);
        return key;
    }

    // ---- K-PKE ------------------------------------------------------------------

    private static byte[][] pkeKeyGen(byte[] d) {
        byte[] g = Bytes.sha3_512(Bytes.concat(d, new byte[] {(byte) K}));
        byte[] rho = Bytes.slice(g, 0, 32);
        byte[] sigma = Bytes.slice(g, 32, 64);
        int[][][] a = sampleMatrix(rho);
        int nonce = 0;
        int[][] s = new int[K][];
        int[][] e = new int[K][];
        for (int i = 0; i < K; i++) {
            s[i] = samplePolyCbd(prf(sigma, nonce++, ETA1), ETA1);
        }
        for (int i = 0; i < K; i++) {
            e[i] = samplePolyCbd(prf(sigma, nonce++, ETA1), ETA1);
        }
        for (int i = 0; i < K; i++) {
            ntt(s[i]);
            ntt(e[i]);
        }
        byte[] ek = new byte[EK_BYTES];
        byte[] dk = new byte[384 * K];
        for (int i = 0; i < K; i++) {
            int[] t = new int[N];
            for (int j = 0; j < K; j++) {
                addTo(t, multiplyNtts(a[i][j], s[j]));
            }
            addTo(t, e[i]);
            byteEncode(t, 12, ek, 384 * i);
            byteEncode(s[i], 12, dk, 384 * i);
        }
        for (int i = 0; i < K; i++) {
            Arrays.fill(s[i], 0);
            Arrays.fill(e[i], 0);
        }
        System.arraycopy(rho, 0, ek, 384 * K, 32);
        Arrays.fill(g, (byte) 0);
        Arrays.fill(sigma, (byte) 0);
        return new byte[][] {ek, dk};
    }

    private static byte[] pkeEncrypt(byte[] ek, byte[] m, byte[] r) {
        int[][] tHat = new int[K][];
        for (int i = 0; i < K; i++) {
            tHat[i] = byteDecode(ek, 384 * i, 12);
            reduce(tHat[i]);
        }
        byte[] rho = Bytes.slice(ek, 384 * K, 384 * K + 32);
        int[][][] a = sampleMatrix(rho);
        int nonce = 0;
        int[][] y = new int[K][];
        int[][] e1 = new int[K][];
        for (int i = 0; i < K; i++) {
            y[i] = samplePolyCbd(prf(r, nonce++, ETA1), ETA1);
        }
        for (int i = 0; i < K; i++) {
            e1[i] = samplePolyCbd(prf(r, nonce++, ETA2), ETA2);
        }
        int[] e2 = samplePolyCbd(prf(r, nonce, ETA2), ETA2);
        for (int i = 0; i < K; i++) {
            ntt(y[i]);
        }
        byte[] c = new byte[CT_BYTES];
        for (int i = 0; i < K; i++) {
            int[] u = new int[N];
            for (int j = 0; j < K; j++) {
                addTo(u, multiplyNtts(a[j][i], y[j]));
            }
            nttInverse(u);
            addTo(u, e1[i]);
            for (int k = 0; k < N; k++) {
                u[k] = compress(u[k], DU);
            }
            byteEncode(u, DU, c, 32 * DU * i);
        }
        int[] mu = byteDecode(m, 0, 1);
        int[] v = new int[N];
        for (int j = 0; j < K; j++) {
            addTo(v, multiplyNtts(tHat[j], y[j]));
        }
        nttInverse(v);
        addTo(v, e2);
        for (int k = 0; k < N; k++) {
            v[k] = compress((v[k] + decompress(mu[k], 1)) % Q, DV);
        }
        byteEncode(v, DV, c, 32 * DU * K);
        for (int i = 0; i < K; i++) {
            Arrays.fill(y[i], 0);
            Arrays.fill(e1[i], 0);
        }
        Arrays.fill(e2, 0);
        Arrays.fill(mu, 0);
        return c;
    }

    private static byte[] pkeDecrypt(byte[] dkPke, byte[] c) {
        int[] w = byteDecode(c, 32 * DU * K, DV);
        for (int k = 0; k < N; k++) {
            w[k] = decompress(w[k], DV);
        }
        int[] acc = new int[N];
        for (int i = 0; i < K; i++) {
            int[] u = byteDecode(c, 32 * DU * i, DU);
            for (int k = 0; k < N; k++) {
                u[k] = decompress(u[k], DU);
            }
            ntt(u);
            int[] s = byteDecode(dkPke, 384 * i, 12);
            reduce(s);
            addTo(acc, multiplyNtts(s, u));
            Arrays.fill(s, 0);
        }
        nttInverse(acc);
        for (int k = 0; k < N; k++) {
            w[k] = compress(Math.floorMod(w[k] - acc[k], Q), 1);
        }
        byte[] m = new byte[32];
        byteEncode(w, 1, m, 0);
        Arrays.fill(w, 0);
        Arrays.fill(acc, 0);
        return m;
    }

    // ---- Sampling ---------------------------------------------------------------

    /** Â[i][j] = SampleNTT(rho ‖ j ‖ i). */
    private static int[][][] sampleMatrix(byte[] rho) {
        int[][][] a = new int[K][K][];
        for (int i = 0; i < K; i++) {
            for (int j = 0; j < K; j++) {
                a[i][j] = sampleNtt(Bytes.concat(rho, new byte[] {(byte) j, (byte) i}));
            }
        }
        return a;
    }

    private static int[] sampleNtt(byte[] seed) {
        Keccak xof = Keccak.shake128().absorb(seed);
        byte[] buf = new byte[Keccak.SHAKE128_RATE];
        int[] a = new int[N];
        int j = 0;
        int pos = buf.length;
        while (j < N) {
            if (pos == buf.length) {
                xof.squeeze(buf, 0, buf.length);
                pos = 0;
            }
            int c0 = buf[pos] & 0xFF, c1 = buf[pos + 1] & 0xFF, c2 = buf[pos + 2] & 0xFF;
            pos += 3;
            int d1 = c0 + 256 * (c1 & 15);
            int d2 = (c1 >> 4) + 16 * c2;
            if (d1 < Q) {
                a[j++] = d1;
            }
            if (d2 < Q && j < N) {
                a[j++] = d2;
            }
        }
        return a;
    }

    private static byte[] prf(byte[] s, int b, int eta) {
        return Keccak.shake256(Bytes.concat(s, new byte[] {(byte) b}), 64 * eta);
    }

    private static int[] samplePolyCbd(byte[] bytes, int eta) {
        int[] f = new int[N];
        for (int i = 0; i < N; i++) {
            int x = 0, y = 0;
            for (int j = 0; j < eta; j++) {
                x += bit(bytes, 2 * i * eta + j);
                y += bit(bytes, 2 * i * eta + eta + j);
            }
            f[i] = Math.floorMod(x - y, Q);
        }
        Arrays.fill(bytes, (byte) 0);
        return f;
    }

    private static int bit(byte[] b, int i) {
        return (b[i >>> 3] >>> (i & 7)) & 1;
    }

    // ---- NTT --------------------------------------------------------------------

    private static void ntt(int[] f) {
        int i = 1;
        for (int len = 128; len >= 2; len >>= 1) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[i++];
                for (int j = start; j < start + len; j++) {
                    int t = (zeta * f[j + len]) % Q;
                    f[j + len] = Math.floorMod(f[j] - t, Q);
                    f[j] = (f[j] + t) % Q;
                }
            }
        }
    }

    private static void nttInverse(int[] f) {
        int i = 127;
        for (int len = 2; len <= 128; len <<= 1) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[i--];
                for (int j = start; j < start + len; j++) {
                    int t = f[j];
                    f[j] = (t + f[j + len]) % Q;
                    f[j + len] = (zeta * Math.floorMod(f[j + len] - t, Q)) % Q;
                }
            }
        }
        for (int j = 0; j < N; j++) {
            f[j] = (f[j] * 3303) % Q;
        }
    }

    private static int[] multiplyNtts(int[] f, int[] g) {
        int[] h = new int[N];
        for (int i = 0; i < 128; i++) {
            int a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
            h[2 * i] = (a0 * b0 + (a1 * b1 % Q) * GAMMAS[i]) % Q;
            h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
        }
        return h;
    }

    private static void addTo(int[] acc, int[] x) {
        for (int i = 0; i < N; i++) {
            acc[i] = (acc[i] + x[i]) % Q;
        }
    }

    private static void reduce(int[] f) {
        for (int i = 0; i < N; i++) {
            f[i] %= Q;
        }
    }

    // ---- Encoding and compression (also used by Kemeleon) ----------------------------

    static int compress(int x, int d) {
        return (int) ((((long) x << d) + Q / 2) / Q) & ((1 << d) - 1);
    }

    static int decompress(int y, int d) {
        return (y * Q + (1 << (d - 1))) >> d;
    }

    /** ByteEncode_d of 256 d-bit integers into {@code out} at {@code off} (32·d bytes). */
    static void byteEncode(int[] f, int d, byte[] out, int off) {
        Arrays.fill(out, off, off + 32 * d, (byte) 0);
        for (int i = 0; i < N; i++) {
            int a = f[i];
            for (int j = 0; j < d; j++) {
                int bitIndex = i * d + j;
                out[off + (bitIndex >>> 3)] |= (byte) (((a >>> j) & 1) << (bitIndex & 7));
            }
        }
    }

    /** ByteDecode_d of 32·d bytes at {@code off}; for d = 12 the values are NOT reduced mod q. */
    static int[] byteDecode(byte[] in, int off, int d) {
        int[] f = new int[N];
        for (int i = 0; i < N; i++) {
            int a = 0;
            for (int j = 0; j < d; j++) {
                int bitIndex = i * d + j;
                a |= ((in[off + (bitIndex >>> 3)] >>> (bitIndex & 7)) & 1) << j;
            }
            f[i] = a;
        }
        return f;
    }

    private static int powMod(int base, int exp) {
        long r = 1, b = base;
        while (exp > 0) {
            if ((exp & 1) != 0) {
                r = r * b % Q;
            }
            b = b * b % Q;
            exp >>= 1;
        }
        return (int) r;
    }
}
