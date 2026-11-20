package org.janus;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Kemeleon encoding of ML-KEM-768 ciphertexts (draft-irtf-cfrg-kemeleon-02, non-rejecting
 * variant), vectors written big-endian as Janus v1 fixes it (spec 5.5). 1088 ↔ 1536 bytes.
 */
final class Kemeleon {

    static final int ENCODED_BYTES = 1536;
    private static final int BLOCK = 384;
    private static final int Q = MlKem768.Q;
    private static final int N = MlKem768.N;
    private static final BigInteger BQ = BigInteger.valueOf(Q);
    private static final BigInteger Q_256 = BQ.pow(N);
    private static final BigInteger MAX_3072 = BigInteger.ONE.shiftLeft(3072).subtract(BigInteger.ONE);

    /** PREIMAGES_d[c] = every x in [0, q−1] with Compress_d(x) = c. */
    private static final int[][] PREIMAGES_10 = preimages(10);
    private static final int[][] PREIMAGES_4 = preimages(4);

    private Kemeleon() {
    }

    private static int[][] preimages(int d) {
        List<List<Integer>> lists = new ArrayList<>();
        for (int c = 0; c < (1 << d); c++) {
            lists.add(new ArrayList<>());
        }
        for (int x = 0; x < Q; x++) {
            lists.get(MlKem768.compress(x, d)).add(x);
        }
        int[][] out = new int[1 << d][];
        for (int c = 0; c < out.length; c++) {
            out[c] = lists.get(c).stream().mapToInt(Integer::intValue).toArray();
        }
        return out;
    }

    static byte[] encode(byte[] ct, SecureRandom rng) {
        if (ct.length != MlKem768.CT_BYTES) {
            throw new IllegalArgumentException("ML-KEM-768 ciphertext length");
        }
        byte[] out = new byte[ENCODED_BYTES];
        for (int j = 0; j < 4; j++) {
            int d = j < 3 ? MlKem768.DU : MlKem768.DV;
            int[][] pre = j < 3 ? PREIMAGES_10 : PREIMAGES_4;
            int[] c = MlKem768.byteDecode(ct, j < 3 ? 32 * MlKem768.DU * j : 32 * MlKem768.DU * 3, d);
            int[] a = new int[N];
            for (int i = 0; i < N; i++) {
                int[] choices = pre[c[i]];
                a[i] = choices[rng.nextInt(choices.length)];
            }
            vectorEncode(a, rng, out, BLOCK * j);
        }
        return out;
    }

    private static void vectorEncode(int[] a, SecureRandom rng, byte[] out, int off) {
        BigInteger r = BigInteger.ZERO;
        for (int i = N - 1; i >= 0; i--) {
            r = r.multiply(BQ).add(BigInteger.valueOf(a[i]));
        }
        BigInteger mMax = MAX_3072.subtract(r).divide(Q_256);
        BigInteger m = uniformBelow(mMax.add(BigInteger.ONE), rng);
        BigInteger value = r.add(m.multiply(Q_256));
        byte[] be = value.toByteArray();
        int n = Math.min(be.length, BLOCK);
        System.arraycopy(be, be.length - n, out, off + BLOCK - n, n);
    }

    /** Uniform integer in [0, bound), by rejection. */
    private static BigInteger uniformBelow(BigInteger bound, SecureRandom rng) {
        int bits = bound.subtract(BigInteger.ONE).bitLength();
        while (true) {
            BigInteger x = new BigInteger(bits, rng);
            if (x.compareTo(bound) < 0) {
                return x;
            }
        }
    }

    /** Never fails. */
    static byte[] decode(byte[] kappa) {
        byte[] ct = new byte[MlKem768.CT_BYTES];
        for (int j = 0; j < 4; j++) {
            byte[] block = Bytes.slice(kappa, BLOCK * j, BLOCK * (j + 1));
            BigInteger r = new BigInteger(1, block);
            int d = j < 3 ? MlKem768.DU : MlKem768.DV;
            int[] c = new int[N];
            for (int i = 0; i < N; i++) {
                BigInteger[] qr = r.divideAndRemainder(BQ);
                c[i] = MlKem768.compress(qr[1].intValue(), d);
                r = qr[0];
            }
            MlKem768.byteEncode(c, d, ct, j < 3 ? 32 * MlKem768.DU * j : 32 * MlKem768.DU * 3);
        }
        return ct;
    }
}
