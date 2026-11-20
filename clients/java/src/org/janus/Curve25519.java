package org.janus;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Curve25519 field arithmetic and the Montgomery ladder (RFC 7748), on {@link BigInteger}.
 * Not constant-time.
 */
final class Curve25519 {

    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger A = BigInteger.valueOf(486662);
    private static final BigInteger A24 = BigInteger.valueOf(121665);
    private static final BigInteger TWO = BigInteger.TWO;

    /** ℓ, the order of the prime-order subgroup. */
    static final BigInteger ELL = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));
    /** 8ℓ, the order of the full group. */
    static final BigInteger EIGHT_ELL = ELL.shiftLeft(3);

    /** u(G), G = Ed25519 base point plus a point of order 8: a generator of the full group (spec 5.2). */
    static final byte[] U_G = Bytes.hex("bb72312170e8156f7a836313f85bee9b1fdce926ba9804a29e8d137ec67f2533");
    static final byte[] U_9 = toLe(BigInteger.valueOf(9));

    private static final BigInteger P_MINUS_1_HALF = P.subtract(BigInteger.ONE).shiftRight(1);
    private static final BigInteger SQRT_EXP = P.add(BigInteger.valueOf(3)).shiftRight(3);
    private static final BigInteger SQRT_M1 = TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    private Curve25519() {
    }

    // ---- Encoding ------------------------------------------------------------------

    static BigInteger fromLe(byte[] b) {
        byte[] be = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) {
            be[b.length - i] = b[i];
        }
        return new BigInteger(be);
    }

    static byte[] toLe(BigInteger x) {
        byte[] be = x.toByteArray();                 // x < 2^256: at most 32 significant bytes
        byte[] out = new byte[32];
        for (int i = 0; i < Math.min(32, be.length); i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    /** RFC 7748 decodeUCoordinate: clear bit 255, reduce mod p. */
    static BigInteger decodeU(byte[] u) {
        byte[] c = u.clone();
        c[31] &= 0x7F;
        return fromLe(c).mod(P);
    }

    // ---- Field ----------------------------------------------------------------------

    static BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(P);
    }

    static BigInteger inv(BigInteger a) {
        return a.modPow(P.subtract(TWO), P);
    }

    /** Euler's criterion; 0 counts as a square. */
    static boolean isSquare(BigInteger a) {
        BigInteger l = a.mod(P).modPow(P_MINUS_1_HALF, P);
        return !l.equals(P.subtract(BigInteger.ONE));
    }

    /** A square root of a square {@code a} (p ≡ 5 mod 8). */
    static BigInteger sqrt(BigInteger a) {
        a = a.mod(P);
        BigInteger r = a.modPow(SQRT_EXP, P);
        if (!mul(r, r).equals(a)) {
            r = mul(r, SQRT_M1);
        }
        if (!mul(r, r).equals(a)) {
            throw new ArithmeticException("not a square");
        }
        return r;
    }

    // ---- Montgomery ladder ------------------------------------------------------------

    /** RFC 7748 ladder on all 256 bits of {@code scalar} (little-endian), without clamping. */
    static byte[] ladder(byte[] scalar, byte[] u) {
        BigInteger x1 = decodeU(u);
        BigInteger x2 = BigInteger.ONE, z2 = BigInteger.ZERO, x3 = x1, z3 = BigInteger.ONE;
        int swap = 0;
        for (int t = 255; t >= 0; t--) {
            int kt = (scalar[t >>> 3] >>> (t & 7)) & 1;
            swap ^= kt;
            if (swap != 0) {
                BigInteger tmp = x2; x2 = x3; x3 = tmp;
                tmp = z2; z2 = z3; z3 = tmp;
            }
            swap = kt;
            BigInteger a = x2.add(z2);
            BigInteger aa = mul(a, a);
            BigInteger b = x2.subtract(z2);
            BigInteger bb = mul(b, b);
            BigInteger e = aa.subtract(bb);
            BigInteger c = x3.add(z3);
            BigInteger d = x3.subtract(z3);
            BigInteger da = mul(d, a);
            BigInteger cb = mul(c, b);
            BigInteger s = da.add(cb);
            BigInteger m = da.subtract(cb);
            x3 = mul(s, s);
            z3 = mul(x1, mul(m, m));
            x2 = mul(aa, bb);
            z2 = mul(e, aa.add(mul(A24, e)));
        }
        if (swap != 0) {
            x2 = x3;
            z2 = z3;
        }
        return toLe(mul(x2, inv(z2)));
    }

    /** X25519 (RFC 7748), with clamping. */
    static byte[] x25519(byte[] k, byte[] u) {
        byte[] s = k.clone();
        s[0] &= (byte) 248;
        s[31] &= 127;
        s[31] |= 64;
        try {
            return ladder(s, u);
        } finally {
            java.util.Arrays.fill(s, (byte) 0);
        }
    }

    /** A scalar uniform in [0, 8ℓ − 1], little-endian, by rejection. */
    static byte[] randomFullGroupScalar(SecureRandom rng) {
        byte[] s = new byte[32];
        while (true) {
            rng.nextBytes(s);
            if (fromLe(s).compareTo(EIGHT_ELL) < 0) {
                return s;
            }
        }
    }
}
