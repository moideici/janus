package org.janus;

import java.math.BigInteger;
import java.security.SecureRandom;

/** Elligator 2 on Curve25519, u-coordinate only, Z = 2 (spec 5.4). */
final class Elligator2 {

    private static final BigInteger P = Curve25519.P;
    private static final BigInteger A = Curve25519.A;
    private static final BigInteger P_MINUS_1_HALF = P.subtract(BigInteger.ONE).shiftRight(1);

    private Elligator2() {
    }

    /** Map: representative (32 bytes, top two bits ignored) to a u-coordinate. Never fails. */
    static byte[] map(byte[] r32) {
        byte[] c = r32.clone();
        c[31] &= 0x3F;
        BigInteger r = Curve25519.fromLe(c);
        BigInteger den = BigInteger.ONE.add(BigInteger.TWO.multiply(r).multiply(r)).mod(P);
        BigInteger x1 = den.signum() == 0
                ? A.negate().mod(P)
                : Curve25519.mul(A.negate().mod(P), Curve25519.inv(den));
        BigInteger g = x1.multiply(x1).multiply(x1).add(A.multiply(x1).multiply(x1)).add(x1).mod(P);
        BigInteger u = Curve25519.isSquare(g) ? x1 : x1.negate().subtract(A).mod(P);
        return Curve25519.toLe(u);
    }

    /**
     * A uniformly chosen representative of {@code u} (canonical, 32 bytes), with random top bits,
     * or {@code null} if {@code u} has none.
     */
    static byte[] representative(byte[] uBytes, SecureRandom rng) {
        BigInteger u = Curve25519.fromLe(uBytes);
        if (u.compareTo(P) >= 0) {
            return null;
        }
        BigInteger uPlusA = u.add(A).mod(P);
        BigInteger den = BigInteger.TWO.negate().multiply(u).multiply(uPlusA).mod(P);
        if (den.signum() == 0 || !Curve25519.isSquare(den)) {
            return null;
        }
        BigInteger t = rng.nextBoolean() ? u : uPlusA;
        BigInteger r = Curve25519.mul(t, Curve25519.inv(Curve25519.sqrt(den)));
        if (r.compareTo(P_MINUS_1_HALF) > 0) {
            r = P.subtract(r);
        }
        byte[] out = Curve25519.toLe(r);
        out[31] |= (byte) ((rng.nextInt() & 3) << 6);
        return out;
    }
}
